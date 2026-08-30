package vpswebapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsbackup"
	"gateway-vpn/internal/vpsfabric"
	"gateway-vpn/internal/vpsops"
	"gateway-vpn/internal/wgingress"
)

type fakeRestoreTrigger struct{ calls int }

func (trigger *fakeRestoreTrigger) ApplyPendingVPSRestore(context.Context) error {
	trigger.calls++
	return nil
}

type fakeFabricTrigger struct {
	calls int
	err   error
}

func (trigger *fakeFabricTrigger) ApplyVPSFabric(context.Context) error {
	trigger.calls++
	return trigger.err
}

type apiSession struct {
	Cookie *http.Cookie
	CSRF   string
}

func TestVPSHubBackupDownloadStagePreviewAndAuthorizedApply(t *testing.T) {
	server, trigger := vpsAPIFixture(t)
	session := loginVPSHub(t, server, "administrator password 123")
	passphrase := "correct horse battery staple"

	download := jsonRequest(t, server, session, http.MethodPost, "/api/v1/vps/backup/download", map[string]any{
		"password": "administrator password 123", "passphrase": passphrase, "passphrase_confirmation": passphrase,
	})
	if download.Code != http.StatusOK || download.Header().Get("X-Backup-Role") != "vps" || !strings.Contains(download.Header().Get("Content-Disposition"), ".gvpn-vps") || download.Body.Len() == 0 {
		t.Fatalf("backup download = %d headers=%v body=%s", download.Code, download.Header(), download.Body.String())
	}
	encrypted := append([]byte(nil), download.Body.Bytes()...)
	backupPath := filepath.Join(t.TempDir(), "download.gvpn-vps")
	if err := os.WriteFile(backupPath, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.DecryptVPSBackupToZIP(context.Background(), backupPath, filepath.Join(t.TempDir(), "vps.zip"), passphrase); err != nil {
		t.Fatalf("downloaded VPS backup cannot be decrypted: %v", err)
	}
	if _, err := backup.DecryptToZIP(context.Background(), backupPath, filepath.Join(t.TempDir(), "gateway.zip"), passphrase); err == nil {
		t.Fatal("downloaded VPS backup was accepted as Gateway role")
	}

	stage := multipartRestoreRequest(t, server, session, "download.gvpn-vps", encrypted, passphrase)
	if stage.Code != http.StatusCreated {
		t.Fatalf("stage = %d %s", stage.Code, stage.Body.String())
	}
	var staged struct {
		Operation           vpsbackup.RestoreOperation `json:"operation"`
		ConfirmationPhrases map[string]string          `json:"confirmation_phrases"`
	}
	if err := json.Unmarshal(stage.Body.Bytes(), &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Operation.RestoreID == "" || !staged.Operation.IdentityMatches || len(staged.Operation.AllowedModes) != 2 || staged.Operation.ApplyAuthorization != "" || staged.ConfirmationPhrases[vpsbackup.RestoreModeSameVPS] == "" || staged.ConfirmationPhrases[vpsbackup.RestoreModeNewVPS] == "" {
		t.Fatalf("staged response = %+v", staged)
	}

	wrong := jsonRequest(t, server, session, http.MethodPost, "/api/v1/vps/restore/apply", map[string]any{
		"restore_id": staged.Operation.RestoreID, "mode": vpsbackup.RestoreModeSameVPS,
		"password": "administrator password 123", "confirmation": "wrong phrase",
	})
	if wrong.Code != http.StatusConflict || trigger.calls != 0 {
		t.Fatalf("wrong confirmation = %d calls=%d %s", wrong.Code, trigger.calls, wrong.Body.String())
	}
	apply := jsonRequest(t, server, session, http.MethodPost, "/api/v1/vps/restore/apply", map[string]any{
		"restore_id": staged.Operation.RestoreID, "mode": vpsbackup.RestoreModeSameVPS,
		"password": "administrator password 123", "confirmation": staged.ConfirmationPhrases[vpsbackup.RestoreModeSameVPS],
	})
	if apply.Code != http.StatusAccepted || trigger.calls != 1 {
		t.Fatalf("apply = %d calls=%d %s", apply.Code, trigger.calls, apply.Body.String())
	}
	status := authorizedRequest(server, session, http.MethodGet, "/api/v1/vps/backup/status", nil, "")
	if status.Code != http.StatusOK || bytes.Contains(status.Body.Bytes(), []byte(`"apply_authorization":"`)) {
		t.Fatalf("status leaked authorization or failed: %d %s", status.Code, status.Body.String())
	}
}

func TestVPSHubRejectsMissingCSRFBadReauthenticationAndCanDiscardStage(t *testing.T) {
	server, _ := vpsAPIFixture(t)
	session := loginVPSHub(t, server, "administrator password 123")
	missingCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/vps/backup/download", strings.NewReader(`{}`))
	missingCSRF.AddCookie(session.Cookie)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, missingCSRF)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF = %d %s", recorder.Code, recorder.Body.String())
	}
	badPassword := jsonRequest(t, server, session, http.MethodPost, "/api/v1/vps/backup/download", map[string]any{
		"password": "wrong administrator password", "passphrase": "correct horse battery staple", "passphrase_confirmation": "correct horse battery staple",
	})
	if badPassword.Code != http.StatusUnauthorized {
		t.Fatalf("bad backup reauthentication = %d %s", badPassword.Code, badPassword.Body.String())
	}
	valid := jsonRequest(t, server, session, http.MethodPost, "/api/v1/vps/backup/download", map[string]any{
		"password": "administrator password 123", "passphrase": "correct horse battery staple", "passphrase_confirmation": "correct horse battery staple",
	})
	if valid.Code != http.StatusOK {
		t.Fatalf("valid backup = %d %s", valid.Code, valid.Body.String())
	}
	stage := multipartRestoreRequest(t, server, session, "backup.gvpn-vps", valid.Body.Bytes(), "correct horse battery staple")
	if stage.Code != http.StatusCreated {
		t.Fatalf("stage = %d %s", stage.Code, stage.Body.String())
	}
	discard := authorizedRequest(server, session, http.MethodDelete, "/api/v1/vps/restore", nil, "discard-staged-vps-restore")
	if discard.Code != http.StatusNoContent {
		t.Fatalf("discard = %d %s", discard.Code, discard.Body.String())
	}
	status := authorizedRequest(server, session, http.MethodGet, "/api/v1/vps/backup/status", nil, "")
	if !bytes.Contains(status.Body.Bytes(), []byte(`"pending":false`)) {
		t.Fatalf("discarded status = %d %s", status.Code, status.Body.String())
	}
}

func TestVPSOperationalLogsAndDiagnosticDownloadUseDisplayOnlySnapshot(t *testing.T) {
	server, _ := vpsAPIFixture(t)
	session := loginVPSHub(t, server, "administrator password 123")
	logs := authorizedRequest(server, session, http.MethodGet, "/api/v1/vps/logs?category=agent-control&limit=50", nil, "")
	if logs.Code != http.StatusOK || !strings.Contains(logs.Body.String(), "root snapshot fixture") || strings.Contains(logs.Body.String(), "fixture-secret") {
		t.Fatalf("operational logs = %d %s", logs.Code, logs.Body.String())
	}
	bad := authorizedRequest(server, session, http.MethodGet, "/api/v1/vps/logs?category=../../etc&limit=50", nil, "")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unsafe category = %d %s", bad.Code, bad.Body.String())
	}
	status := authorizedRequest(server, session, http.MethodGet, "/api/v1/vps/diagnostics/status", nil, "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"secrets_included":false`) {
		t.Fatalf("diagnostic status = %d %s", status.Code, status.Body.String())
	}
	download := authorizedRequest(server, session, http.MethodPost, "/api/v1/vps/diagnostics/download", nil, "")
	if download.Code != http.StatusOK || download.Header().Get("Content-Type") != "application/zip" || download.Header().Get("X-Content-SHA256") == "" {
		t.Fatalf("diagnostic download = %d %v %s", download.Code, download.Header(), download.Body.String())
	}
	manifest, err := vpsops.VerifyBundle(download.Body.Bytes())
	if err != nil || !manifest.Complete || manifest.SecretsIncluded {
		t.Fatalf("diagnostic verification = %+v %v", manifest, err)
	}
}

func TestVPSHubManagementAPIEndToEndAndDestructiveReauthentication(t *testing.T) {
	server, _ := vpsAPIFixture(t)
	session := loginVPSHub(t, server, "administrator password 123")
	invitationResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/pairing-invitations", map[string]any{
		"gateway_name": "Дом", "endpoint": "vps.example:51820", "assigned_subnet": "10.82.0.0/30", "expiry_seconds": 900,
	})
	if invitationResponse.Code != http.StatusCreated {
		t.Fatalf("create invitation = %d %s", invitationResponse.Code, invitationResponse.Body.String())
	}
	var invitation struct {
		Invitation vpsagent.PairingBundle `json:"invitation"`
		ShownOnce  bool                   `json:"token_shown_once"`
	}
	if err := json.Unmarshal(invitationResponse.Body.Bytes(), &invitation); err != nil || invitation.Invitation.Token == "" || !invitation.ShownOnce {
		t.Fatalf("invitation response = %+v, %v", invitation, err)
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	completion := jsonRequest(t, server, apiSession{}, http.MethodPost, "/api/v1/pairing/complete", map[string]any{
		"invitation_id": invitation.Invitation.InvitationID, "token": invitation.Invitation.Token,
		"site_id": "site:home", "display_name": "Дом", "public_key": pair.Public, "webui_url": "https://10.82.0.2/",
	})
	if completion.Code != http.StatusCreated || strings.Contains(completion.Body.String(), invitation.Invitation.Token) {
		t.Fatalf("complete pairing = %d %s", completion.Code, completion.Body.String())
	}
	var paired struct {
		Gateway vpsagent.GatewayPeer `json:"gateway"`
	}
	if err := json.Unmarshal(completion.Body.Bytes(), &paired); err != nil || paired.Gateway.ID == "" {
		t.Fatalf("paired Gateway = %+v, %v", paired, err)
	}

	adminPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	adminResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins", map[string]any{
		"name": "Ноутбук", "public_key": adminPair.Public, "assigned_address": "10.81.0.10", "key_mode": "EXTERNAL",
	})
	if adminResponse.Code != http.StatusCreated {
		t.Fatalf("create admin = %d %s", adminResponse.Code, adminResponse.Body.String())
	}
	var admin vpsagent.AdminPeer
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &admin); err != nil || admin.ID == "" {
		t.Fatalf("admin = %+v, %v", admin, err)
	}
	relayAdminPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayAdminResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins", map[string]any{
		"name": "Телефон end-to-end", "public_key": relayAdminPair.Public, "assigned_address": "10.81.0.13",
		"key_mode": "EXTERNAL", "trust_mode": vpsagent.TrustEndToEndRelay,
	})
	if relayAdminResponse.Code != http.StatusCreated {
		t.Fatalf("create end-to-end admin = %d %s", relayAdminResponse.Code, relayAdminResponse.Body.String())
	}
	var relayAdmin vpsagent.AdminPeer
	if err := json.Unmarshal(relayAdminResponse.Body.Bytes(), &relayAdmin); err != nil || relayAdmin.ID == "" || relayAdmin.TrustMode != vpsagent.TrustEndToEndRelay {
		t.Fatalf("end-to-end admin = %+v, %v", relayAdmin, err)
	}
	managedRelay := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins", map[string]any{
		"name": "Managed relay", "assigned_address": "10.81.0.14", "key_mode": "MANAGED",
		"trust_mode": vpsagent.TrustEndToEndRelay, "password": "administrator password 123",
		"confirmation": "СОЗДАТЬ УПРАВЛЯЕМЫЙ КЛЮЧ",
	})
	if managedRelay.Code != http.StatusBadRequest || !strings.Contains(managedRelay.Body.String(), "MANAGED_ADMIN_TRUST_MODE_INVALID") {
		t.Fatalf("managed end-to-end admin = %d %s", managedRelay.Code, managedRelay.Body.String())
	}

	relayResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admin-relays", map[string]any{
		"gateway_peer_id": paired.Gateway.ID, "public_endpoint_host": "relay.example",
		"public_bind_address": "203.0.113.10", "public_udp_port": 51830,
		"destination_port": vpsagent.AdminRelayDestinationPort, "rate_limit_per_second": 120, "burst_packets": 240,
	})
	if relayResponse.Code != http.StatusCreated {
		t.Fatalf("create end-to-end relay = %d %s", relayResponse.Code, relayResponse.Body.String())
	}
	var relay vpsagent.AdminRelay
	if err := json.Unmarshal(relayResponse.Body.Bytes(), &relay); err != nil || relay.ID == "" || !relay.Enabled || relay.GatewayPeerID != paired.Gateway.ID {
		t.Fatalf("end-to-end relay = %+v, %v", relay, err)
	}
	if body := strings.ToLower(relayResponse.Body.String()); strings.Contains(body, "private_key") || strings.Contains(body, "private-key") || strings.Contains(body, "server.key") {
		t.Fatalf("relay response exposes private key material: %s", relayResponse.Body.String())
	}
	relays := authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/admin-relays", nil, "")
	if relays.Code != http.StatusOK || !strings.Contains(relays.Body.String(), relay.ID) || !strings.Contains(relays.Body.String(), `"private_keys_on_vps":false`) || !strings.Contains(relays.Body.String(), `"destination_port":51822`) {
		t.Fatalf("list end-to-end relays = %d %s", relays.Code, relays.Body.String())
	}
	deleteEnabled := authorizedRequest(server, session, http.MethodDelete, "/api/v1/hub/admin-relays/"+relay.ID, nil, "delete-disabled-admin-relay")
	if deleteEnabled.Code != http.StatusBadRequest {
		t.Fatalf("delete enabled relay = %d %s", deleteEnabled.Code, deleteEnabled.Body.String())
	}
	disableRelay := jsonRequest(t, server, session, http.MethodPut, "/api/v1/hub/admin-relays/"+relay.ID+"/enabled", map[string]any{"enabled": false})
	if disableRelay.Code != http.StatusNoContent {
		t.Fatalf("disable relay = %d %s", disableRelay.Code, disableRelay.Body.String())
	}
	enableRelay := jsonRequest(t, server, session, http.MethodPut, "/api/v1/hub/admin-relays/"+relay.ID+"/enabled", map[string]any{"enabled": true})
	if enableRelay.Code != http.StatusNoContent {
		t.Fatalf("enable relay = %d %s", enableRelay.Code, enableRelay.Body.String())
	}
	disableRelay = jsonRequest(t, server, session, http.MethodPut, "/api/v1/hub/admin-relays/"+relay.ID+"/enabled", map[string]any{"enabled": false})
	if disableRelay.Code != http.StatusNoContent {
		t.Fatalf("disable relay before delete = %d %s", disableRelay.Code, disableRelay.Body.String())
	}
	deleteRelay := authorizedRequest(server, session, http.MethodDelete, "/api/v1/hub/admin-relays/"+relay.ID, nil, "delete-disabled-admin-relay")
	if deleteRelay.Code != http.StatusNoContent {
		t.Fatalf("delete disabled relay = %d %s", deleteRelay.Code, deleteRelay.Body.String())
	}
	relays = authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/admin-relays", nil, "")
	if relays.Code != http.StatusOK || strings.Contains(relays.Body.String(), relay.ID) {
		t.Fatalf("deleted relay survived = %d %s", relays.Code, relays.Body.String())
	}
	trustRouted := jsonRequest(t, server, session, http.MethodPut, "/api/v1/hub/admins/"+relayAdmin.ID+"/trust-mode", map[string]any{"trust_mode": vpsagent.TrustRoutedHub})
	if trustRouted.Code != http.StatusNoContent {
		t.Fatalf("change trust mode to routed = %d %s", trustRouted.Code, trustRouted.Body.String())
	}
	trustEndToEnd := jsonRequest(t, server, session, http.MethodPut, "/api/v1/hub/admins/"+relayAdmin.ID+"/trust-mode", map[string]any{"trust_mode": vpsagent.TrustEndToEndRelay})
	if trustEndToEnd.Code != http.StatusNoContent {
		t.Fatalf("change trust mode to end-to-end = %d %s", trustEndToEnd.Code, trustEndToEnd.Body.String())
	}
	managed := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins", map[string]any{
		"name": "Managed", "assigned_address": "10.81.0.11", "key_mode": "MANAGED",
		"password": "administrator password 123", "confirmation": "СОЗДАТЬ УПРАВЛЯЕМЫЙ КЛЮЧ",
	})
	if managed.Code != http.StatusCreated || strings.Contains(managed.Body.String(), "PrivateKey") || strings.Contains(managed.Body.String(), "private_key") {
		t.Fatalf("managed admin creation = %d %s", managed.Code, managed.Body.String())
	}
	var managedAdmin vpsagent.AdminPeer
	if err := json.Unmarshal(managed.Body.Bytes(), &managedAdmin); err != nil || managedAdmin.KeyMode != "MANAGED" || managedAdmin.ConfigState != "AVAILABLE" {
		t.Fatalf("managed admin = %+v, %v", managedAdmin, err)
	}
	config := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins/"+managedAdmin.ID+"/config", map[string]any{
		"endpoint": "vps.example:51820", "password": "administrator password 123",
		"confirmation": "СКАЧАТЬ КОНФИГУРАЦИЮ " + managedAdmin.ID,
	})
	if config.Code != http.StatusOK || !strings.Contains(config.Body.String(), "PrivateKey = ") || !strings.Contains(config.Body.String(), "Endpoint = vps.example:51820") || strings.Contains(config.Body.String(), "10.81.0.10") {
		t.Fatalf("managed admin one-use config = %d %s", config.Code, config.Body.String())
	}
	repeated := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins/"+managedAdmin.ID+"/config", map[string]any{
		"endpoint": "vps.example:51820", "password": "administrator password 123",
		"confirmation": "СКАЧАТЬ КОНФИГУРАЦИЮ " + managedAdmin.ID,
	})
	if repeated.Code != http.StatusConflict {
		t.Fatalf("repeated managed config = %d %s", repeated.Code, repeated.Body.String())
	}
	rotation := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins/"+managedAdmin.ID+"/rotate", map[string]any{
		"assigned_address": "10.81.0.12", "password": "administrator password 123",
		"confirmation": "НАЧАТЬ СМЕНУ КЛЮЧА " + managedAdmin.ID,
	})
	if rotation.Code != http.StatusCreated || !strings.Contains(rotation.Body.String(), `"rotation_source_id":"`+managedAdmin.ID+`"`) {
		t.Fatalf("managed admin rotation = %d %s", rotation.Code, rotation.Body.String())
	}

	resourceResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/resources", map[string]any{
		"gateway_peer_id": paired.Gateway.ID, "resource_id": "gateway:web", "display_name": "Gateway WebUI",
		"resource_kind": "GATEWAY_SERVICE", "local_destination": "192.168.200.2", "published_alias": "10.96.0.2",
		"access_profile": "GATEWAY_ONLY", "enabled": true, "advanced_scope_acknowledged": false,
	})
	if resourceResponse.Code != http.StatusCreated {
		t.Fatalf("create resource = %d %s", resourceResponse.Code, resourceResponse.Body.String())
	}
	var resource vpsagent.ResourcePublication
	if err := json.Unmarshal(resourceResponse.Body.Bytes(), &resource); err != nil || resource.ID == "" {
		t.Fatalf("resource = %+v, %v", resource, err)
	}
	aclResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/acl", map[string]any{
		"admin_peer_id": admin.ID, "publication_id": resource.ID, "protocol": "TCP", "port_start": 443, "port_end": 443,
	})
	if aclResponse.Code != http.StatusCreated {
		t.Fatalf("create ACL = %d %s", aclResponse.Code, aclResponse.Body.String())
	}
	matrix := authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/access-matrix", nil, "")
	if matrix.Code != http.StatusOK || !strings.Contains(matrix.Body.String(), `"host_apply_available":false`) || !strings.Contains(matrix.Body.String(), admin.ID) || !strings.Contains(matrix.Body.String(), resource.ID) {
		t.Fatalf("access matrix = %d %s", matrix.Code, matrix.Body.String())
	}
	watchdog := authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/watchdog", nil, "")
	if watchdog.Code != http.StatusOK || !strings.Contains(watchdog.Body.String(), `"state":"PENDING"`) || !strings.Contains(watchdog.Body.String(), "HOST_APPLY_NOT_IMPLEMENTED") {
		t.Fatalf("watchdog = %d %s", watchdog.Code, watchdog.Body.String())
	}

	wrong := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins/"+admin.ID+"/revoke", map[string]any{
		"password": "wrong password", "confirmation": "ОТОЗВАТЬ АДМИНИСТРАТОРА " + admin.ID,
	})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong admin revoke = %d %s", wrong.Code, wrong.Body.String())
	}
	revoke := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins/"+admin.ID+"/revoke", map[string]any{
		"password": "administrator password 123", "confirmation": "ОТОЗВАТЬ АДМИНИСТРАТОРА " + admin.ID,
	})
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke admin = %d %s", revoke.Code, revoke.Body.String())
	}
	matrix = authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/access-matrix", nil, "")
	if strings.Contains(matrix.Body.String(), `"admin_peer_id":"`+admin.ID+`"`) {
		t.Fatalf("revoked admin ACL survived: %s", matrix.Body.String())
	}
}

func TestVPSHubFabricTriggerSchedulesAutomaticAndExplicitApply(t *testing.T) {
	fabric := &fakeFabricTrigger{}
	server, _ := newVPSAPIFixture(t, fabric)
	session := loginVPSHub(t, server, "administrator password 123")
	overview := authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/overview", nil, "")
	if overview.Code != http.StatusOK || !strings.Contains(overview.Body.String(), `"host_apply_available":true`) {
		t.Fatalf("fabric-aware overview = %d %s", overview.Code, overview.Body.String())
	}
	watchdog := authorizedRequest(server, session, http.MethodGet, "/api/v1/hub/watchdog", nil, "")
	if watchdog.Code != http.StatusOK || !strings.Contains(watchdog.Body.String(), `"host_fabric":{`) || !strings.Contains(watchdog.Body.String(), `"available":true`) || !strings.Contains(watchdog.Body.String(), `"reason":"HEALTHY"`) || !strings.Contains(watchdog.Body.String(), `"relay_rule_count":0`) {
		t.Fatalf("fabric-aware watchdog = %d %s", watchdog.Code, watchdog.Body.String())
	}
	initial := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/fabric/apply", map[string]any{})
	if initial.Code != http.StatusAccepted || fabric.calls != 1 || !strings.Contains(initial.Body.String(), "APPLY_SCHEDULED") {
		t.Fatalf("initial fabric apply = %d calls=%d %s", initial.Code, fabric.calls, initial.Body.String())
	}
	invitationResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/pairing-invitations", map[string]any{
		"gateway_name": "Дом", "endpoint": "vps.example:51820", "assigned_subnet": "10.82.0.0/30", "expiry_seconds": 900,
	})
	var invitation struct {
		Invitation vpsagent.PairingBundle `json:"invitation"`
	}
	if invitationResponse.Code != http.StatusCreated || json.Unmarshal(invitationResponse.Body.Bytes(), &invitation) != nil {
		t.Fatalf("fabric pairing invitation = %d %s", invitationResponse.Code, invitationResponse.Body.String())
	}
	pair, _ := wgingress.GenerateKeyPair()
	completion := jsonRequest(t, server, apiSession{}, http.MethodPost, "/api/v1/pairing/complete", map[string]any{
		"invitation_id": invitation.Invitation.InvitationID, "token": invitation.Invitation.Token,
		"site_id": "site:trigger", "display_name": "Дом", "public_key": pair.Public, "webui_url": "https://10.82.0.2:9444/",
	})
	if completion.Code != http.StatusCreated || fabric.calls != 2 {
		t.Fatalf("automatic fabric schedule = %d calls=%d %s", completion.Code, fabric.calls, completion.Body.String())
	}
	adminPair, _ := wgingress.GenerateKeyPair()
	adminResponse := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/admins", map[string]any{
		"name": "End-to-end admin", "public_key": adminPair.Public, "assigned_address": "10.81.0.20",
		"key_mode": "EXTERNAL", "trust_mode": vpsagent.TrustEndToEndRelay,
	})
	var admin vpsagent.AdminPeer
	if adminResponse.Code != http.StatusCreated || json.Unmarshal(adminResponse.Body.Bytes(), &admin) != nil || fabric.calls != 3 {
		t.Fatalf("trust-mode admin schedule = %d calls=%d %s", adminResponse.Code, fabric.calls, adminResponse.Body.String())
	}
	trustMode := jsonRequest(t, server, session, http.MethodPut, "/api/v1/hub/admins/"+admin.ID+"/trust-mode", map[string]any{"trust_mode": vpsagent.TrustRoutedHub})
	if trustMode.Code != http.StatusNoContent || fabric.calls != 4 {
		t.Fatalf("trust-mode update schedule = %d calls=%d %s", trustMode.Code, fabric.calls, trustMode.Body.String())
	}
	manual := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/fabric/apply", map[string]any{})
	if manual.Code != http.StatusAccepted || fabric.calls != 5 || !strings.Contains(manual.Body.String(), "APPLY_SCHEDULED") {
		t.Fatalf("manual fabric schedule = %d calls=%d %s", manual.Code, fabric.calls, manual.Body.String())
	}
	fabric.err = errors.New("injected trigger failure")
	failed := jsonRequest(t, server, session, http.MethodPost, "/api/v1/hub/fabric/apply", map[string]any{})
	if failed.Code != http.StatusBadGateway || fabric.calls != 6 {
		t.Fatalf("failed fabric schedule = %d calls=%d %s", failed.Code, fabric.calls, failed.Body.String())
	}
}

func TestVPSHubWebUIExposesFabricApplyAndRootWatchdogStatus(t *testing.T) {
	server, _ := newVPSAPIFixture(t, &fakeFabricTrigger{})
	for path, required := range map[string][]string{
		"/styles.css": {
			"overflow-wrap:anywhere", "text-wrap:balance", "minmax(min(320px,100%),1fr)", ".mobile-navigation{display:grid}", ".actions button,form>button,.page-heading>button{width:100%}", ".log-tabs", ".log-window", ".inline-filter",
		},
		"/app.js": {
			"/api/v1/hub/fabric/apply", "Применить изменения сейчас", "Запустить reconciliation",
			"host_fabric", "Последняя root-проверка", "Привилегированный reconciler",
			"/api/v1/hub/admin-relays", "/trust-mode", "private_keys_on_vps", "mobile-navigation-select",
			"/api/v1/vps/logs", "/api/v1/vps/diagnostics/status", "/api/v1/vps/diagnostics/download", "Отображение очищено",
		},
		"/": {
			"последнюю root-проверку Management Fabric", "ownership-scoped root transaction с rollback",
			"data-page=\"relays\"", "Создать и включить relay", "ключ не хранится на VPS", "id=\"mobile-navigation-select\"",
			"data-page=\"logs\"", "Журналы VPS Hub", "Очистить окно", "data-page=\"diagnostics\"", "Собрать и скачать ZIP",
		},
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, recorder.Code)
		}
		for _, value := range required {
			if !strings.Contains(recorder.Body.String(), value) {
				t.Fatalf("GET %s missing %q", path, value)
			}
		}
		if strings.Contains(recorder.Body.String(), "Нет, следующий этап") || strings.Contains(recorder.Body.String(), "Ещё не подключён") {
			t.Fatalf("GET %s still contains obsolete host-apply placeholder", path)
		}
	}
}

func vpsAPIFixture(t *testing.T) (*Server, *fakeRestoreTrigger) {
	return newVPSAPIFixture(t, nil)
}

func newVPSAPIFixture(t *testing.T, fabric FabricApplyTrigger) (*Server, *fakeRestoreTrigger) {
	t.Helper()
	ctx := context.Background()
	stateDirectory := filepath.Join(t.TempDir(), "state")
	databasePath := filepath.Join(stateDirectory, "vps-agent.db")
	database, err := vpsagent.Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vpsagent.InitializeIdentity(ctx, database, vpsagent.IdentityInput{
		VPSID: "vps:test", DisplayName: "Test VPS", IdentityFingerprint: strings.Repeat("c", 64), PublicKey: pair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	configurationPath := filepath.Join(t.TempDir(), "vps-agent.yaml")
	files := map[string]string{
		configurationPath: "version: 1\nlisten: 127.0.0.1:9443\n",
		filepath.Join(stateDirectory, "secrets", "wireguard", "server.key"): "private-wireguard-key",
		filepath.Join(stateDirectory, "secrets", "update", "identity.key"):  "private-update-key",
		filepath.Join(stateDirectory, "tls", "cert.pem"):                    "test-certificate",
		filepath.Join(stateDirectory, "tls", "key.pem"):                     "private-tls-key",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	authService := auth.Service{Database: database}
	if created, err := authService.CreateBootstrapAdmin(ctx, "administrator password 123"); err != nil || !created {
		t.Fatalf("CreateBootstrapAdmin() = %t, %v", created, err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE users SET must_change_password=0 WHERE id='admin'"); err != nil {
		t.Fatal(err)
	}
	backupManager, err := vpsbackup.NewManager(database, stateDirectory, configurationPath, "vps-agent test")
	if err != nil {
		t.Fatal(err)
	}
	restoreManager, err := vpsbackup.NewRestoreManager(database, stateDirectory, databasePath, configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	adminKeys, err := vpsagent.NewAdminKeyManager(database, stateDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	trigger := &fakeRestoreTrigger{}
	now := time.Now().UTC()
	fabricStatusPath := ""
	if fabric != nil {
		fabricStatusPath = filepath.Join(stateDirectory, vpsfabric.WatchdogStatusFilename)
		status := vpsfabric.NewWatchdogStatus("HEALTHY", "HEALTHY", true, false, now)
		if err := vpsfabric.WriteWatchdogStatus(fabricStatusPath, status, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	operationsDirectory := filepath.Join(stateDirectory, "operations")
	if err := os.MkdirAll(operationsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	operationsPath := filepath.Join(operationsDirectory, "snapshot.json")
	snapshot := vpsops.Snapshot{
		SchemaVersion: vpsops.SnapshotSchemaVersion, CollectedAt: now.Format(time.RFC3339Nano), State: "HEALTHY",
		Units: []vpsops.UnitStatus{}, Host: vpsops.HostStatus{Interfaces: []vpsops.InterfaceStatus{}, OwnedRoutes: json.RawMessage("[]"), OwnedNFT: json.RawMessage("{}")}, FabricStatus: json.RawMessage("{}"),
		Entries: []vpsops.LogEntry{{Cursor: "s=fixture-1", OccurredAt: now.Format(time.RFC3339Nano), Severity: "info", Category: vpsops.CategoryAgent, Source: "systemd-journald", Unit: "gateway-vpn-vps-agent.service", Message: "root snapshot fixture"}}, SectionErrors: []string{},
	}
	content, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operationsPath, append(content, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO audit_events(occurred_at,severity,event_type,details_json) VALUES(?,?,?,?)`, now.Format(time.RFC3339Nano), "WARNING", "VPS_ADMIN_PEER_CREATED", `{"password":"fixture-secret"}`); err != nil {
		t.Fatal(err)
	}
	server, err := New(Dependencies{
		Database: database, Auth: authService, Backups: backupManager, Restores: restoreManager,
		AdminKeys: &adminKeys, RestoreApply: trigger, FabricApply: fabric, FabricStatusPath: fabricStatusPath,
		Operations: &vpsops.Service{Database: database, SnapshotPath: operationsPath, FabricStatusPath: operationsPath, Config: vpsops.ConfigSummary{Listen: []string{"127.0.0.1:9443"}, AdminPrefixes: []string{"10.80.0.0/24"}, StateDirectory: stateDirectory}, AgentVersion: "test"},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, trigger
}

func loginVPSHub(t *testing.T, server *Server, password string) apiSession {
	t.Helper()
	recorder := jsonRequest(t, server, apiSession{}, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "admin", "password": password})
	if recorder.Code != http.StatusOK {
		t.Fatalf("login = %d %s", recorder.Code, recorder.Body.String())
	}
	response := struct {
		CSRF string `json:"csrf_token"`
	}{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || response.CSRF == "" {
		t.Fatalf("login cookie/CSRF = %v / %+v", cookies, response)
	}
	return apiSession{Cookie: cookies[0], CSRF: response.CSRF}
}

func jsonRequest(t *testing.T, server *Server, session apiSession, method, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return authorizedRequest(server, session, method, path, bytes.NewReader(content), "")
}

func authorizedRequest(server *Server, session apiSession, method, path string, body *bytes.Reader, destructive string) *httptest.ResponseRecorder {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, body)
		request.Header.Set("Content-Type", "application/json")
	}
	if session.Cookie != nil {
		request.AddCookie(session.Cookie)
	}
	if session.CSRF != "" {
		request.Header.Set("X-CSRF-Token", session.CSRF)
	}
	if destructive != "" {
		request.Header.Set("X-Confirm-Destructive", destructive)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func multipartRestoreRequest(t *testing.T, server *Server, session apiSession, filename string, content []byte, passphrase string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("passphrase")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(passphrase))
	part, err = writer.CreateFormFile("backup", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(content)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/vps/restore/stage", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-CSRF-Token", session.CSRF)
	request.AddCookie(session.Cookie)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}
