package vpswebapi

import (
	"bytes"
	"context"
	"encoding/json"
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
	"gateway-vpn/internal/wgingress"
)

type fakeRestoreTrigger struct{ calls int }

func (trigger *fakeRestoreTrigger) ApplyPendingVPSRestore(context.Context) error {
	trigger.calls++
	return nil
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

func vpsAPIFixture(t *testing.T) (*Server, *fakeRestoreTrigger) {
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
	trigger := &fakeRestoreTrigger{}
	server, err := New(Dependencies{Database: database, Auth: authService, Backups: backupManager, Restores: restoreManager, RestoreApply: trigger})
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
