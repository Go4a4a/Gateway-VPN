package webapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
)

func TestWireGuardIngressManagedExportRequiresSingleUseReauthentication(t *testing.T) {
	server, ctx := testServer(t)
	controller := attachWireGuardIngress(t, server)
	if _, err := controller.backend.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: false, Name: "Clients", SubnetCIDR: "10.90.0.0/24", ListenPort: 51820,
		EndpointHost: "vpn.example.org", MTU: 1420, TopologyMode: "ROUTED", DNS: []string{"1.1.1.1"},
	}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := login(t, server)
	request := func(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(cookie)
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, req)
		return response
	}
	created := request(http.MethodPost, "/api/v1/wireguard-ingress/peers", `{
  "name":"Phone","peer_kind":"DEVICE","key_mode":"MANAGED","persistent_keepalive":25,
  "access_policy_mode":"AUTO","allow_whitelist_only":true,"block_when_unqualified":true,
  "client_dns_enabled":true,"behind_subnets":[],"client_allowed_ips":["0.0.0.0/0"],
  "allowed_access_method_ids":[]
}`, nil)
	if created.Code != http.StatusCreated {
		t.Fatalf("create managed peer = %d %s", created.Code, created.Body.String())
	}
	var payload struct {
		Peer wgingress.Peer `json:"peer"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil || payload.Peer.ID == "" {
		t.Fatalf("managed peer response = %s, %v", created.Body.String(), err)
	}
	var privateRef, presharedRef string
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT private_key_secret_ref,preshared_key_secret_ref FROM wireguard_ingress_peers WHERE id=?", payload.Peer.ID).Scan(&privateRef, &presharedRef); err != nil {
		t.Fatal(err)
	}
	privateContent, err := os.ReadFile(privateRef)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := strings.TrimSpace(string(privateContent))
	for _, responseBody := range []string{created.Body.String(), request(http.MethodGet, "/api/v1/wireguard-ingress/peers", "", nil).Body.String()} {
		if strings.Contains(responseBody, privateKey) || strings.Contains(responseBody, privateRef) || strings.Contains(responseBody, presharedRef) || strings.Contains(responseBody, "private_key_secret_ref") {
			t.Fatalf("ordinary WireGuard API exposed a secret: %s", responseBody)
		}
	}

	withoutGrant := request(http.MethodGet, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/config", "", nil)
	if withoutGrant.Code != http.StatusForbidden || !strings.Contains(withoutGrant.Body.String(), "REAUTH_REQUIRED") {
		t.Fatalf("config without reauth = %d %s", withoutGrant.Code, withoutGrant.Body.String())
	}
	wrongPassword := request(http.MethodPost, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/reauth", `{"password_confirmation":"wrong"}`, nil)
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password reauth = %d %s", wrongPassword.Code, wrongPassword.Body.String())
	}
	grant := request(http.MethodPost, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/reauth", `{"password_confirmation":"correct horse battery staple"}`, nil)
	var grantPayload struct {
		Token string `json:"reauth_token"`
	}
	if grant.Code != http.StatusOK || json.Unmarshal(grant.Body.Bytes(), &grantPayload) != nil || grantPayload.Token == "" {
		t.Fatalf("reauth grant = %d %s", grant.Code, grant.Body.String())
	}
	config := request(http.MethodGet, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/config", "", map[string]string{"X-Reauth-Token": grantPayload.Token})
	if config.Code != http.StatusOK || !strings.Contains(config.Body.String(), "PrivateKey = "+privateKey) || config.Header().Get("Cache-Control") != "no-store" || !strings.Contains(config.Header().Get("Content-Type"), "application/wireguard-profile") {
		t.Fatalf("managed config = %d headers=%v body=%s", config.Code, config.Header(), config.Body.String())
	}
	reused := request(http.MethodGet, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/config", "", map[string]string{"X-Reauth-Token": grantPayload.Token})
	if reused.Code != http.StatusForbidden {
		t.Fatalf("reused grant = %d %s", reused.Code, reused.Body.String())
	}

	grant = request(http.MethodPost, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/reauth", `{"password_confirmation":"correct horse battery staple"}`, nil)
	if json.Unmarshal(grant.Body.Bytes(), &grantPayload) != nil || grantPayload.Token == "" {
		t.Fatalf("QR grant = %d %s", grant.Code, grant.Body.String())
	}
	qr := request(http.MethodGet, "/api/v1/wireguard-ingress/peers/"+payload.Peer.ID+"/qrcode", "", map[string]string{"X-Reauth-Token": grantPayload.Token})
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(qr.Body.Bytes(), []byte{0x89, 'P', 'N', 'G'}) || qr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("managed QR = %d headers=%v bytes=%x", qr.Code, qr.Header(), qr.Body.Bytes()[:min(qr.Body.Len(), 8)])
	}
}

func TestWireGuardIngressExternalPeerExportsOnlyPlaceholder(t *testing.T) {
	server, ctx := testServer(t)
	controller := attachWireGuardIngress(t, server)
	if _, err := controller.backend.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: false, Name: "Clients", SubnetCIDR: "10.90.0.0/24", ListenPort: 51820,
		EndpointHost: "vpn.example.org", MTU: 1420, TopologyMode: "ROUTED", DNS: []string{"1.1.1.1"},
	}); err != nil {
		t.Fatal(err)
	}
	pair, _ := wgingress.GenerateKeyPair()
	peer, err := controller.backend.CreatePeer(ctx, wgingress.PeerCreate{
		Name: "External router", PeerKind: "ROUTER_NAT", KeyMode: "EXTERNAL", PublicKey: pair.Public,
		PersistentKeepalive: 25, AccessPolicyMode: "AUTO", ClientAllowedIPs: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := login(t, server)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wireguard-ingress/peers/"+peer.ID+"/config", nil)
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "PrivateKey = <INSERT_PRIVATE_KEY>") || strings.Contains(response.Body.String(), pair.Private) || response.Header().Get("X-Gateway-VPN-Key-Mode") != "external-template" {
		t.Fatalf("external template = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

type webIngressController struct{ backend *wgingress.Backend }

func (controller webIngressController) SyncWireGuardIngress(ctx context.Context) error {
	return controller.backend.Sync(ctx)
}
func (controller webIngressController) UpdateWireGuardIngressServer(ctx context.Context, input wgingress.ServerUpdate) (wgingress.Server, error) {
	return controller.backend.UpdateServer(ctx, input)
}
func (controller webIngressController) RotateWireGuardIngressServer(ctx context.Context) (wgingress.Server, error) {
	return controller.backend.RotateServer(ctx)
}
func (controller webIngressController) CreateWireGuardIngressPeer(ctx context.Context, input wgingress.PeerCreate) (wgingress.Peer, error) {
	return controller.backend.CreatePeer(ctx, input)
}
func (controller webIngressController) UpdateWireGuardIngressPeer(ctx context.Context, id string, input wgingress.PeerUpdate) (wgingress.Peer, error) {
	return controller.backend.UpdatePeer(ctx, id, input)
}
func (controller webIngressController) RevokeWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	return controller.backend.RevokePeer(ctx, id)
}
func (controller webIngressController) DeleteWireGuardIngressPeer(ctx context.Context, id string) error {
	return controller.backend.DeletePeer(ctx, id)
}
func (controller webIngressController) RotateWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	return controller.backend.RotatePeer(ctx, id)
}
func (controller webIngressController) ProbeWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	return controller.backend.ProbePeer(ctx, id)
}
func (controller webIngressController) ExportWireGuardIngressPeer(ctx context.Context, id string) (wgingress.ExportedConfig, error) {
	return controller.backend.ExportPeerConfig(ctx, id)
}

type noCommandExecutor struct{}

func (noCommandExecutor) Run(context.Context, platformexec.Request) (platformexec.Result, error) {
	return platformexec.Result{}, os.ErrPermission
}

func attachWireGuardIngress(t *testing.T, server *Server) webIngressController {
	t.Helper()
	root := filepath.Join(t.TempDir(), "wireguard-ingress")
	repository := &wgingress.Repository{Database: server.dependencies.Database, SecretRoot: root}
	backend := &wgingress.Backend{
		Repository: *repository, Keys: wgingress.KeyStore{Root: root}, Executor: noCommandExecutor{},
		IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", Mutate: false,
	}
	controller := webIngressController{backend: backend}
	server.dependencies.WireGuardIngress = repository
	server.dependencies.WireGuardIngressAdmin = controller
	if err := backend.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	return controller
}
