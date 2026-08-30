// Command vpswebui-preview serves a disposable HTTP-only VPS Hub fixture on
// loopback for browser smoke tests. It is never included in release artifacts.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsbackup"
	"gateway-vpn/internal/vpsops"
	"gateway-vpn/internal/vpswebapi"
	"gateway-vpn/internal/wgingress"
)

const previewPassword = "browser-test-password-123"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	root, err := os.MkdirTemp("", "gateway-vpn-vps-preview-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	state := filepath.Join(root, "state")
	databasePath := filepath.Join(state, "vps-agent.db")
	database, err := vpsagent.Open(ctx, databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	vpsPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		return err
	}
	if _, err := vpsagent.InitializeIdentity(ctx, database, vpsagent.IdentityInput{
		VPSID: "vps:preview", DisplayName: "Тестовый VPS", IdentityFingerprint: strings.Repeat("d", 64), PublicKey: vpsPair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Now()); err != nil {
		return err
	}
	configurationPath := filepath.Join(root, "config.yaml")
	files := map[string]string{
		configurationPath: "version: 1\nlisten: 127.0.0.1:9443\n",
		filepath.Join(state, "secrets", "wireguard", "server.key"): vpsPair.Private,
		filepath.Join(state, "secrets", "update", "identity.key"):  strings.Repeat("a", 64),
		filepath.Join(state, "tls", "cert.pem"):                    "preview-certificate",
		filepath.Join(state, "tls", "key.pem"):                     "preview-private-key",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	authService := auth.Service{Database: database}
	if created, err := authService.CreateBootstrapAdmin(ctx, previewPassword); err != nil || !created {
		return fmt.Errorf("create preview administrator: created=%t: %w", created, err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE users SET must_change_password=0 WHERE id='admin'"); err != nil {
		return err
	}
	repository := vpsagent.HubRepository{Database: database}
	invitation, err := repository.CreatePairing(ctx, vpsagent.PairingCreateInput{
		GatewayName: "Пример Gateway", Endpoint: "vps.example:51820", Subnet: "10.82.0.0/30",
	})
	if err != nil {
		return err
	}
	gatewayPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		return err
	}
	gateway, err := repository.CompletePairing(ctx, vpsagent.PairingCompletion{
		InvitationID: invitation.InvitationID, Token: invitation.Token, SiteID: "site:preview",
		DisplayName: "Пример Gateway", PublicKey: gatewayPair.Public, WebUIURL: "https://10.82.0.2/",
	})
	if err != nil {
		return err
	}
	adminPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		return err
	}
	admin, err := repository.CreateAdmin(ctx, vpsagent.AdminCreateInput{
		Name: "Пример администратора", PublicKey: adminPair.Public, AssignedAddress: "10.81.0.10", KeyMode: "EXTERNAL",
	})
	if err != nil {
		return err
	}
	resource, err := repository.CreateResource(ctx, vpsagent.ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "gateway:web", DisplayName: "Gateway WebUI",
		ResourceKind: "GATEWAY_SERVICE", LocalDestination: "192.168.200.2", PublishedAlias: "10.96.0.2",
		AccessProfile: "GATEWAY_ONLY", Enabled: true,
	})
	if err != nil {
		return err
	}
	if _, err := repository.CreateACL(ctx, vpsagent.ACLInput{
		AdminPeerID: admin.ID, PublicationID: resource.ID, Protocol: "TCP", PortStart: 443, PortEnd: 443,
	}); err != nil {
		return err
	}
	backups, err := vpsbackup.NewManager(database, state, configurationPath, "vps-agent browser preview")
	if err != nil {
		return err
	}
	restores, err := vpsbackup.NewRestoreManager(database, state, databasePath, configurationPath)
	if err != nil {
		return err
	}
	adminKeys, err := vpsagent.NewAdminKeyManager(database, state, nil)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	operationsDirectory := filepath.Join(state, "operations")
	if err := os.MkdirAll(operationsDirectory, 0o700); err != nil {
		return err
	}
	operationsPath := filepath.Join(operationsDirectory, "snapshot.json")
	snapshot := vpsops.Snapshot{
		SchemaVersion: vpsops.SnapshotSchemaVersion, CollectedAt: now.Format(time.RFC3339Nano), State: "HEALTHY",
		Units:        []vpsops.UnitStatus{{Unit: "gateway-vpn-vps-agent.service", LoadState: "loaded", ActiveState: "active", SubState: "running"}},
		Host:         vpsops.HostStatus{Interfaces: []vpsops.InterfaceStatus{{Name: "wg-mgmt", State: "UP", Addresses: []string{"10.80.0.1/24"}}}, OwnedRoutes: json.RawMessage("[]"), OwnedNFT: json.RawMessage(`{"nftables":[]}`), WireGuard: vpsops.WireGuardStatus{Available: true, ListenPort: 51821, Peers: 2}},
		FabricStatus: json.RawMessage(`{"state":"HEALTHY"}`), Entries: []vpsops.LogEntry{{Cursor: "s=preview-1", OccurredAt: now.Format(time.RFC3339Nano), Severity: "info", Category: vpsops.CategoryAgent, Source: "systemd-journald", Unit: "gateway-vpn-vps-agent.service", Message: "VPS Hub preview is ready"}}, SectionErrors: []string{},
	}
	content, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err := os.WriteFile(operationsPath, append(content, '\n'), 0o600); err != nil {
		return err
	}
	operations := &vpsops.Service{Database: database, SnapshotPath: operationsPath, FabricStatusPath: operationsPath, Config: vpsops.ConfigSummary{Listen: []string{"127.0.0.1:9443"}, AdminPrefixes: []string{"10.80.0.0/24"}, StateDirectory: state}, AgentVersion: "vps-agent browser preview"}
	web, err := vpswebapi.New(vpswebapi.Dependencies{Database: database, Auth: authService, Backups: backups, Restores: restores, AdminKeys: &adminKeys, Operations: operations})
	if err != nil {
		return err
	}
	server := &http.Server{Addr: "127.0.0.1:18081", Handler: web.Handler(), ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("READY http://127.0.0.1:18081 user=admin password=%s\n", previewPassword)
	return server.ListenAndServe()
}
