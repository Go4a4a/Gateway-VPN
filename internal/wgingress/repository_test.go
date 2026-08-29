package wgingress

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
)

func TestManagedAndExternalPeerLifecycleDoesNotExposeSecrets(t *testing.T) {
	ctx, repository, keys := ingressFixture(t)
	server, err := repository.EnsureDefault(ctx, keys)
	if err != nil || server.Enabled || !ValidKey(server.PublicKey) || server.PrivateKeySecretRef == "" {
		t.Fatalf("EnsureDefault() = %+v, %v", server, err)
	}
	pair, _ := GenerateKeyPair()
	psk, _ := GeneratePresharedKey()
	managed, err := repository.CreatePeer(ctx, PeerCreate{
		Name: "Телефон", PeerKind: "DEVICE", KeyMode: "MANAGED", PersistentKeepalive: 25,
		AccessPolicyMode: "AUTO", AllowWhitelistOnly: true, BlockWhenUnqualified: true,
		ClientDNSEnabled: true, ClientAllowedIPs: []string{"0.0.0.0/0"},
	}, &pair, psk, keys)
	if err != nil {
		t.Fatal(err)
	}
	if managed.DisplayNumber != 1 || managed.AssignedAddress != "10.90.0.2" || !managed.PrivateKeyAvailable {
		t.Fatalf("managed peer = %+v", managed)
	}
	payload, _ := json.Marshal(managed)
	if strings.Contains(string(payload), pair.Private) || strings.Contains(string(payload), psk) || strings.Contains(string(payload), "secret_ref") {
		t.Fatalf("peer JSON exposed secret material: %s", payload)
	}
	if content, err := os.ReadFile(managed.privateKeySecretRef); err != nil || strings.TrimSpace(string(content)) != pair.Private {
		t.Fatalf("managed private file = %q, %v", content, err)
	}

	externalPair, _ := GenerateKeyPair()
	external, err := repository.CreatePeer(ctx, PeerCreate{
		Name: "Роутер", PeerKind: "ROUTER_ROUTED", KeyMode: "EXTERNAL", PublicKey: externalPair.Public,
		PersistentKeepalive: 25, AccessPolicyMode: "AUTO", ClientDNSEnabled: false,
		BehindSubnets: []string{"172.20.0.0/24"}, ClientAllowedIPs: []string{"10.0.0.0/8"},
		AllowedAccessMethodIDs: []string{"access:direct"},
	}, nil, "", keys)
	if err != nil || external.DisplayNumber != 2 || external.PrivateKeyAvailable {
		t.Fatalf("external peer = %+v, %v", external, err)
	}
	if _, err := repository.CreatePeer(ctx, PeerCreate{
		Name: "Duplicate", PeerKind: "DEVICE", KeyMode: "EXTERNAL", PublicKey: externalPair.Public,
		PersistentKeepalive: 25, AccessPolicyMode: "AUTO", ClientAllowedIPs: []string{"0.0.0.0/0"},
	}, nil, "", keys); err == nil {
		t.Fatal("duplicate WireGuard public key was accepted")
	}
	if _, err := repository.CreatePeer(ctx, PeerCreate{
		Name: "Overlap", PeerKind: "ROUTER_ROUTED", KeyMode: "EXTERNAL", PublicKey: mustPublicKey(t),
		PersistentKeepalive: 25, AccessPolicyMode: "AUTO", BehindSubnets: []string{"172.20.0.128/25"}, ClientAllowedIPs: []string{"0.0.0.0/0"},
	}, nil, "", keys); err == nil {
		t.Fatal("overlapping behind subnet was accepted")
	}
	if _, err := repository.DeletePeer(ctx, managed.ID); err == nil {
		t.Fatal("active peer deletion was accepted")
	}
	revoked, err := repository.RevokePeer(ctx, managed.ID)
	if err != nil || revoked.RevokedAt == "" || revoked.Enabled {
		t.Fatalf("RevokePeer() = %+v, %v", revoked, err)
	}
	deleted, err := repository.DeletePeer(ctx, managed.ID)
	if err != nil || deleted.ID != managed.ID {
		t.Fatalf("DeletePeer() = %+v, %v", deleted, err)
	}
	nextPair, _ := GenerateKeyPair()
	next, err := repository.CreatePeer(ctx, PeerCreate{
		Name: "Новый", PeerKind: "DEVICE", KeyMode: "MANAGED", PersistentKeepalive: 25,
		AccessPolicyMode: "AUTO", ClientAllowedIPs: []string{"0.0.0.0/0"},
	}, &nextPair, mustPSK(t), keys)
	if err != nil || next.DisplayNumber != 3 {
		t.Fatalf("peer number was reused: %+v, %v", next, err)
	}
}

func TestClientConfigAndRuntimeObservationAreBounded(t *testing.T) {
	ctx, repository, keys := ingressFixture(t)
	server, err := repository.EnsureDefault(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	server.EndpointHost, server.Endpoint = "vpn.example.org", "vpn.example.org:51820"
	pair, _ := GenerateKeyPair()
	peer := Peer{
		Name: "Phone", DisplayNumber: 1, KeyMode: "MANAGED", AssignedAddress: "10.90.0.2",
		ClientDNSEnabled: true, ClientAllowedIPs: []string{"0.0.0.0/0"}, PersistentKeepalive: 25,
	}
	psk := mustPSK(t)
	content, err := RenderClientConfig(server, peer, pair.Private, psk)
	if err != nil || !strings.Contains(string(content), "Address = 10.90.0.2/32") || !strings.Contains(string(content), "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("RenderClientConfig() = %s, %v", content, err)
	}
	created, err := repository.CreatePeer(ctx, PeerCreate{
		Name: "Phone", PeerKind: "DEVICE", KeyMode: "MANAGED", PersistentKeepalive: 25,
		AccessPolicyMode: "AUTO", ClientAllowedIPs: []string{"0.0.0.0/0"},
	}, &pair, psk, keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	repository.Now = func() time.Time { return now }
	if err := repository.UpdatePeerRuntime(ctx, []PeerRuntime{{PublicKey: created.PublicKey, HandshakeAt: now.Add(-time.Minute), RXBytes: 12, TXBytes: 34, Endpoint: "203.0.113.44:54321"}}); err != nil {
		t.Fatal(err)
	}
	observed, err := repository.GetPeer(ctx, created.ID)
	if err != nil || observed.RuntimeState != "HEALTHY" || observed.RXBytes != 12 || observed.TXBytes != 34 || observed.ObservedEndpoint == "203.0.113.44:54321" || !strings.Contains(observed.ObservedEndpoint, "x.x") {
		t.Fatalf("observed peer = %+v, %v", observed, err)
	}
}

func TestBackendApplyFailureDeletesIngressInterface(t *testing.T) {
	ctx, repository, keys := ingressFixture(t)
	if _, err := repository.EnsureDefault(ctx, keys); err != nil {
		t.Fatal(err)
	}
	seedListenInterface(t, repository)
	if _, err := repository.UpdateServer(ctx, ServerUpdate{
		Enabled: true, Name: "Clients", SubnetCIDR: "10.90.0.0/24", ListenPort: 51820,
		EndpointHost: "vpn.example.org", MTU: 1420, TopologyMode: "ROUTED", DNS: []string{"1.1.1.1"},
		ListenInterfaces: []ListenInterface{{NetworkInterfaceID: "netif:listen", ExposureMode: "LOCAL", Priority: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	executor := &ingressExecutor{failSync: true}
	backend := Backend{Repository: repository, Keys: keys, Executor: executor, IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", Mutate: true}
	if err := backend.Sync(ctx); err == nil {
		t.Fatal("Backend.Sync() succeeded despite wg syncconf failure")
	}
	joined := strings.Join(executor.requests, "\n")
	if !strings.Contains(joined, "wg syncconf wg-ingress /dev/stdin") || !strings.Contains(joined, "ip link delete dev wg-ingress") {
		t.Fatalf("fail-closed operations missing:\n%s", joined)
	}
	server, err := repository.GetServer(ctx)
	if err != nil || server.State != "ERROR" || server.LastErrorCode != "WIREGUARD_INGRESS_APPLY_FAILED" || server.AppliedGeneration != 0 {
		t.Fatalf("failed runtime = %+v, %v", server, err)
	}
}

type ingressExecutor struct {
	failSync bool
	requests []string
}

func (executor *ingressExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	name := filepath.Base(request.Executable)
	executor.requests = append(executor.requests, name+" "+strings.Join(request.Arguments, " "))
	if name == "wg" && len(request.Arguments) > 0 && request.Arguments[0] == "syncconf" && executor.failSync {
		return platformexec.Result{ExitCode: 1}, os.ErrInvalid
	}
	if name == "wg" && len(request.Arguments) > 0 && request.Arguments[0] == "show" {
		return platformexec.Result{Stdout: "private\tpublic\t51820\toff\n"}, nil
	}
	return platformexec.Result{}, nil
}

func ingressFixture(t *testing.T) (context.Context, Repository, KeyStore) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "wireguard-ingress")
	repository := Repository{Database: database, SecretRoot: root, Now: func() time.Time { return time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC) }}
	return ctx, repository, KeyStore{Root: root}
}

func seedListenInterface(t *testing.T, repository Repository) {
	t.Helper()
	_, err := repository.Database.Exec(`
INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at)
VALUES('netif:listen','PERMANENT_MAC','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','enp1s0','UP','now','now');
INSERT INTO interface_role_assignments(id,network_interface_id,role,created_at,updated_at)
VALUES('role:listen','netif:listen','LAN_MEMBER','now','now')`)
	if err != nil {
		t.Fatal(err)
	}
}

func mustPublicKey(t *testing.T) string {
	t.Helper()
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pair.Public
}

func mustPSK(t *testing.T) string {
	t.Helper()
	value, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
