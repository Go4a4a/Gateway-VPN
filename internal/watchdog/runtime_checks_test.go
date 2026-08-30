package watchdog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	configpkg "gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

func TestWorkerRuntimeHealthSeparatesCriticalAndAdvisoryStaleness(t *testing.T) {
	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	heartbeat := ControlHeartbeat{WorkersOK: true, Workers: map[string]WorkerProgress{
		WorkerDataPlaneReconcile: {LastProgressAt: now.Add(-time.Duration(policy.WorkerStaleSeconds+1) * time.Second).Format(time.RFC3339Nano), MaximumSilenceSeconds: 30, Critical: true},
		WorkerDatabaseBackup:     {LastProgressAt: now.Add(-24 * time.Hour).Format(time.RFC3339Nano), MaximumSilenceSeconds: 3600, Critical: false},
	}}
	healthy, code, details := workerRuntimeHealth(heartbeat, nil, now, policy)
	if healthy || code != "CRITICAL_WORKER_STALE" {
		t.Fatalf("critical stale worker health = %v %s %+v", healthy, code, details)
	}
	heartbeat.Workers[WorkerDataPlaneReconcile] = WorkerProgress{LastProgressAt: now.Add(-time.Second).Format(time.RFC3339Nano), MaximumSilenceSeconds: 30, Critical: true}
	healthy, code, _ = workerRuntimeHealth(heartbeat, nil, now, policy)
	if !healthy || code != "" {
		t.Fatalf("advisory stale worker affected critical health = %v %s", healthy, code)
	}
	if healthy, code, _ = workerRuntimeHealth(ControlHeartbeat{}, errors.New("missing"), now, policy); healthy || code != "WORKER_HEARTBEAT_UNAVAILABLE" {
		t.Fatalf("missing worker heartbeat = %v %s", healthy, code)
	}
}

func TestWireGuardRuntimeParsersDoNotExposeOrLooselyMatchState(t *testing.T) {
	if !sameFwmark("0x1101", 0x1101) || sameFwmark("0x11010", 0x1101) {
		t.Fatal("WireGuard fwmark parser is not exact")
	}
	peer := "peer-public-key"
	when := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	if got := peerHandshake(peer+"\t"+strconv.FormatInt(when.Unix(), 10)+"\nother\t1\n", peer); !got.Equal(when) {
		t.Fatalf("peer handshake = %v, want %v", got, when)
	}
	if jsonRouteContains(`[{"dst":"10.80.0.0/24","dev":"wg-other","protocol":186}]`, "10.80.0.0/24", "wg-mgmt", 186, 0, "") {
		t.Fatal("WireGuard route parser accepted another interface")
	}
	// Ubuntu 24.04 iproute2 emits protocol and table as quoted decimal values
	// when -N and -json are combined. Keep accepting the unquoted fixture form
	// as well, but never coerce names or partially numeric strings.
	if !jsonRouteContains(`[{"dst":"10.80.0.0/24","dev":"wg-mgmt","protocol":"186"}]`, "10.80.0.0/24", "wg-mgmt", 186, 0, "") {
		t.Fatal("WireGuard route parser rejected Ubuntu 24.04 numeric protocol output")
	}
	if !jsonRouteContains(`[{"dst":"8.8.8.8","gateway":"192.168.8.1","dev":"enx-a","table":"1101"}]`, "8.8.8.8", "enx-a", 0, 1101, "192.168.8.1") {
		t.Fatal("WireGuard route parser rejected Ubuntu 24.04 numeric table output")
	}
	if _, ok := jsonUint32(json.RawMessage(`"1101x"`)); ok {
		t.Fatal("numeric JSON parser accepted a partially numeric string")
	}
}

type exactOutputExecutor struct {
	outputs map[string]string
	errors  map[string]error
}

func (executor *exactOutputExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	key := request.Executable + " " + strings.Join(request.Arguments, " ")
	if err := executor.errors[key]; err != nil {
		return platformexec.Result{ExitCode: 1}, err
	}
	output, exists := executor.outputs[key]
	if !exists {
		return platformexec.Result{ExitCode: 1}, errors.New("unexpected command: " + key)
	}
	return platformexec.Result{Stdout: output}, nil
}

func TestWireGuardManagementHealthDistinguishesLocalStateFromExternalHandshake(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	stamp := now.Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `INSERT INTO uplinks(
id, display_number, type, name, enabled, priority, address_mode, routing_table_id, fwmark, state, created_at, updated_at
) VALUES('uplink-a', 1, 'HILINK', 'A', 1, 10, 'DHCP', 1101, 4353, 'UPLINK_READY', ?, ?)`, stamp, stamp); err != nil {
		database.Close()
		t.Fatal(err)
	}
	state := wireguardpkg.RuntimeState{EndpointIP: "8.8.8.8", RouteInterface: "enx-a", RouteGateway: "192.168.8.1", RouteTableID: 1101, RouteFwmark: 4353}
	if err := (wireguardpkg.RuntimeStore{Database: database}).Put(ctx, state, now); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	key := func(value byte) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
	}
	configuration := wireguardpkg.Config{
		InterfaceName: "wg-mgmt", Address: "10.80.0.2/32", PrivateKey: key(1), PeerPublicKey: key(2),
		Endpoint: "8.8.8.8:51821", AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: 25,
	}
	configPath := filepath.Join(directory, "wireguard.yaml")
	if err := wireguardpkg.SaveConfig(configPath, configuration); err != nil {
		t.Fatal(err)
	}
	executor := &exactOutputExecutor{outputs: map[string]string{}}
	probe := &SystemProbe{Executor: executor, IP: "/usr/sbin/ip", WG: "/usr/bin/wg", DatabasePath: databasePath, WireGuardConfigPath: configPath, RoutingTableStart: 1101, FwmarkStart: 4353}
	executor.outputs["/usr/sbin/ip -json link show dev wg-mgmt"] = `[{"flags":["UP"]}]`
	executor.outputs["/usr/sbin/ip -json -4 address show dev wg-mgmt"] = `[{"addr_info":[{"local":"10.80.0.2","prefixlen":32}]}]`
	executor.outputs["/usr/sbin/ip -N -json -4 route show 10.80.0.0/24"] = `[{"dst":"10.80.0.0/24","dev":"wg-mgmt","protocol":186}]`
	executor.outputs["/usr/bin/wg show wg-mgmt peers"] = configuration.PeerPublicKey + "\n"
	executor.outputs["/usr/bin/wg show wg-mgmt fwmark"] = "0x1101\n"
	executor.outputs["/usr/sbin/ip -N -json -4 route get 8.8.8.8 mark 0x1101"] = `[{"dst":"8.8.8.8","gateway":"192.168.8.1","dev":"enx-a","table":1101}]`
	handshakeKey := "/usr/bin/wg show wg-mgmt latest-handshakes"
	executor.outputs[handshakeKey] = configuration.PeerPublicKey + "\t" + strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10) + "\n"

	policy := DefaultPolicy()
	observation := probe.wireGuardManagementHealth(ctx, now, policy)
	if !observation.Healthy || observation.Classification != "" || observation.ErrorCode != "" {
		t.Fatalf("healthy WireGuard observation = %+v", observation)
	}
	executor.outputs[handshakeKey] = configuration.PeerPublicKey + "\t" + strconv.FormatInt(now.Add(-time.Duration(policy.WireGuardHandshakeStaleSeconds+1)*time.Second).Unix(), 10) + "\n"
	observation = probe.wireGuardManagementHealth(ctx, now, policy)
	if observation.Healthy || observation.Classification != ClassificationExternal || observation.ErrorCode != "WG_VPS_HANDSHAKE_STALE" {
		t.Fatalf("stale external handshake observation = %+v", observation)
	}
	executor.outputs[handshakeKey] = configuration.PeerPublicKey + "\t" + strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10) + "\n"
	executor.outputs["/usr/sbin/ip -N -json -4 route show 10.80.0.0/24"] = `[{"dst":"10.80.0.0/24","dev":"wg-other","protocol":186}]`
	observation = probe.wireGuardManagementHealth(ctx, now, policy)
	if observation.Healthy || observation.Classification == ClassificationExternal || observation.ErrorCode != "WG_MANAGEMENT_ROUTE_MISSING" {
		t.Fatalf("local WireGuard route mismatch observation = %+v", observation)
	}
}

func TestManagementFabricWatchdogSeparatesConvergenceFromExternalAdminHandshake(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	databasePath := filepath.Join(t.TempDir(), "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := &managementfabric.Repository{Database: database, Now: func() time.Time { return now }}
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	vpsKeys, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	localKeys, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	vps, err := repository.CreateVPS(ctx, managementfabric.CreateVPSInput{
		ID: "vps:a", Name: "VPS A", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: vpsKeys.Public,
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem:a", Name: "Operator", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem:a", modem.LeaseInput{
		InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1",
		DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateLink(ctx, managementfabric.CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
		LocalPublicKey:           localKeys.Public, RemotePublicKey: vpsKeys.Public,
		UplinkPolicy: managementfabric.UplinkAuto, PersistentKeepalive: 25,
		Endpoints: []managementfabric.EndpointSpec{{Host: "203.0.113.10", Port: 51821}},
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := repository.BuildGatewayHostPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.MarkGatewayHostPlanApplied(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeManagementFabricRuntime{}
	executor := &exactOutputExecutor{outputs: map[string]string{
		"/usr/sbin/ip -json link show dev gvm1":       `[{"flags":["UP"]}]`,
		"/usr/sbin/ip -json -4 address show dev gvm1": `[{"addr_info":[{"local":"10.82.0.2","prefixlen":32}]}]`,
		"/usr/bin/wg show gvm1 public-key":            localKeys.Public + "\n",
		"/usr/bin/wg show gvm1 peers":                 vpsKeys.Public + "\n",
		"/usr/bin/wg show gvm1 latest-handshakes":     vpsKeys.Public + "\t" + strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10) + "\n",
	}}
	probe := &SystemProbe{Executor: executor, IP: "/usr/sbin/ip", WG: "/usr/bin/wg", DatabasePath: databasePath, ManagementFabric: runtime}

	routes := probe.managementFabricRouteHealth(ctx)
	if !routes.Applicable || !routes.Healthy || routes.ErrorCode != "" {
		t.Fatalf("healthy management fabric routes = %+v", routes)
	}
	admin := probe.wireGuardAdminHealth(ctx, now, DefaultPolicy())
	if !admin.Applicable || !admin.Healthy || admin.Classification != "" {
		t.Fatalf("healthy admin WireGuard = %+v", admin)
	}

	runtime.status = ManagementFabricStatus{NeedsApply: true, Reason: "KERNEL_STATE_DIVERGED"}
	routes = probe.managementFabricRouteHealth(ctx)
	if routes.Healthy || routes.ErrorCode != "MANAGEMENT_FABRIC_DIVERGED" {
		t.Fatalf("diverged management fabric routes = %+v", routes)
	}
	runtime.status = ManagementFabricStatus{}
	executor.outputs["/usr/bin/wg show gvm1 latest-handshakes"] = vpsKeys.Public + "\t" + strconv.FormatInt(now.Add(-time.Hour).Unix(), 10) + "\n"
	admin = probe.wireGuardAdminHealth(ctx, now, DefaultPolicy())
	if admin.Healthy || admin.Classification != ClassificationExternal || admin.ErrorCode != "WG_ADMIN_EXTERNAL_OUTAGE" {
		t.Fatalf("stale admin handshake = %+v", admin)
	}
	executor.outputs["/usr/bin/wg show gvm1 latest-handshakes"] = vpsKeys.Public + "\t" + strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10) + "\n"
	executor.outputs["/usr/bin/wg show gvm1 peers"] = "unexpected-peer\n"
	admin = probe.wireGuardAdminHealth(ctx, now, DefaultPolicy())
	if admin.Healthy || admin.Classification == ClassificationExternal || admin.ErrorCode != "WG_ADMIN_LOCAL_DRIFT" {
		t.Fatalf("local admin WireGuard drift = %+v", admin)
	}
}

func TestSSHHealthIsNotApplicableWhenOperatorDisabledIt(t *testing.T) {
	configuration := configpkg.Default()
	configuration.Network.DisableSSHManagement = true
	probe := &SystemProbe{Executor: &exactOutputExecutor{outputs: map[string]string{}}}
	observation := probe.sshManagementHealthForConfig(context.Background(), configuration)
	if observation.Applicable || !observation.Healthy || observation.ErrorCode != "" {
		t.Fatalf("disabled SSH observation = %+v", observation)
	}
	if !ipv4WildcardSSHListener("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n") || ipv4WildcardSSHListener("LISTEN 0 128 [::]:22 [::]:*\n") {
		t.Fatal("SSH listener parser did not require IPv4 wildcard")
	}
}

func TestSSHHealthRequiresEnabledValidWildcardServiceAndLANOnlyFirewall(t *testing.T) {
	configuration := configpkg.Default()
	configuration.Network.LANInterface = "gateway-vpn-lan"
	executor := &exactOutputExecutor{outputs: map[string]string{
		"/usr/bin/systemctl is-enabled --quiet ssh.service": "",
		"/usr/bin/systemctl is-active --quiet ssh.service":  "",
		"/usr/sbin/sshd -t":                               "",
		"/usr/bin/ss -H -ltn sport = :22":                 "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
		"/usr/sbin/nft list chain inet gateway_vpn input": "iifname \"gateway-vpn-lan\" tcp dport 22 accept comment \"gateway-vpn LAN SSH\"\n",
	}}
	probe := &SystemProbe{Executor: executor, Systemctl: "/usr/bin/systemctl", SSHD: "/usr/sbin/sshd", SS: "/usr/bin/ss", NFT: "/usr/sbin/nft"}
	observation := probe.sshManagementHealthForConfig(context.Background(), configuration)
	if !observation.Applicable || !observation.Healthy || observation.ErrorCode != "" {
		t.Fatalf("healthy SSH observation = %+v", observation)
	}
	executor.outputs["/usr/sbin/nft list chain inet gateway_vpn input"] = "iifname \"enx-uplink\" tcp dport 22 accept comment \"gateway-vpn LAN SSH\"\n"
	observation = probe.sshManagementHealthForConfig(context.Background(), configuration)
	if observation.Healthy || observation.ErrorCode != "SSH_FIREWALL_SCOPE_INVALID" {
		t.Fatalf("uplink-scoped SSH firewall observation = %+v", observation)
	}
}

func TestLoggingPipelineHealthRequiresConvergedJournaldAndBoundedExports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose the Unix 0640 mode required by the Linux log export contract")
	}
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	settings, err := (loggingpkg.Repository{Database: database}).Get(ctx)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	fingerprint := loggingpkg.RetentionFingerprint(settings)
	if _, err := database.ExecContext(ctx, `
UPDATE logging_runtime
SET desired_sha256=?, applied_sha256=?, state='APPLIED', applied_at='now'
WHERE singleton_id=1;
UPDATE log_export_policy
SET applied_generation=desired_generation, state='APPLIED'
WHERE singleton_id=1`, fingerprint, fingerprint); err != nil {
		database.Close()
		t.Fatal(err)
	}
	policy, err := (loggingpkg.ExportRepository{Database: database}).Get(ctx)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(directory, "gateway-vpn")
	if err := os.MkdirAll(filepath.Join(root, "current"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, category := range policy.Categories {
		filename := filepath.Join(root, "current", category+".log")
		if err := os.WriteFile(filename, []byte("safe\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		// Windows applies the process umask/ACL translation to newly created files,
		// so set the portable permission bits explicitly just like the exporter.
		if err := os.Chmod(filename, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	executor := &exactOutputExecutor{outputs: map[string]string{
		"/usr/bin/systemctl is-active --quiet systemd-journald@gateway-vpn.service": "",
	}}
	probe := &SystemProbe{Executor: executor, Systemctl: "/usr/bin/systemctl", DatabasePath: databasePath, LogExportRoot: root}
	observation := probe.loggingPipelineHealth(ctx)
	if !observation.Healthy || observation.ErrorCode != "" || observation.Details["categories"] != len(policy.Categories) {
		t.Fatalf("healthy logging pipeline = %+v", observation)
	}
	if err := os.Chmod(filepath.Join(root, "current", "all.log"), 0o666); err != nil {
		t.Fatal(err)
	}
	observation = probe.loggingPipelineHealth(ctx)
	if observation.Healthy || observation.ErrorCode != "LOG_EXPORT_FILE_INVALID" {
		t.Fatalf("unsafe log export observation = %+v", observation)
	}
}

func TestWireGuardIngressHealthRequiresExactLocalKernelContour(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at)
VALUES('netif:lan','MANAGED_VIRTUAL','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','gateway-vpn-lan','UP','now','now')`); err != nil {
		t.Fatal(err)
	}
	secretRoot := filepath.Join(directory, "secrets", "wireguard-ingress")
	repository := wgingress.Repository{Database: database, SecretRoot: secretRoot}
	keys := wgingress.KeyStore{Root: secretRoot}
	server, err := repository.EnsureDefault(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	server, err = repository.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: true, Name: "Clients", SubnetCIDR: "10.90.0.0/24", ListenPort: 51820,
		EndpointHost: "vpn.example.org", MTU: 1420, TopologyMode: "ROUTED",
		ListenInterfaces: []wgingress.ListenInterface{{NetworkInterfaceID: "netif:lan", ExposureMode: "LOCAL", Priority: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetRuntime(ctx, server.ID, "ACTIVE", "", server.DesiredGeneration); err != nil {
		t.Fatal(err)
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wgingress.GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := repository.CreatePeer(ctx, wgingress.PeerCreate{
		Name: "Phone", PeerKind: "DEVICE", KeyMode: "MANAGED", PersistentKeepalive: 25,
		AccessPolicyMode: "AUTO", ClientAllowedIPs: []string{"0.0.0.0/0"},
	}, &pair, psk, keys)
	if err != nil {
		t.Fatal(err)
	}
	server, err = repository.GetServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetRuntime(ctx, server.ID, "ACTIVE", "", server.DesiredGeneration); err != nil {
		t.Fatal(err)
	}
	executor := &exactOutputExecutor{outputs: map[string]string{
		"/usr/sbin/ip -json link show dev wg-ingress":                         `[{"flags":["UP"]}]`,
		"/usr/sbin/ip -json -4 address show dev wg-ingress":                   `[{"addr_info":[{"local":"10.90.0.1","prefixlen":24}]}]`,
		"/usr/bin/wg show wg-ingress public-key":                              server.PublicKey + "\n",
		"/usr/bin/wg show wg-ingress listen-port":                             "51820\n",
		"/usr/bin/wg show wg-ingress peers":                                   peer.PublicKey + "\n",
		"/usr/sbin/ip -N -json -4 route show dev wg-ingress protocol 186":     `[]`,
		"/usr/sbin/nft list set inet gateway_vpn wireguard_ingress_listeners": `set wireguard_ingress_listeners { type ifname . inet_service; elements = { "gateway-vpn-lan" . 51820 } }`,
	}}
	probe := &SystemProbe{Executor: executor, IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", DatabasePath: databasePath}
	observation := probe.wireGuardIngressHealth(ctx)
	if !observation.Applicable || !observation.Healthy || observation.ErrorCode != "" || observation.Details["enabled_peers"] != 1 {
		t.Fatalf("healthy ingress observation = %+v", observation)
	}
	executor.outputs["/usr/sbin/nft list set inet gateway_vpn wireguard_ingress_listeners"] = `set wireguard_ingress_listeners { type ifname . inet_service; elements = { "wrong0" . 51820 } }`
	observation = probe.wireGuardIngressHealth(ctx)
	if observation.Healthy || observation.ErrorCode != "WG_INGRESS_FIREWALL_LISTENER_MISMATCH" {
		t.Fatalf("mismatched listener observation = %+v", observation)
	}
}
