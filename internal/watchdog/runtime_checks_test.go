package watchdog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	configpkg "gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
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
