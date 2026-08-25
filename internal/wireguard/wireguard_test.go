package wireguard

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
)

func testKey(seed byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{seed}), 32)))
}

func TestConfigAndUplinkSwitchAreManagementScopedAndOrdered(t *testing.T) {
	configuration := Config{InterfaceName: "wg-mgmt", Address: "10.80.0.2/32", PrivateKey: testKey('a'), PeerPublicKey: testKey('b'), Endpoint: "203.0.113.10:51821", AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: 25}
	content, err := RenderSyncConf(configuration)
	if err != nil || !strings.Contains(string(content), "AllowedIPs = 10.80.0.0/24") || strings.Contains(string(content), "192.168.") {
		t.Fatalf("RenderSyncConf() = %s, %v", content, err)
	}
	previous := modem.Modem{ID: "m1", InterfaceName: "enxm1", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101}
	next := modem.Modem{ID: "m2", InterfaceName: "enxm2", Gateway: "192.168.9.1", RoutingTableID: 1102, Fwmark: 0x1102}
	operations, err := RenderUplinkSwitch("wg-mgmt", netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.10"), &previous, next, "/usr/sbin/ip", "/usr/bin/wg")
	if err != nil || len(operations) != 3 {
		t.Fatalf("RenderUplinkSwitch() = %+v, %v", operations, err)
	}
	if !strings.Contains(strings.Join(operations[0].Request.Arguments, " "), "table 1102") || !strings.Contains(strings.Join(operations[1].Request.Arguments, " "), "fwmark 0x1102") || !strings.Contains(strings.Join(operations[2].Request.Arguments, " "), "table 1101") {
		t.Fatalf("switch operation order = %+v", operations)
	}
	executor := &wgFakeExecutor{}
	controller := Controller{Executor: executor, IPExecutable: "/usr/sbin/ip", WGExecutable: "/usr/bin/wg"}
	if err := controller.Apply(context.Background(), operations); err != nil || len(executor.requests) != 0 {
		t.Fatalf("dry Apply() requests/error = %d/%v", len(executor.requests), err)
	}
}

func TestUplinkSwitchRemovesOldEndpointWhenIPChangesOnSameModem(t *testing.T) {
	current := modem.Modem{ID: "m1", InterfaceName: "enxm1", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101}
	operations, err := RenderUplinkSwitch("wg-mgmt", netip.MustParseAddr("203.0.113.20"), netip.MustParseAddr("203.0.113.10"), &current, current, "/usr/sbin/ip", "/usr/bin/wg")
	if err != nil || len(operations) != 3 {
		t.Fatalf("RenderUplinkSwitch(endpoint change) = %+v, %v", operations, err)
	}
	if arguments := strings.Join(operations[2].Request.Arguments, " "); !strings.Contains(arguments, "route del 203.0.113.10/32") {
		t.Fatalf("old endpoint route was not removed: %s", arguments)
	}
}

func TestManagementSelectorHonorsReachabilityAndFailbackHysteresis(t *testing.T) {
	now := time.Now().UTC()
	candidates := []modem.Modem{
		{ID: "preferred", DisplayNumber: 1, Priority: 10, Enabled: true, State: modem.StateReady, ManagementReachabilityState: "REACHABLE", StableSince: now.Add(-2 * time.Minute).Format(time.RFC3339Nano)},
		{ID: "current", DisplayNumber: 2, Priority: 20, Enabled: true, State: modem.StateReady, ManagementReachabilityState: "REACHABLE", StableSince: now.Add(-time.Hour).Format(time.RFC3339Nano)},
	}
	policy := SelectionPolicy{ReconnectStable: 3 * time.Minute, FailbackCooldown: 15 * time.Minute}
	selection := SelectManagementModem(candidates, "current", now.Add(-time.Hour), now, policy)
	if selection.Modem.ID != "current" || selection.Changed {
		t.Fatalf("unstable failback selection = %+v", selection)
	}
	candidates[0].StableSince = now.Add(-10 * time.Minute).Format(time.RFC3339Nano)
	selection = SelectManagementModem(candidates, "current", now.Add(-time.Hour), now, policy)
	if selection.Modem.ID != "preferred" || !selection.Changed {
		t.Fatalf("stable failback selection = %+v", selection)
	}
}

type wgFakeExecutor struct{ requests []platformexec.Request }

func (executor *wgFakeExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return platformexec.Result{}, nil
}
