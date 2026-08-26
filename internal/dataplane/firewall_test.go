package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gateway-vpn/internal/platformexec"
)

type firewallExecutor struct {
	requests []platformexec.Request
	state    PathState
	badTable bool
	applyErr error
}

func (executor *firewallExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	arguments := strings.Join(request.Arguments, " ")
	switch arguments {
	case "list table inet gateway_vpn":
		if executor.badTable {
			return platformexec.Result{Stdout: "table inet gateway_vpn { chain forward { } }"}, nil
		}
		return platformexec.Result{Stdout: `table inet gateway_vpn {
set firewall_schema_generation { type mark; elements = { 2 }; }
set active_tun_interfaces { type ifname; }
set active_path_generation { type mark; }
counter user_upload
counter user_download
counter service_upload
counter service_download
chain forward { type filter hook forward priority filter; policy drop;
meta nfproto ipv4 iifname "enp2s0" oifname @active_tun_interfaces accept
counter comment "gateway-vpn PATH_BLOCKED" }
}`}, nil
	case "--check --file -":
		return platformexec.Result{}, nil
	case "--file -":
		if executor.applyErr != nil {
			return platformexec.Result{Stderr: "private nft detail"}, executor.applyErr
		}
		if strings.Contains(string(request.Stdin), `add element inet gateway_vpn active_tun_interfaces { "gateway-vpn-tun" }`) {
			executor.state = PathState{Active: true, Generation: parseGeneration(string(request.Stdin))}
		} else {
			executor.state = PathState{}
		}
		return platformexec.Result{}, nil
	case "--json list table inet gateway_vpn":
		return platformexec.Result{Stdout: observedJSON(executor.state)}, nil
	default:
		return platformexec.Result{}, fmt.Errorf("unexpected request %s", arguments)
	}
}

func TestFirewallBackendAtomicallyActivatesAndBlocksOnlyTUNGateSets(t *testing.T) {
	executor := &firewallExecutor{}
	backend := FirewallBackend{Executor: executor, NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun"}
	if err := backend.ActivatePath(context.Background(), 42); err != nil {
		t.Fatalf("ActivatePath() error = %v", err)
	}
	if executor.state != (PathState{Active: true, Generation: 42}) {
		t.Fatalf("active state = %+v", executor.state)
	}
	activePayload := string(executor.requests[2].Stdin)
	for _, required := range []string{
		"flush set inet gateway_vpn active_tun_interfaces",
		"flush set inet gateway_vpn active_path_generation",
		"add element inet gateway_vpn active_path_generation { 42 }",
		`add element inet gateway_vpn active_tun_interfaces { "gateway-vpn-tun" }`,
	} {
		if !strings.Contains(activePayload, required) {
			t.Errorf("active transaction missing %q: %s", required, activePayload)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "delete table", "hilink_interfaces", "policy accept"} {
		if strings.Contains(activePayload, forbidden) {
			t.Fatalf("active transaction contains forbidden %q", forbidden)
		}
	}
	if err := backend.BlockPath(context.Background()); err != nil {
		t.Fatalf("BlockPath() error = %v", err)
	}
	if executor.state.Active || executor.state.Generation != 0 {
		t.Fatalf("blocked state = %+v", executor.state)
	}
	blockPayload := string(executor.requests[6].Stdin)
	if strings.Contains(blockPayload, "add element") {
		t.Fatalf("blocked transaction opens a set: %s", blockPayload)
	}
}

func TestFirewallBackendRejectsMissingIntegrityMarkersAndRedactsNftFailure(t *testing.T) {
	executor := &firewallExecutor{badTable: true}
	backend := FirewallBackend{Executor: executor, NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun"}
	if err := backend.ActivatePath(context.Background(), 1); err == nil {
		t.Fatal("ActivatePath(incomplete table) error = nil")
	}
	executor = &firewallExecutor{applyErr: errors.New("apply failed")}
	backend.Executor = executor
	if err := backend.ActivatePath(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "private nft detail") {
		t.Fatalf("ActivatePath(apply failure) error = %v", err)
	}
}

func TestDecodePathStateRejectsHalfActiveAndWrongTUN(t *testing.T) {
	if _, err := decodePathState([]byte(observedJSON(PathState{Active: true, Generation: 9})), "wrong-tun"); err == nil {
		t.Fatal("decodePathState(wrong TUN) error = nil")
	}
	half := `{"nftables":[{"set":{"family":"inet","table":"gateway_vpn","name":"active_tun_interfaces","elem":["gateway-vpn-tun"]}},{"set":{"family":"inet","table":"gateway_vpn","name":"active_path_generation"}}]}`
	if _, err := decodePathState([]byte(half), "gateway-vpn-tun"); err == nil {
		t.Fatal("decodePathState(half active) error = nil")
	}
}

func parseGeneration(payload string) uint32 {
	var generation uint32
	_, _ = fmt.Sscanf(payload[strings.Index(payload, "active_path_generation { "):], "active_path_generation { %d", &generation)
	return generation
}

func observedJSON(state PathState) string {
	tunElements := ""
	generationElements := ""
	if state.Active {
		tunElements = `,"elem":["gateway-vpn-tun"]`
		generationElements = fmt.Sprintf(`,"elem":[%d]`, state.Generation)
	}
	return fmt.Sprintf(`{"nftables":[{"set":{"family":"inet","table":"gateway_vpn","name":"active_tun_interfaces"%s}},{"set":{"family":"inet","table":"gateway_vpn","name":"active_path_generation"%s}}]}`, tunElements, generationElements)
}
