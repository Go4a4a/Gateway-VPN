package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
)

type scriptedExecutor struct {
	requests []platformexec.Request
	results  map[string]platformexec.Result
	errors   map[string]error
}

func (executor *scriptedExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	key := request.Executable + " " + strings.Join(request.Arguments, " ")
	return executor.results[key], executor.errors[key]
}

func TestHostCollectorUsesFixedCommandsAndExcludesKeysMACAndUnownedRules(t *testing.T) {
	directory := t.TempDir()
	osRelease := filepath.Join(directory, "os-release")
	if err := os.WriteFile(osRelease, []byte("ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: map[string]platformexec.Result{}, errors: map[string]error{}}
	executor.results["/usr/bin/uname -r"] = platformexec.Result{Stdout: "6.8.0-test\n"}
	executor.results["/usr/sbin/ip -json -4 address show"] = platformexec.Result{Stdout: `[{"ifname":"enp2s0","address":"de:ad:be:ef:00:01","operstate":"UP","mtu":1500,"addr_info":[{"family":"inet","local":"192.168.200.1","prefixlen":24,"scope":"global"}]}]`}
	executor.results["/usr/sbin/ip -json -4 route show table all protocol 186"] = platformexec.Result{Stdout: `[{"dst":"default","gateway":"192.168.8.1","dev":"enxmodem","protocol":186,"table":1101}]`}
	executor.results["/usr/sbin/ip -json -4 rule show"] = platformexec.Result{Stdout: `[{"priority":100,"protocol":2,"table":254},{"priority":11101,"protocol":186,"fwmark":"0x1101","table":1101}]`}
	executor.results["/usr/sbin/nft -j list table inet gateway_vpn"] = platformexec.Result{Stdout: `{"nftables":[{"rule":{"expr":[{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.168.200.0/24"}}],"comment":"see https://example.test/private?token=topsecret"}}]}`}
	executor.results["/usr/bin/wg show wg-mgmt dump"] = platformexec.Result{Stdout: "PRIVATEKEY\tPUBLICKEY\t51821\t0x1101\nPEERPUBLIC\tPRESHARED\t203.0.113.10:51821\t10.80.0.1/32\t1724500000\t123\t456\t25\n"}
	executor.results["/opt/gateway-vpn/mihomo -v"] = platformexec.Result{Stdout: "Mihomo Meta v1.0\n"}
	now := time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC)
	collector := HostCollector{
		Executor: executor, IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg",
		Uname: "/usr/bin/uname", MihomoBinary: "/opt/gateway-vpn/mihomo", OSReleaseFile: osRelease,
		Now: func() time.Time { return now },
	}
	snapshot, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OS.ID != "ubuntu" || snapshot.Kernel != "6.8.0-test" || len(snapshot.Interfaces) != 1 || len(snapshot.SectionErrors) != 0 {
		t.Fatalf("snapshot summary = %+v", snapshot)
	}
	if !snapshot.WireGuard.Available || len(snapshot.WireGuard.Peers) != 1 || snapshot.WireGuard.Peers[0].Endpoint != "[MASKED]:51821" {
		t.Fatalf("WireGuard summary = %+v", snapshot.WireGuard)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, forbidden := range []string{"PRIVATEKEY", "PUBLICKEY", "PEERPUBLIC", "PRESHARED", "203.0.113.10", "de:ad:be:ef", "topsecret", `"protocol":2`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("host snapshot leaked %q: %s", forbidden, text)
		}
	}
	for _, expected := range []string{`"protocol":186`, `"payload"`, "https://example.test/", "Mihomo Meta v1.0"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("host snapshot missing %q: %s", expected, text)
		}
	}
	if len(payload) > MaximumHostSnapshotBytes || len(executor.requests) != 7 {
		t.Fatalf("payload/requests = %d/%d", len(payload), len(executor.requests))
	}
	for _, request := range executor.requests {
		if request.MaxOutputBytes <= 0 || !strings.HasPrefix(request.Executable, "/") {
			t.Fatalf("unbounded or non-absolute command: %+v", request)
		}
	}
}

func TestHostCollectorReportsStableSectionErrorsWithoutCommandDetails(t *testing.T) {
	directory := t.TempDir()
	osRelease := filepath.Join(directory, "os-release")
	if err := os.WriteFile(osRelease, []byte("ID=ubuntu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{results: map[string]platformexec.Result{}, errors: map[string]error{}}
	privateError := errors.New("private command output token=should-not-escape")
	for _, key := range []string{
		"/usr/bin/uname -r", "/usr/sbin/ip -json -4 address show",
		"/usr/sbin/ip -json -4 route show table all protocol 186", "/usr/sbin/ip -json -4 rule show",
		"/usr/sbin/nft -j list table inet gateway_vpn", "/usr/bin/wg show wg-mgmt dump", "/opt/gateway-vpn/mihomo -v",
	} {
		executor.errors[key] = privateError
	}
	collector := HostCollector{Executor: executor, IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", Uname: "/usr/bin/uname", MihomoBinary: "/opt/gateway-vpn/mihomo", OSReleaseFile: osRelease}
	snapshot, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(snapshot)
	if len(snapshot.SectionErrors) != 7 || strings.Contains(string(payload), "should-not-escape") || strings.Contains(string(payload), "private command") {
		t.Fatalf("section errors leaked backend detail: %s", payload)
	}
}
