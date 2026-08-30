package vpsops_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/vpsops"
)

type fixtureExecutor struct{}

func (fixtureExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	switch filepath.Base(request.Executable) {
	case "systemctl":
		return platformexec.Result{Stdout: "Id=gateway-vpn-vps-agent.service\nLoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=1\n\nId=wg-quick@wg-mgmt.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nNRestarts=0\n"}, nil
	case "journalctl":
		return platformexec.Result{Stdout: `{"__CURSOR":"s=cursor-1","__REALTIME_TIMESTAMP":"1788120000000000","PRIORITY":"4","_SYSTEMD_UNIT":"gateway-vpn-vps-agent.service","MESSAGE":"refresh https://user:pass@example.test/private?token=secret authorization=Bearer-abcdef"}` + "\n"}, nil
	case "uname":
		return platformexec.Result{Stdout: "6.8.0-test\n"}, nil
	case "ip":
		if strings.Contains(strings.Join(request.Arguments, " "), "address") {
			return platformexec.Result{Stdout: `[{"ifname":"wg-mgmt","operstate":"UP","addr_info":[{"family":"inet","local":"10.80.0.1","prefixlen":24}]}]`}, nil
		}
		return platformexec.Result{Stdout: `[{"dst":"10.96.0.2","dev":"wg-mgmt","protocol":186}]`}, nil
	case "nft":
		return platformexec.Result{Stdout: `{"nftables":[{"table":{"family":"inet","name":"gateway_vpn_vps"}}]}`}, nil
	case "wg":
		return platformexec.Result{Stdout: "PRIVATE-KEY\tPUBLIC-KEY\t51821\toff\nPEER-KEY\tPSK\t203.0.113.5:1234\t10.82.0.2/32\t1788120000\t10\t20\t25\n"}, nil
	default:
		return platformexec.Result{}, nil
	}
}

func TestCollectorWritesBoundedSanitizedDisplayOnlySnapshot(t *testing.T) {
	root := t.TempDir()
	operations := filepath.Join(root, "operations")
	if err := os.Mkdir(operations, 0o750); err != nil {
		t.Fatal(err)
	}
	fabric := filepath.Join(root, "fabric-watchdog.json")
	if err := os.WriteFile(fabric, []byte(`{"state":"HEALTHY","private_key":"must-not-leak"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	paths := vpsops.Paths{Output: filepath.Join(operations, "snapshot.json"), FabricStatus: fabric, Journalctl: filepath.Join(root, "journalctl"), Systemctl: filepath.Join(root, "systemctl"), IP: filepath.Join(root, "ip"), NFT: filepath.Join(root, "nft"), WG: filepath.Join(root, "wg"), Uname: filepath.Join(root, "uname")}
	collector := vpsops.Collector{Executor: fixtureExecutor{}, Paths: paths, AgentGID: 1000, Now: func() time.Time { return time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC) }}
	snapshot, err := collector.CollectAndWrite(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != "HEALTHY" || snapshot.Host.WireGuard.Peers != 1 || snapshot.Host.WireGuard.RXBytes != 10 || len(snapshot.Entries) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	content, err := os.ReadFile(paths.Output)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PRIVATE-KEY", "PEER-KEY", "PSK", "user:pass", "token=secret", "must-not-leak", "Bearer-abcdef"} {
		if strings.Contains(string(content), forbidden) {
			t.Fatalf("snapshot leaked %q: %s", forbidden, content)
		}
	}
	if !strings.Contains(string(content), `"private_key": "[REDACTED]"`) {
		t.Fatalf("structured secret was not redacted: %s", content)
	}
	loaded, err := (vpsops.Store{Path: paths.Output}).Read()
	if err != nil || loaded.CollectedAt != snapshot.CollectedAt {
		t.Fatalf("read snapshot: %+v %v", loaded, err)
	}
}

func TestSnapshotRejectsTamperingAndUnsafeQueryCategory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operations")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "snapshot.json")
	payload, _ := json.Marshal(vpsops.Snapshot{SchemaVersion: 999, CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), State: "HEALTHY"})
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := (vpsops.Store{Path: path}).Read(); err == nil {
		t.Fatal("tampered snapshot was accepted")
	}
	if vpsops.ValidCategory("../../journal") {
		t.Fatal("unsafe category was accepted")
	}
}
