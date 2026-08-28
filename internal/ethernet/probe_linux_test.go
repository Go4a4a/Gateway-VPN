//go:build linux

package ethernet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSysFSProbeUsesMACOnlyWhenKernelMarksItPermanent(t *testing.T) {
	root := t.TempDir()
	makeNIC := func(name, topology, assignment string) {
		t.Helper()
		base := filepath.Join(root, "class", "net", name)
		device := filepath.Join(root, "devices", topology)
		if err := os.MkdirAll(base, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(device, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(device, filepath.Join(base, "device")); err != nil {
			t.Fatal(err)
		}
		for filename, content := range map[string]string{
			"type": "1\n", "address": "02:00:00:00:00:01\n",
			"addr_assign_type": assignment + "\n", "carrier": "1\n", "mtu": "1500\n",
		} {
			if err := os.WriteFile(filepath.Join(base, filename), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	makeNIC("ethperm", "pci0000:00/0000:00:01.0", "0")
	makeNIC("ethrandom", "pci0000:00/0000:00:02.0", "1")
	probe := SysFSProbe{
		Root: root, IdentitySalt: []byte(strings.Repeat("s", 32)),
		Addresses: func(string) ([]string, error) { return []string{"172.20.1.2/24"}, nil },
	}
	items, err := probe.List(context.Background())
	if err != nil || len(items) != 2 {
		t.Fatalf("List() = %+v, %v", items, err)
	}
	byName := map[string]Device{}
	for _, item := range items {
		byName[item.Observation.CurrentIfname] = item
	}
	permanent := byName["ethperm"].Observation
	if permanent.StableIdentityKind != "ETHERNET_PERMANENT_MAC" || permanent.PermanentMAC != "02:00:00:00:00:01" {
		t.Fatalf("permanent identity = %+v", permanent)
	}
	randomized := byName["ethrandom"].Observation
	if randomized.StableIdentityKind != "ETHERNET_TOPOLOGY" || randomized.PermanentMAC != "" || randomized.TopologyPath != "pci0000:00/0000:00:02.0" {
		t.Fatalf("randomized identity = %+v", randomized)
	}
}
