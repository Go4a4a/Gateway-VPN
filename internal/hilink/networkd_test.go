package hilink

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkdLeaseReaderUsesIfindexAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	sysRoot, runRoot := filepath.Join(root, "sys"), filepath.Join(root, "run")
	interfaceDirectory := filepath.Join(sysRoot, "class", "net", "enxone")
	leaseDirectory := filepath.Join(runRoot, "systemd", "netif", "leases")
	if err := os.MkdirAll(interfaceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(leaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interfaceDirectory, "ifindex"), []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interfaceDirectory, "mtu"), []byte("1500\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(leaseDirectory, "42")
	if err := os.WriteFile(leasePath, []byte("ADDRESS=192.168.8.2\nPREFIXLEN=24\nROUTER=192.168.8.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := NetworkdLeaseReader{SysRoot: sysRoot, RunRoot: runRoot}
	lease, err := reader.Lease(context.Background(), "enxone")
	if err != nil || lease.Gateway.String() != "192.168.8.1" {
		t.Fatalf("Lease() = %+v, %v", lease, err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(leasePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, leasePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := reader.Lease(context.Background(), "enxone"); err == nil {
		t.Fatal("Lease(symlink) error = nil")
	}
}
