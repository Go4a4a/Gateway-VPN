package hilink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type NetworkdLeaseReader struct {
	SysRoot string
	RunRoot string
}

func (reader NetworkdLeaseReader) Lease(ctx context.Context, interfaceName string) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	if !validInterfaceName(interfaceName) {
		return Lease{}, errors.New("invalid interface name for networkd lease")
	}
	sysRoot, runRoot := reader.SysRoot, reader.RunRoot
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	if runRoot == "" {
		runRoot = "/run"
	}
	ifindex, err := readSmallInteger(filepath.Join(sysRoot, "class", "net", interfaceName, "ifindex"), 1, 1<<31-1)
	if err != nil {
		return Lease{}, fmt.Errorf("read interface index: %w", err)
	}
	mtu, err := readSmallInteger(filepath.Join(sysRoot, "class", "net", interfaceName, "mtu"), 576, 9000)
	if err != nil {
		return Lease{}, fmt.Errorf("read interface MTU: %w", err)
	}
	leasePath := filepath.Join(runRoot, "systemd", "netif", "leases", strconv.Itoa(ifindex))
	info, err := os.Lstat(leasePath)
	if err != nil {
		return Lease{}, fmt.Errorf("inspect networkd lease: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return Lease{}, errors.New("networkd lease must be a small regular non-symlink file")
	}
	content, err := os.ReadFile(leasePath)
	if err != nil {
		return Lease{}, fmt.Errorf("read networkd lease: %w", err)
	}
	return ParseNetworkdLease(content, interfaceName, mtu)
}

func readSmallInteger(filename string, minimum, maximum int) (int, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	if len(content) > 32 {
		return 0, errors.New("integer sysfs file is oversized")
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || value < minimum || value > maximum {
		return 0, errors.New("integer sysfs value is out of range")
	}
	return value, nil
}
