//go:build linux

package hilink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SysFSProbe struct {
	Root string
}

func HostProbe() Probe { return SysFSProbe{} }

func (probe SysFSProbe) ListUSBNetworkDevices(ctx context.Context) ([]RawDevice, error) {
	root := probe.Root
	if root == "" {
		root = "/sys"
	}
	entries, err := os.ReadDir(filepath.Join(root, "class", "net"))
	if err != nil {
		return nil, fmt.Errorf("read sysfs network interfaces: %w", err)
	}
	var result []RawDevice
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		devicePath, err := filepath.EvalSymlinks(filepath.Join(root, "class", "net", name, "device"))
		if err != nil {
			continue
		}
		vendor, product, serial, topology, ok := findUSBMetadata(root, devicePath)
		if !ok {
			continue
		}
		driver := ""
		if resolved, err := filepath.EvalSymlinks(filepath.Join(devicePath, "driver")); err == nil {
			driver = filepath.Base(resolved)
		}
		carrier := strings.TrimSpace(readOptional(filepath.Join(root, "class", "net", name, "carrier"))) == "1"
		result = append(result, RawDevice{InterfaceName: name, VendorID: vendor, ProductID: product, USBSerial: serial, PermanentMAC: readOptional(filepath.Join(root, "class", "net", name, "address")), USBTopology: topology, Driver: driver, Carrier: carrier})
	}
	return result, nil
}

func findUSBMetadata(root, start string) (vendor, product, serial, topology string, ok bool) {
	root, _ = filepath.Abs(root)
	current, _ := filepath.Abs(start)
	for strings.HasPrefix(current, root) && current != root {
		vendor = strings.TrimSpace(readOptional(filepath.Join(current, "idVendor")))
		product = strings.TrimSpace(readOptional(filepath.Join(current, "idProduct")))
		if vendor != "" && product != "" {
			serial = strings.TrimSpace(readOptional(filepath.Join(current, "serial")))
			relative, err := filepath.Rel(filepath.Join(root, "devices"), current)
			if err == nil && !strings.HasPrefix(relative, "..") {
				topology = filepath.ToSlash(relative)
			}
			return vendor, product, serial, topology, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", "", "", "", false
}

func readOptional(filename string) string {
	content, err := os.ReadFile(filename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ""
	}
	return string(content)
}
