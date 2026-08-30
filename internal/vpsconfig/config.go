// Package vpsconfig owns the strict, role-specific VPS Agent bootstrap config.
package vpsconfig

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"
)

const MaximumFileBytes = int64(1 << 20)

type Config struct {
	Version       int      `yaml:"version"`
	System        System   `yaml:"system"`
	Listen        []string `yaml:"listen"`
	AdminPrefixes []string `yaml:"admin_prefixes"`
	TLS           TLS      `yaml:"tls"`
}

type System struct {
	StateDirectory  string `yaml:"state_directory"`
	Database        string `yaml:"database"`
	TransactionRoot string `yaml:"transaction_root"`
}

type TLS struct {
	Certificate string `yaml:"certificate"`
	PrivateKey  string `yaml:"private_key"`
}

func Default() Config {
	return Config{
		Version: 1,
		System:  System{StateDirectory: "/var/lib/gateway-vpn-vps/agent", Database: "/var/lib/gateway-vpn-vps/agent/vps-agent.db", TransactionRoot: "/var/lib/gateway-vpn-vps-privileged/restore-transactions"},
		Listen:  []string{"127.0.0.1:9443"}, AdminPrefixes: []string{"10.84.0.0/24"},
		TLS: TLS{Certificate: "/var/lib/gateway-vpn-vps/agent/tls/cert.pem", PrivateKey: "/var/lib/gateway-vpn-vps/agent/tls/key.pem"},
	}
}

func Load(filename string) (Config, error) {
	if !absolutePath(filename) {
		return Config{}, errors.New("absolute VPS Agent config path is required")
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumFileBytes || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("VPS Agent config must be a bounded protected regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, MaximumFileBytes+1))
	decoder.KnownFields(true)
	configuration := Default()
	if err := decoder.Decode(&configuration); err != nil {
		return Config{}, fmt.Errorf("decode VPS Agent config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("VPS Agent config must contain exactly one document")
	}
	if err := configuration.Validate(); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func (configuration Config) Validate() error {
	if configuration.Version != 1 || !absolutePath(configuration.System.StateDirectory) || !absolutePath(configuration.System.Database) || !absolutePath(configuration.System.TransactionRoot) || !absolutePath(configuration.TLS.Certificate) || !absolutePath(configuration.TLS.PrivateKey) {
		return errors.New("VPS Agent config paths and version are invalid")
	}
	for _, path := range []string{configuration.System.Database, configuration.TLS.Certificate, configuration.TLS.PrivateKey} {
		if !containedPath(configuration.System.StateDirectory, path) {
			return errors.New("VPS Agent database and TLS files must stay inside its state directory")
		}
	}
	if len(configuration.AdminPrefixes) == 0 || len(configuration.AdminPrefixes) > 32 || len(configuration.Listen) == 0 || len(configuration.Listen) > 8 {
		return errors.New("VPS Agent requires bounded admin prefixes and listen addresses")
	}
	prefixes := make([]netip.Prefix, 0, len(configuration.AdminPrefixes))
	seenPrefixes := map[string]struct{}{}
	for _, raw := range configuration.AdminPrefixes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 16 || prefix.Bits() > 30 {
			return errors.New("VPS Agent admin prefixes must be canonical private IPv4 /16../30")
		}
		if _, exists := seenPrefixes[prefix.String()]; exists {
			return errors.New("VPS Agent admin prefix is duplicated")
		}
		seenPrefixes[prefix.String()] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	seenListeners := map[string]struct{}{}
	for _, raw := range configuration.Listen {
		endpoint, err := netip.ParseAddrPort(strings.TrimSpace(raw))
		if err != nil || !endpoint.Addr().Is4() || endpoint.Addr().IsUnspecified() || endpoint.Port() < 1024 {
			return errors.New("VPS Agent listener must be a fixed unprivileged IPv4 address")
		}
		allowed := endpoint.Addr().IsLoopback()
		for _, prefix := range prefixes {
			allowed = allowed || prefix.Contains(endpoint.Addr())
		}
		if !allowed {
			return errors.New("VPS Agent listener must be localhost or inside an explicit admin prefix")
		}
		if _, exists := seenListeners[endpoint.String()]; exists {
			return errors.New("VPS Agent listener is duplicated")
		}
		seenListeners[endpoint.String()] = struct{}{}
	}
	return nil
}

func absolutePath(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(value, "/")
}

func containedPath(root, target string) bool {
	if strings.HasPrefix(root, "/") && strings.HasPrefix(target, "/") {
		cleanRoot, cleanTarget := pathpkg.Clean(root), pathpkg.Clean(target)
		return cleanTarget != cleanRoot && strings.HasPrefix(cleanTarget, cleanRoot+"/")
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, "../") && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
