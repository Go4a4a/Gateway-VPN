// Package wireguard owns the management-plane WireGuard configuration and
// uplink switching plan.
package wireguard

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	InterfaceName       string   `yaml:"interface_name"`
	Address             string   `yaml:"address"`
	PrivateKey          string   `yaml:"private_key"`
	PeerPublicKey       string   `yaml:"peer_public_key"`
	Endpoint            string   `yaml:"endpoint"`
	AllowedIPs          []string `yaml:"allowed_ips"`
	PersistentKeepalive int      `yaml:"persistent_keepalive"`
	HandshakeTimeout    int      `yaml:"handshake_timeout_seconds"`
}

func ValidateConfig(config Config) error {
	return validateConfig(config)
}

func ValidEndpointHostname(value string) bool {
	return validHostname(value)
}

func LoadConfig(filename string) (Config, error) {
	if !filepath.IsAbs(filename) {
		return Config{}, errors.New("absolute WireGuard config path is required")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return Config{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16*1024 {
		return Config{}, errors.New("WireGuard config must be a bounded regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Config{}, errors.New("WireGuard config permissions are too broad")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("decode strict WireGuard config failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("WireGuard config must contain one YAML document")
	}
	if err := validateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

// SaveConfig atomically replaces the protected desired management-tunnel
// configuration. It never follows a destination symlink and leaves no
// partially written file for the privileged reconciler to consume.
func SaveConfig(filename string, config Config) error {
	if !filepath.IsAbs(filename) {
		return errors.New("absolute WireGuard config path is required")
	}
	if err := validateConfig(config); err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("WireGuard config directory must be an existing non-symlink directory")
	}
	content, err := yaml.Marshal(config)
	if err != nil || len(content) == 0 || len(content) > 16*1024 {
		return errors.New("encode WireGuard config failed")
	}
	temporary, err := os.CreateTemp(directory, ".wireguard-*.tmp")
	if err != nil {
		return errors.New("create temporary WireGuard config failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("protect temporary WireGuard config failed")
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write temporary WireGuard config failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync temporary WireGuard config failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close temporary WireGuard config failed")
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return errors.New("activate WireGuard config failed")
	}
	if runtime.GOOS != "windows" {
		directoryHandle, err := os.Open(directory)
		if err != nil {
			return errors.New("open WireGuard config directory for sync failed")
		}
		defer directoryHandle.Close()
		if err := directoryHandle.Sync(); err != nil {
			return errors.New("sync WireGuard config directory failed")
		}
	}
	return nil
}

func RenderSyncConf(config Config) ([]byte, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = ")
	builder.WriteString(config.PrivateKey)
	builder.WriteString("\n\n[Peer]\nPublicKey = ")
	builder.WriteString(config.PeerPublicKey)
	builder.WriteString("\nEndpoint = ")
	builder.WriteString(config.Endpoint)
	builder.WriteString("\nAllowedIPs = ")
	builder.WriteString(strings.Join(config.AllowedIPs, ", "))
	builder.WriteString("\nPersistentKeepalive = ")
	builder.WriteString(strconv.Itoa(config.PersistentKeepalive))
	builder.WriteByte('\n')
	return []byte(builder.String()), nil
}

func validateConfig(config Config) error {
	if !validInterfaceName(config.InterfaceName) {
		return errors.New("invalid WireGuard interface name")
	}
	if config.InterfaceName != "wg-mgmt" {
		return errors.New("WireGuard interface must be wg-mgmt in MVP")
	}
	address, err := netip.ParsePrefix(config.Address)
	if err != nil || !address.Addr().Is4() || address.Bits() != 32 || address.Addr().String() != "10.80.0.2" {
		return errors.New("Gateway WireGuard address must be 10.80.0.2/32 in MVP")
	}
	if !validKey(config.PrivateKey) || !validKey(config.PeerPublicKey) || config.PrivateKey == config.PeerPublicKey {
		return errors.New("WireGuard private and peer public keys must be distinct 32-byte base64 values")
	}
	host, port, err := net.SplitHostPort(config.Endpoint)
	if err != nil || host == "" {
		return errors.New("WireGuard endpoint must use host:port")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return errors.New("WireGuard endpoint port is invalid")
	}
	if parsedPort != 51821 {
		return errors.New("WireGuard endpoint port must be 51821 in MVP")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return errors.New("WireGuard endpoint IP must be public global unicast")
		}
	} else if !validHostname(host) {
		return errors.New("WireGuard endpoint hostname is invalid")
	}
	if len(config.AllowedIPs) != 1 || config.AllowedIPs[0] != "10.80.0.0/24" {
		return errors.New("Gateway WireGuard AllowedIPs must be exactly 10.80.0.0/24 in MVP")
	}
	if config.PersistentKeepalive < 10 || config.PersistentKeepalive > 60 {
		return errors.New("WireGuard keepalive must be 10..60 seconds")
	}
	if config.HandshakeTimeout != 0 && (config.HandshakeTimeout < 30 || config.HandshakeTimeout > 180) {
		return errors.New("WireGuard handshake timeout must be 30..180 seconds")
	}
	return nil
}

func HandshakeTimeout(config Config) time.Duration {
	if config.HandshakeTimeout == 0 {
		return 45 * time.Second
	}
	return time.Duration(config.HandshakeTimeout) * time.Second
}

func validKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validHostname(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".local") || strings.HasSuffix(value, ".internal") || strings.HasSuffix(value, ".lan") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:-", char) {
			continue
		}
		return false
	}
	return true
}

func PublicEndpointIP(endpoint string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, err
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsGlobalUnicast() || address.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("endpoint %q is not a public literal IP", endpoint)
	}
	return address, nil
}
