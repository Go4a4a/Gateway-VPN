package networkapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/platformexec"

	"go.yaml.in/yaml/v3"
)

type UbuntuPaths struct {
	ConfigFile     string
	DNSMasqFile    string
	BootNFTFile    string
	LANNetworkFile string
	IP             string
	NFT            string
	DNSMasq        string
	Systemctl      string
	Networkctl     string
	ConfigGID      int
}

func DefaultUbuntuPaths() UbuntuPaths {
	return UbuntuPaths{
		ConfigFile:     "/etc/gateway-vpn/config.yaml",
		DNSMasqFile:    "/etc/gateway-vpn/dnsmasq.conf",
		BootNFTFile:    "/etc/gateway-vpn/nftables/boot.nft",
		LANNetworkFile: "/etc/systemd/network/70-gateway-vpn-lan.network",
		IP:             "/usr/sbin/ip", NFT: "/usr/sbin/nft", DNSMasq: "/usr/sbin/dnsmasq",
		Systemctl: "/usr/bin/systemctl", Networkctl: "/usr/bin/networkctl", ConfigGID: -1,
	}
}

type UbuntuBackend struct {
	Executor platformexec.Executor
	Paths    UbuntuPaths
}

func (backend UbuntuBackend) Snapshot(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validate(); err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	if err := backend.verifyAddress(ctx, manifest.InterfaceName, manifest.OldLANCIDR, true); err != nil {
		return fmt.Errorf("verify current LAN address: %w", err)
	}
	if err := backend.verifyNoHostOverlap(ctx, manifest); err != nil {
		return err
	}
	configuration, err := config.Load(backend.Paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("load current Gateway VPN config: %w", err)
	}
	if configuration.Network.LANInterface != manifest.InterfaceName || configuration.Network.LANAddress != manifest.OldLANCIDR {
		return errors.New("current Gateway VPN config does not match the old LAN manifest")
	}
	snapshotDirectory, candidateDirectory, err := prepareBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	currentConfig, err := readBoundedRegular(backend.Paths.ConfigFile, 1<<20)
	if err != nil {
		return fmt.Errorf("snapshot Gateway VPN config: %w", err)
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "config.yaml"), currentConfig, 0o600); err != nil {
		return err
	}
	currentBootNFT, err := readBoundedRegular(backend.Paths.BootNFTFile, 1<<20)
	if err != nil {
		return fmt.Errorf("snapshot persistent firewall config: %w", err)
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "boot.nft"), currentBootNFT, 0o600); err != nil {
		return err
	}
	currentLANNetwork, err := readBoundedRegular(backend.Paths.LANNetworkFile, 1<<20)
	if err != nil {
		return fmt.Errorf("snapshot persistent LAN networkd config: %w", err)
	}
	expectedLANNetwork, err := renderLANNetwork(manifest.InterfaceName, manifest.OldLANCIDR)
	if err != nil || string(currentLANNetwork) != expectedLANNetwork {
		return errors.New("persistent LAN networkd config does not match the current safe-apply manifest")
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "lan.network"), currentLANNetwork, 0o600); err != nil {
		return err
	}
	runtimeFirewall, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.NFT, Arguments: []string{"list", "table", "inet", firewall.TableName}})
	if err != nil || !strings.Contains(runtimeFirewall.Stdout, "table inet "+firewall.TableName) {
		return errors.New("snapshot owned runtime firewall failed")
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "runtime-firewall.nft"), []byte(runtimeFirewall.Stdout), 0o600); err != nil {
		return err
	}
	dnsmasqExists, dnsmasqContent, err := readOptionalRegular(backend.Paths.DNSMasqFile, 1<<20)
	if err != nil {
		return err
	}
	if dnsmasqExists {
		if err := atomicWrite(filepath.Join(snapshotDirectory, "dnsmasq.conf"), dnsmasqContent, 0o600); err != nil {
			return err
		}
	}

	candidateConfig, apiPort, err := renderCandidateConfig(configuration, manifest)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(candidateDirectory, "config.yaml"), candidateConfig, 0o600); err != nil {
		return err
	}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: manifest.InterfaceName, TUNInterface: configuration.Mihomo.TunName,
		WireGuardInterface: "wg-mgmt", APIPort: apiPort, WireGuardListenPort: 51821,
	})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(candidateDirectory, "boot.nft"), []byte(ruleset.Text), 0o600); err != nil {
		return err
	}
	candidateLANNetwork, err := renderLANNetwork(manifest.InterfaceName, manifest.NewLANCIDR)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(candidateDirectory, "lan.network"), []byte(candidateLANNetwork), 0o600); err != nil {
		return err
	}
	if dnsmasqExists {
		dnsmasq, err := renderDNSMasq(manifest.InterfaceName, manifest.NewLANCIDR)
		if err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(candidateDirectory, "dnsmasq.conf"), []byte(dnsmasq), 0o600); err != nil {
			return err
		}
	}
	return syncDirectory(transactionDirectory)
}

func (backend UbuntuBackend) Apply(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validate(); err != nil {
		return err
	}
	_, candidateDirectory, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	configuration, err := config.Load(filepath.Join(candidateDirectory, "config.yaml"))
	if err != nil || configuration.Network.LANAddress != manifest.NewLANCIDR || configuration.Network.LANInterface != manifest.InterfaceName {
		return errors.New("candidate Gateway VPN config is invalid")
	}
	ruleset, err := loadRuleset(filepath.Join(candidateDirectory, "boot.nft"))
	if err != nil {
		return err
	}
	if err := firewall.ValidateAndLoad(ctx, backend.Executor, ruleset, firewall.LoadOptions{NFTExecutable: backend.Paths.NFT, Mutate: false}); err != nil {
		return err
	}
	if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.NFT, Arguments: []string{"--check", "--file", filepath.Join(candidateDirectory, "boot.nft")}}); err != nil {
		return errors.New("candidate firewall validation failed")
	}
	dnsmasqCandidate := filepath.Join(candidateDirectory, "dnsmasq.conf")
	if exists, _, err := readOptionalRegular(dnsmasqCandidate, 1<<20); err != nil {
		return err
	} else if exists {
		if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.DNSMasq, Arguments: []string{"--test", "--conf-file=" + dnsmasqCandidate}}); err != nil {
			return errors.New("candidate dnsmasq config validation failed")
		}
	}
	if err := backend.verifyAddress(ctx, manifest.InterfaceName, manifest.OldLANCIDR, true); err != nil {
		return err
	}
	if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "replace", manifest.NewLANCIDR, "dev", manifest.InterfaceName}}); err != nil {
		return errors.New("add candidate LAN address failed")
	}
	if err := installRegular(filepath.Join(candidateDirectory, "lan.network"), backend.Paths.LANNetworkFile, 0o644, -1); err != nil {
		return err
	}
	if err := backend.networkctlReload(ctx); err != nil {
		return err
	}
	if err := installRegular(filepath.Join(candidateDirectory, "config.yaml"), backend.Paths.ConfigFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	if err := installRegular(filepath.Join(candidateDirectory, "boot.nft"), backend.Paths.BootNFTFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	if err := firewall.ValidateAndLoad(ctx, backend.Executor, ruleset, firewall.LoadOptions{NFTExecutable: backend.Paths.NFT, Mutate: true}); err != nil {
		return err
	}
	if exists, _, _ := readOptionalRegular(dnsmasqCandidate, 1<<20); exists {
		if err := installRegular(dnsmasqCandidate, backend.Paths.DNSMasqFile, 0o640, backend.Paths.ConfigGID); err != nil {
			return err
		}
		if err := backend.systemctl(ctx, "try-restart", "gateway-vpn-dnsmasq.service"); err != nil {
			return err
		}
	}
	return backend.systemctl(ctx, "restart", "gateway-vpn.service")
}

func (backend UbuntuBackend) Commit(ctx context.Context, manifest Manifest, _ string) error {
	if err := backend.validate(); err != nil {
		return err
	}
	if err := backend.verifyAddress(ctx, manifest.InterfaceName, manifest.NewLANCIDR, true); err != nil {
		return errors.New("new LAN address disappeared before confirmation commit")
	}
	present, err := backend.addressPresent(ctx, manifest.InterfaceName, manifest.OldLANCIDR)
	if err != nil {
		return err
	}
	if present {
		if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "del", manifest.OldLANCIDR, "dev", manifest.InterfaceName}}); err != nil {
			return errors.New("remove old LAN address failed")
		}
	}
	return nil
}

func (backend UbuntuBackend) Rollback(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validate(); err != nil {
		return err
	}
	snapshotDirectory, _, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	configuration, err := config.Load(filepath.Join(snapshotDirectory, "config.yaml"))
	if err != nil || configuration.Network.LANAddress != manifest.OldLANCIDR || configuration.Network.LANInterface != manifest.InterfaceName {
		return errors.New("snapshot Gateway VPN config is invalid")
	}
	runtimeRuleset, err := loadRuleset(filepath.Join(snapshotDirectory, "runtime-firewall.nft"))
	if err != nil {
		return err
	}
	if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "replace", manifest.OldLANCIDR, "dev", manifest.InterfaceName}}); err != nil {
		return errors.New("restore old LAN address failed")
	}
	if err := installRegular(filepath.Join(snapshotDirectory, "lan.network"), backend.Paths.LANNetworkFile, 0o644, -1); err != nil {
		return err
	}
	if err := backend.networkctlReload(ctx); err != nil {
		return err
	}
	if err := installRegular(filepath.Join(snapshotDirectory, "config.yaml"), backend.Paths.ConfigFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	if err := installRegular(filepath.Join(snapshotDirectory, "boot.nft"), backend.Paths.BootNFTFile, 0o640, backend.Paths.ConfigGID); err != nil {
		return err
	}
	if err := firewall.ValidateAndLoad(ctx, backend.Executor, runtimeRuleset, firewall.LoadOptions{NFTExecutable: backend.Paths.NFT, Mutate: true}); err != nil {
		return err
	}
	snapshotDNSMasq := filepath.Join(snapshotDirectory, "dnsmasq.conf")
	if exists, _, err := readOptionalRegular(snapshotDNSMasq, 1<<20); err != nil {
		return err
	} else if exists {
		if err := installRegular(snapshotDNSMasq, backend.Paths.DNSMasqFile, 0o640, backend.Paths.ConfigGID); err != nil {
			return err
		}
		if err := backend.systemctl(ctx, "try-restart", "gateway-vpn-dnsmasq.service"); err != nil {
			return err
		}
	}
	if err := backend.systemctl(ctx, "restart", "gateway-vpn.service"); err != nil {
		return err
	}
	present, err := backend.addressPresent(ctx, manifest.InterfaceName, manifest.NewLANCIDR)
	if err != nil {
		return err
	}
	if present {
		if _, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"address", "del", manifest.NewLANCIDR, "dev", manifest.InterfaceName}}); err != nil {
			return errors.New("remove candidate LAN address failed")
		}
	}
	return nil
}

func (backend UbuntuBackend) validate() error {
	if backend.Executor == nil {
		return errors.New("Ubuntu network backend executor is required")
	}
	for _, path := range []string{backend.Paths.ConfigFile, backend.Paths.DNSMasqFile, backend.Paths.BootNFTFile, backend.Paths.LANNetworkFile, backend.Paths.IP, backend.Paths.NFT, backend.Paths.DNSMasq, backend.Paths.Systemctl, backend.Paths.Networkctl} {
		if !filepath.IsAbs(path) {
			return errors.New("Ubuntu network backend paths must be absolute")
		}
	}
	return nil
}

func (backend UbuntuBackend) networkctlReload(ctx context.Context) error {
	_, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.Networkctl, Arguments: []string{"reload"}})
	if err != nil {
		return errors.New("reload persistent systemd-networkd policy")
	}
	return nil
}

func (backend UbuntuBackend) systemctl(ctx context.Context, action, unit string) error {
	if action != "restart" && action != "try-restart" {
		return errors.New("unsupported systemctl action")
	}
	if unit != "gateway-vpn.service" && unit != "gateway-vpn-dnsmasq.service" {
		return errors.New("unsupported systemctl unit")
	}
	_, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.Systemctl, Arguments: []string{"--no-block", action, unit}})
	if err != nil {
		return fmt.Errorf("request controlled service restart: %w", err)
	}
	return nil
}

func (backend UbuntuBackend) verifyAddress(ctx context.Context, interfaceName, cidr string, required bool) error {
	present, err := backend.addressPresent(ctx, interfaceName, cidr)
	if err != nil {
		return err
	}
	if present != required {
		return errors.New("LAN address observation does not match expected state")
	}
	return nil
}

func (backend UbuntuBackend) addressPresent(ctx context.Context, interfaceName, cidr string) (bool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !validInterfaceName(interfaceName) {
		return false, errors.New("invalid address observation request")
	}
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"-json", "address", "show", "dev", interfaceName}})
	if err != nil || len(result.Stdout) > 1<<20 {
		return false, errors.New("observe LAN interface addresses failed")
	}
	var links []struct {
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &links); err != nil {
		return false, errors.New("decode LAN interface addresses failed")
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			if address.Family == "inet" && address.Local == prefix.Addr().String() && address.PrefixLen == prefix.Bits() {
				return true, nil
			}
		}
	}
	return false, nil
}

func (backend UbuntuBackend) verifyNoHostOverlap(ctx context.Context, manifest Manifest) error {
	newPrefix, err := netip.ParsePrefix(manifest.NewLANCIDR)
	if err != nil {
		return errors.New("new LAN CIDR is invalid")
	}
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.IP, Arguments: []string{"-json", "address", "show"}})
	if err != nil || len(result.Stdout) > 1<<20 {
		return errors.New("observe host interface addresses failed")
	}
	var links []struct {
		Interface string `json:"ifname"`
		Addresses []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &links); err != nil {
		return errors.New("decode host interface addresses failed")
	}
	for _, link := range links {
		for _, item := range link.Addresses {
			if item.Family != "inet" {
				continue
			}
			address, err := netip.ParseAddr(item.Local)
			if err != nil || item.PrefixLen < 0 || item.PrefixLen > 32 {
				return errors.New("host contains an invalid observed IPv4 prefix")
			}
			observed := netip.PrefixFrom(address, item.PrefixLen)
			if link.Interface == manifest.InterfaceName && observed.String() == manifest.OldLANCIDR {
				continue
			}
			if newPrefix.Masked().Overlaps(observed.Masked()) {
				return fmt.Errorf("new LAN overlaps observed interface %s network %s", link.Interface, observed.Masked())
			}
		}
	}
	return nil
}

func prepareBackendDirectories(transactionDirectory string) (string, string, error) {
	if !filepath.IsAbs(transactionDirectory) {
		return "", "", errors.New("absolute transaction directory is required")
	}
	info, err := os.Lstat(transactionDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("network transaction directory is unsafe")
	}
	snapshot, candidate := filepath.Join(transactionDirectory, "snapshot"), filepath.Join(transactionDirectory, "candidate")
	for _, directory := range []string{snapshot, candidate} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return "", "", fmt.Errorf("create backend transaction directory: %w", err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return "", "", err
		}
	}
	return snapshot, candidate, nil
}

func existingBackendDirectories(transactionDirectory string) (string, string, error) {
	if !filepath.IsAbs(transactionDirectory) {
		return "", "", errors.New("absolute transaction directory is required")
	}
	snapshot, candidate := filepath.Join(transactionDirectory, "snapshot"), filepath.Join(transactionDirectory, "candidate")
	for _, directory := range []string{transactionDirectory, snapshot, candidate} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("backend transaction directory is unsafe")
		}
	}
	return snapshot, candidate, nil
}

func renderCandidateConfig(configuration config.Config, manifest Manifest) ([]byte, uint16, error) {
	oldURL, _ := url.Parse(manifest.OldURL)
	newURL, _ := url.Parse(manifest.NewURL)
	oldListen := net.JoinHostPort(oldURL.Hostname(), oldURL.Port())
	newListen := net.JoinHostPort(newURL.Hostname(), newURL.Port())
	replaced := 0
	for index, listen := range configuration.API.Listen {
		if listen == oldListen {
			configuration.API.Listen[index] = newListen
			replaced++
		}
	}
	if replaced != 1 {
		return nil, 0, errors.New("current API listen set does not contain exactly one old LAN endpoint")
	}
	configuration.Network.LANAddress = manifest.NewLANCIDR
	if err := configuration.Validate(); err != nil {
		return nil, 0, fmt.Errorf("validate candidate Gateway VPN config: %w", err)
	}
	port, err := strconv.ParseUint(newURL.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, 0, errors.New("candidate API port is invalid")
	}
	encoded, err := yaml.Marshal(configuration)
	if err != nil {
		return nil, 0, err
	}
	return encoded, uint16(port), nil
}

func renderDNSMasq(interfaceName, cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || prefix.Bits() != 24 || !validInterfaceName(interfaceName) {
		return "", errors.New("managed dnsmasq safe apply requires a valid /24 LAN")
	}
	address := prefix.Addr().As4()
	start, end := address, address
	start[3], end[3] = 100, 200
	return fmt.Sprintf(`interface=%s
bind-dynamic
listen-address=%s
port=53
dhcp-authoritative
dhcp-range=%s,%s,255.255.255.0,12h
dhcp-option=option:router,%s
dhcp-option=option:dns-server,%s
domain-needed
bogus-priv
no-resolv
server=127.0.0.1#1053
cache-size=0
log-facility=-
dhcp-leasefile=/var/lib/gateway-vpn-dnsmasq/dnsmasq.leases
pid-file=/run/gateway-vpn-dnsmasq.pid
`, interfaceName, prefix.Addr(), netip.AddrFrom4(start), netip.AddrFrom4(end), prefix.Addr(), prefix.Addr()), nil
}

func renderLANNetwork(interfaceName, cidr string) (string, error) {
	prefix, ok := netutil.ParseGatewayLAN(cidr)
	if !ok || !validInterfaceName(interfaceName) {
		return "", errors.New("managed LAN networkd policy requires a valid interface and IPv4 CIDR")
	}
	return fmt.Sprintf(`[Match]
Name=%s

[Network]
Address=%s
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
`, interfaceName, prefix.String()), nil
}

func readOptionalRegular(filename string, limit int64) (bool, []byte, error) {
	_, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	content, err := readBoundedRegular(filename, limit)
	return err == nil, content, err
}

func loadRuleset(filename string) (firewall.Ruleset, error) {
	content, err := readBoundedRegular(filename, 1<<20)
	if err != nil {
		return firewall.Ruleset{}, err
	}
	if !strings.Contains(string(content), "table inet "+firewall.TableName) {
		return firewall.Ruleset{}, errors.New("snapshot does not contain the owned firewall table")
	}
	digest := sha256.Sum256(content)
	return firewall.Ruleset{Text: string(content), SHA256: hex.EncodeToString(digest[:])}, nil
}

func installRegular(source, destination string, mode os.FileMode, gid int) error {
	content, err := readBoundedRegular(source, 1<<20)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("managed destination is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".network-apply-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if runtime.GOOS != "windows" && gid >= 0 {
		if err := temporary.Chown(0, gid); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, destination); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(name, destination); err != nil {
			return err
		}
	}
	return syncDirectory(directory)
}
