package bootstrapinstall

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gateway-vpn/internal/distribution"
	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/wireguard"
)

var (
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	ipv4CIDRPattern  = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:[1-9]|[12][0-9]|30)$`)
)

type CommandRequest struct {
	Executable  string
	Arguments   []string
	Directory   string
	Environment []string
}

type Runner interface {
	Run(context.Context, CommandRequest) error
}

type OSRunner struct{}

type CommandError struct {
	ExitCode int
}

func (err CommandError) Error() string {
	return "verified role installer command failed with exit code " + strconv.Itoa(err.ExitCode)
}

func (OSRunner) Run(ctx context.Context, request CommandRequest) error {
	if request.Executable != "/usr/bin/bash" || !filepath.IsAbs(request.Directory) {
		return errors.New("bootstrap may execute only the fixed Bash interpreter in a verified release")
	}
	command := exec.CommandContext(ctx, request.Executable, request.Arguments...)
	command.Dir = request.Directory
	command.Env = append([]string(nil), request.Environment...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return CommandError{ExitCode: exitError.ExitCode()}
		}
		return errors.New("verified role installer command failed")
	}
	return nil
}

type Installer struct {
	Runner Runner
	Bash   string
}

type GatewayOptions struct {
	LANInterface            string
	LANMembers              []string
	LANAddress              string
	InstallDependencies     bool
	EnableDHCP              bool
	DisableSSH              bool
	BootNetworkPolicy       string
	GRUBPolicy              string
	Apply                   bool
	DependencyPreflightOnly bool
}

type VPSOptions struct {
	PublicEndpoint          string
	GatewayPublicKey        string
	AdminPublicKey          string
	InstallDependencies     bool
	AllowGatewaySSH         bool
	Apply                   bool
	DependencyPreflightOnly bool
}

type InstallResult struct {
	Role            string `json:"role"`
	Version         string `json:"version"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	ManifestSHA256  string `json:"manifest_sha256"`
	SignerKeySHA256 string `json:"signer_key_sha256"`
	Preflight       string `json:"preflight"`
	Installation    string `json:"installation"`
}

func (installer Installer) InstallGateway(ctx context.Context, prepared Prepared, options GatewayOptions) (InstallResult, error) {
	if installer.Runner == nil || installer.Bash != "/usr/bin/bash" {
		return InstallResult{}, errors.New("fixed bootstrap installer runner is required")
	}
	if prepared.Artifact.Role != distribution.RoleGateway || prepared.VerifiedRelease.Release.GatewayVersion == "" || prepared.Manifest.ReleaseVersion != prepared.VerifiedRelease.Release.GatewayVersion || prepared.InstallerPath != filepath.Join(prepared.ReleaseRoot, "scripts", "install-gateway.sh") {
		return InstallResult{}, errors.New("prepared artifact is not an independently verified Gateway release")
	}
	if !interfacePattern.MatchString(options.LANInterface) || !validIPv4CIDR(options.LANAddress) || !validLANMembers(options.LANInterface, options.LANMembers) {
		return InstallResult{}, errors.New("explicit valid Gateway LAN interface and CIDR are required")
	}
	if !validGatewayBootNetworkPolicy(options.BootNetworkPolicy) || !validGatewayGRUBPolicy(options.GRUBPolicy) {
		return InstallResult{}, errors.New("explicit valid Gateway boot-network and GRUB policies are required")
	}
	if options.DependencyPreflightOnly && (options.Apply || !options.InstallDependencies) {
		return InstallResult{}, errors.New("dependency-preflight-only requires a dependency-enabled dry-run")
	}
	arguments := []string{
		prepared.InstallerPath,
		"--release-dir", prepared.ReleaseRoot,
		"--trusted-update-key", prepared.PublicKeyPath,
		"--version", prepared.VerifiedRelease.Release.GatewayVersion,
		"--lan-interface", options.LANInterface,
		"--lan-address", options.LANAddress,
		"--boot-network-policy", options.BootNetworkPolicy,
		"--grub-policy", options.GRUBPolicy,
	}
	if len(options.LANMembers) > 0 {
		arguments = append(arguments, "--lan-members", strings.Join(options.LANMembers, ","))
	}
	if options.EnableDHCP {
		arguments = append(arguments, "--enable-dhcp")
	}
	if options.DisableSSH {
		arguments = append(arguments, "--disable-ssh")
	}
	if options.InstallDependencies {
		arguments = append(arguments, "--install-dependencies")
	}
	preflightArguments := append([]string(nil), arguments...)
	if options.InstallDependencies && (options.Apply || options.DependencyPreflightOnly) {
		preflightArguments = append(preflightArguments, "--dependency-preflight-only")
	}
	request := CommandRequest{
		Executable: installer.Bash, Arguments: preflightArguments, Directory: prepared.ReleaseRoot,
		Environment: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"},
	}
	if err := installer.Runner.Run(ctx, request); err != nil {
		var commandError CommandError
		if !(options.InstallDependencies && (options.Apply || options.DependencyPreflightOnly) && errors.As(err, &commandError) && commandError.ExitCode == 10) {
			return InstallResult{}, errors.New("Gateway read-only preflight failed; no installation was requested")
		}
	}
	preflightState := "PASSED"
	if options.DependencyPreflightOnly {
		preflightState = "DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED"
	} else if options.InstallDependencies {
		preflightState = "DEPENDENCY_PLAN_VALIDATED"
	}
	result := InstallResult{
		Role: distribution.RoleGateway, Version: prepared.VerifiedRelease.Release.GatewayVersion,
		ArtifactSHA256: prepared.Artifact.SHA256, ManifestSHA256: prepared.ManifestSHA256,
		SignerKeySHA256: prepared.SignerKeySHA256, Preflight: preflightState, Installation: "NOT_REQUESTED",
	}
	if !options.Apply {
		return result, nil
	}
	request.Arguments = append(append([]string(nil), arguments...), "--apply")
	if err := installer.Runner.Run(ctx, request); err != nil {
		return InstallResult{}, errors.New("Gateway installer apply failed or rolled back")
	}
	result.Preflight = "PASSED"
	result.Installation = "APPLIED"
	return result, nil
}

func (installer Installer) InstallVPS(ctx context.Context, prepared Prepared, options VPSOptions) (InstallResult, error) {
	if installer.Runner == nil || installer.Bash != "/usr/bin/bash" {
		return InstallResult{}, errors.New("fixed bootstrap installer runner is required")
	}
	if prepared.Artifact.Role != distribution.RoleVPS || prepared.VerifiedVPS.Release.Version == "" || prepared.Manifest.ReleaseVersion != prepared.VerifiedVPS.Release.Version || prepared.InstallerPath != filepath.Join(prepared.ReleaseRoot, "scripts", "install-vps.sh") {
		return InstallResult{}, errors.New("prepared artifact is not an independently verified VPS release")
	}
	if !validVPSPublicEndpoint(options.PublicEndpoint) || !validWireGuardPublicKey(options.GatewayPublicKey) || !validWireGuardPublicKey(options.AdminPublicKey) || options.GatewayPublicKey == options.AdminPublicKey {
		return InstallResult{}, errors.New("explicit safe VPS endpoint and distinct WireGuard public keys are required")
	}
	if options.DependencyPreflightOnly && (options.Apply || !options.InstallDependencies) {
		return InstallResult{}, errors.New("dependency-preflight-only requires a dependency-enabled dry-run")
	}
	arguments := []string{
		prepared.InstallerPath,
		"--release-dir", prepared.ReleaseRoot,
		"--trusted-update-key", prepared.PublicKeyPath,
		"--version", prepared.VerifiedVPS.Release.Version,
		"--public-endpoint", options.PublicEndpoint,
		"--gateway-public-key", options.GatewayPublicKey,
		"--admin-public-key", options.AdminPublicKey,
	}
	if options.AllowGatewaySSH {
		arguments = append(arguments, "--allow-gateway-ssh")
	}
	if options.InstallDependencies {
		arguments = append(arguments, "--install-dependencies")
	}
	preflightArguments := append([]string(nil), arguments...)
	if options.InstallDependencies && (options.Apply || options.DependencyPreflightOnly) {
		// The external read-only phase may discover that an APT index refresh is
		// required. The apply phase refreshes and re-simulates before installing.
		preflightArguments = append(preflightArguments, "--dependency-preflight-only")
	}
	request := CommandRequest{
		Executable: installer.Bash, Arguments: preflightArguments, Directory: prepared.ReleaseRoot,
		Environment: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"},
	}
	if err := installer.Runner.Run(ctx, request); err != nil {
		var commandError CommandError
		if !(options.InstallDependencies && (options.Apply || options.DependencyPreflightOnly) && errors.As(err, &commandError) && commandError.ExitCode == 10) {
			return InstallResult{}, errors.New("VPS read-only preflight failed; no installation was requested")
		}
	}
	preflightState := "PASSED"
	if options.DependencyPreflightOnly {
		preflightState = "DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED"
	} else if options.InstallDependencies {
		// A successful no-apply run can only prove the package plan when
		// managed dependencies are absent. Keep the result conservative.
		preflightState = "DEPENDENCY_PLAN_VALIDATED"
	}
	result := InstallResult{
		Role: distribution.RoleVPS, Version: prepared.VerifiedVPS.Release.Version,
		ArtifactSHA256: prepared.Artifact.SHA256, ManifestSHA256: prepared.ManifestSHA256,
		SignerKeySHA256: prepared.SignerKeySHA256, Preflight: preflightState, Installation: "NOT_REQUESTED",
	}
	if !options.Apply {
		return result, nil
	}
	request.Arguments = append(append([]string(nil), arguments...), "--apply")
	if err := installer.Runner.Run(ctx, request); err != nil {
		return InstallResult{}, errors.New("VPS installer apply failed or rolled back")
	}
	result.Preflight = "PASSED"
	result.Installation = "APPLIED"
	return result, nil
}

func validIPv4CIDR(value string) bool {
	if !ipv4CIDRPattern.MatchString(value) {
		return false
	}
	return netutil.ValidGatewayLAN(value)
}

func validLANMembers(lanInterface string, members []string) bool {
	if len(members) == 0 {
		return true
	}
	if lanInterface != "gateway-vpn-lan" || len(members) > 16 {
		return false
	}
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		if !interfacePattern.MatchString(member) || member == lanInterface || seen[member] {
			return false
		}
		seen[member] = true
	}
	return true
}

func validGatewayBootNetworkPolicy(value string) bool {
	return value == "gateway-nonblocking" || value == "keep"
}

func validGatewayGRUBPolicy(value string) bool {
	return value == "automatic-hidden" || value == "menu-5s" || value == "keep"
}

func validWireGuardPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validVPSPublicEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort != 51821 {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
	}
	return wireguard.ValidEndpointHostname(host)
}
