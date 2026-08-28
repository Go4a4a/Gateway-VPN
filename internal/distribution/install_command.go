package distribution

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"

	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/wireguard"
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	tagPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
	interfacePattern  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

type GatewayInstallCommandOptions struct {
	Repository              string
	ReleaseTag              string
	ManifestSHA256          string
	SignerKeySHA256         string
	Interactive             bool
	LANInterface            string
	LANAddress              string
	InstallDependencies     bool
	EnableDHCP              bool
	BootNetworkPolicy       string
	GRUBPolicy              string
	Apply                   bool
	NonInteractiveRoot      bool
	DependencyPreflightOnly bool
}

type VPSInstallCommandOptions struct {
	Repository              string
	ReleaseTag              string
	ManifestSHA256          string
	SignerKeySHA256         string
	PublicEndpoint          string
	GatewayPublicKey        string
	AdminPublicKey          string
	InstallDependencies     bool
	AllowGatewaySSH         bool
	Apply                   bool
	NonInteractiveRoot      bool
	DependencyPreflightOnly bool
}

type DeployCommandOptions struct {
	Repository          string
	ReleaseTag          string
	ManifestSHA256      string
	SignerKeySHA256     string
	GatewaySSH          string
	GatewayPort         int
	VPSSSH              string
	VPSPort             int
	KnownHosts          string
	GatewayIdentity     string
	VPSIdentity         string
	LANInterface        string
	LANAddress          string
	EnableDHCP          bool
	PublicEndpoint      string
	AdminPublicKey      string
	AdminConfig         string
	InstallDependencies bool
	AllowGatewaySSH     bool
}

// GatewayInstallCommand returns one copy/paste command with every mutable
// release input pinned. The downloaded bootstrap is never passed to sudo until
// its externally published SHA-256 has matched.
func GatewayInstallCommand(manifest Manifest, options GatewayInstallCommandOptions) (string, error) {
	if err := ValidateManifest(manifest); err != nil {
		return "", err
	}
	if !digestPattern.MatchString(options.ManifestSHA256) || !digestPattern.MatchString(options.SignerKeySHA256) || options.SignerKeySHA256 != manifest.SignerKeySHA256 {
		return "", errors.New("exact channel manifest and signer fingerprints are required")
	}
	if !validRepository(options.Repository) || !tagPattern.MatchString(options.ReleaseTag) {
		return "", errors.New("safe GitHub release inputs are required")
	}
	if options.Interactive {
		if options.LANInterface != "" || options.LANAddress != "" || options.InstallDependencies || options.EnableDHCP || options.BootNetworkPolicy != "" || options.GRUBPolicy != "" || options.Apply || options.NonInteractiveRoot || options.DependencyPreflightOnly {
			return "", errors.New("interactive Gateway command must defer all host policy choices and confirmation to the target terminal")
		}
	} else if !interfacePattern.MatchString(options.LANInterface) || !validLANPrefix(options.LANAddress) || !validBootNetworkPolicy(options.BootNetworkPolicy) || !validGRUBPolicy(options.GRUBPolicy) {
		return "", errors.New("safe explicit Gateway LAN inputs are required for automation mode")
	}
	bootstrap, err := SelectArtifact(manifest, RoleBootstrap, "linux", "amd64")
	if err != nil {
		return "", err
	}
	if _, err := SelectArtifact(manifest, RoleGateway, "linux", "amd64"); err != nil {
		return "", err
	}
	baseURL := "https://github.com/" + options.Repository + "/releases/download/" + options.ReleaseTag + "/"
	manifestName := "channel-" + manifest.Channel + ".json"
	signatureName := "channel-" + manifest.Channel + ".sig"
	parts := bootstrapCommandPrefix(baseURL+bootstrap.Filename, bootstrap.SHA256, options.NonInteractiveRoot)
	if options.Interactive {
		// Capture the SSH client before sudo can filter SSH_CONNECTION. The
		// bootstrap parses this only as a typed IP and protects its route.
		parts = append(parts, "management_connection=${SSH_CONNECTION:-}", "management_peer=${management_connection%% *}")
	}
	installCommand := "run_as_root \"$tmp\" install-gateway" +
		" --channel " + manifest.Channel +
		" --release-version " + manifest.ReleaseVersion +
		" --source-commit " + manifest.SourceCommit +
		" --manifest-url " + baseURL + manifestName +
		" --manifest-sha256 " + options.ManifestSHA256 +
		" --signature-url " + baseURL + signatureName +
		" --public-key-url " + baseURL + "update-signing.pub" +
		" --signer-key-sha256 " + options.SignerKeySHA256 +
		" --artifact-base-url " + baseURL
	if options.Interactive {
		installCommand += " --interactive --management-peer \"$management_peer\""
	} else {
		installCommand += " --lan-interface " + options.LANInterface + " --lan-address " + options.LANAddress +
			" --boot-network-policy " + options.BootNetworkPolicy + " --grub-policy " + options.GRUBPolicy
	}
	parts = append(parts, installCommand)
	if options.EnableDHCP {
		parts[len(parts)-1] += " --enable-dhcp"
	}
	if options.InstallDependencies {
		parts[len(parts)-1] += " --install-dependencies"
	}
	if options.DependencyPreflightOnly {
		if options.Apply || !options.InstallDependencies {
			return "", errors.New("dependency-preflight-only requires a dependency-enabled dry-run")
		}
		parts[len(parts)-1] += " --dependency-preflight-only"
	}
	if options.Apply {
		parts[len(parts)-1] += " --apply"
	}
	// SSH remote-command Bash may read ~/.bashrc even though the requested
	// command is non-interactive. Ubuntu's stock bashrc reads PS1 without an
	// unset guard, so nounset would abort the verified bootstrap before it can
	// run. --norc makes the generated command independent of remote dotfiles.
	return "bash --norc -ceu " + shellQuote(strings.Join(parts, "; ")), nil
}

func validBootNetworkPolicy(value string) bool {
	return value == "gateway-nonblocking" || value == "keep"
}

func validGRUBPolicy(value string) bool {
	return value == "automatic-hidden" || value == "menu-5s" || value == "keep"
}

// VPSInstallCommand provides the same bootstrap trust chain for the VPS role.
// WireGuard private keys are intentionally absent: the VPS installer creates
// its private key locally only after the full read-only preflight succeeds.
func VPSInstallCommand(manifest Manifest, options VPSInstallCommandOptions) (string, error) {
	if err := ValidateManifest(manifest); err != nil {
		return "", err
	}
	if !digestPattern.MatchString(options.ManifestSHA256) || !digestPattern.MatchString(options.SignerKeySHA256) || options.SignerKeySHA256 != manifest.SignerKeySHA256 {
		return "", errors.New("exact channel manifest and signer fingerprints are required")
	}
	if !validRepository(options.Repository) || !tagPattern.MatchString(options.ReleaseTag) || !validPublicEndpoint(options.PublicEndpoint) || !validWGPublicKey(options.GatewayPublicKey) || !validWGPublicKey(options.AdminPublicKey) || options.GatewayPublicKey == options.AdminPublicKey {
		return "", errors.New("safe GitHub release, VPS endpoint, and distinct WireGuard public keys are required")
	}
	bootstrap, err := SelectArtifact(manifest, RoleBootstrap, "linux", "amd64")
	if err != nil {
		return "", err
	}
	if _, err := SelectArtifact(manifest, RoleVPS, "linux", "amd64"); err != nil {
		return "", err
	}
	baseURL := "https://github.com/" + options.Repository + "/releases/download/" + options.ReleaseTag + "/"
	manifestName := "channel-" + manifest.Channel + ".json"
	signatureName := "channel-" + manifest.Channel + ".sig"
	parts := bootstrapCommandPrefix(baseURL+bootstrap.Filename, bootstrap.SHA256, options.NonInteractiveRoot)
	parts = append(parts,
		"run_as_root \"$tmp\" install-vps"+
			" --channel "+manifest.Channel+
			" --release-version "+manifest.ReleaseVersion+
			" --source-commit "+manifest.SourceCommit+
			" --manifest-url "+baseURL+manifestName+
			" --manifest-sha256 "+options.ManifestSHA256+
			" --signature-url "+baseURL+signatureName+
			" --public-key-url "+baseURL+"update-signing.pub"+
			" --signer-key-sha256 "+options.SignerKeySHA256+
			" --artifact-base-url "+baseURL+
			" --public-endpoint "+options.PublicEndpoint+
			" --gateway-public-key "+options.GatewayPublicKey+
			" --admin-public-key "+options.AdminPublicKey)
	if options.AllowGatewaySSH {
		parts[len(parts)-1] += " --allow-gateway-ssh"
	}
	if options.InstallDependencies {
		parts[len(parts)-1] += " --install-dependencies"
	}
	if options.DependencyPreflightOnly {
		if options.Apply || !options.InstallDependencies {
			return "", errors.New("dependency-preflight-only requires a dependency-enabled dry-run")
		}
		parts[len(parts)-1] += " --dependency-preflight-only"
	}
	if options.Apply {
		parts[len(parts)-1] += " --apply"
	}
	return "bash --norc -ceu " + shellQuote(strings.Join(parts, "; ")), nil
}

// DeployCommand returns a single administrative Linux command that downloads
// the exact deploy launcher, verifies its externally pinned SHA-256 before
// execution, and passes only public WireGuard material to the launcher.
func DeployCommand(manifest Manifest, options DeployCommandOptions) (string, error) {
	if err := ValidateManifest(manifest); err != nil {
		return "", err
	}
	if !digestPattern.MatchString(options.ManifestSHA256) || !digestPattern.MatchString(options.SignerKeySHA256) || options.SignerKeySHA256 != manifest.SignerKeySHA256 {
		return "", errors.New("exact channel manifest and signer fingerprints are required")
	}
	adminPublicKeyMode := validWGPublicKey(options.AdminPublicKey) && options.AdminConfig == ""
	adminConfigMode := options.AdminPublicKey == "" && validAbsoluteLinuxPath(options.AdminConfig)
	if !validRepository(options.Repository) || !tagPattern.MatchString(options.ReleaseTag) || !interfacePattern.MatchString(options.LANInterface) || !validLANPrefix(options.LANAddress) || !validPublicEndpoint(options.PublicEndpoint) || (!adminPublicKeyMode && !adminConfigMode) {
		return "", errors.New("safe deploy release, network, endpoint, and administrator inputs are required")
	}
	if !validGeneratedSSHDestination(options.GatewaySSH) || !validGeneratedSSHDestination(options.VPSSSH) || sameGeneratedSSHHost(options.GatewaySSH, options.VPSSSH) || options.GatewayPort < 1 || options.GatewayPort > 65535 || options.VPSPort < 1 || options.VPSPort > 65535 {
		return "", errors.New("distinct safe Gateway and VPS SSH destinations are required")
	}
	if !validAbsoluteLinuxPath(options.KnownHosts) || (options.GatewayIdentity != "" && !validAbsoluteLinuxPath(options.GatewayIdentity)) || (options.VPSIdentity != "" && !validAbsoluteLinuxPath(options.VPSIdentity)) {
		return "", errors.New("absolute Linux SSH trust paths are required")
	}
	deployArtifact, err := SelectArtifact(manifest, RoleDeploy, "linux", "amd64")
	if err != nil {
		return "", err
	}
	for _, role := range []string{RoleBootstrap, RoleGateway, RoleVPS} {
		if _, err := SelectArtifact(manifest, role, "linux", "amd64"); err != nil {
			return "", err
		}
	}
	baseURL := "https://github.com/" + options.Repository + "/releases/download/" + options.ReleaseTag + "/"
	manifestName := "channel-" + manifest.Channel + ".json"
	signatureName := "channel-" + manifest.Channel + ".sig"
	launcherArguments := []string{
		"--manifest", "$tmp/" + manifestName,
		"--signature", "$tmp/" + signatureName,
		"--public-key", "$tmp/update-signing.pub",
		"--manifest-sha256", options.ManifestSHA256,
		"--signer-key-sha256", options.SignerKeySHA256,
		"--channel", manifest.Channel,
		"--release-version", manifest.ReleaseVersion,
		"--source-commit", manifest.SourceCommit,
		"--github-repository", options.Repository,
		"--release-tag", options.ReleaseTag,
		"--gateway-ssh", options.GatewaySSH,
		"--gateway-port", strconv.Itoa(options.GatewayPort),
		"--vps-ssh", options.VPSSSH,
		"--vps-port", strconv.Itoa(options.VPSPort),
		"--known-hosts", options.KnownHosts,
		"--lan-interface", options.LANInterface,
		"--lan-address", options.LANAddress,
		"--public-endpoint", options.PublicEndpoint,
	}
	if adminPublicKeyMode {
		launcherArguments = append(launcherArguments, "--admin-public-key", options.AdminPublicKey)
	} else {
		launcherArguments = append(launcherArguments, "--admin-config", options.AdminConfig)
	}
	if options.GatewayIdentity != "" {
		launcherArguments = append(launcherArguments, "--gateway-identity", options.GatewayIdentity)
	}
	if options.VPSIdentity != "" {
		launcherArguments = append(launcherArguments, "--vps-identity", options.VPSIdentity)
	}
	if options.EnableDHCP {
		launcherArguments = append(launcherArguments, "--enable-dhcp")
	}
	if !options.InstallDependencies {
		launcherArguments = append(launcherArguments, "--install-dependencies=false")
	}
	if options.AllowGatewaySSH {
		launcherArguments = append(launcherArguments, "--allow-gateway-ssh")
	}
	launcherArguments = append(launcherArguments, "--apply", "--json")
	quotedArguments := make([]string, 0, len(launcherArguments))
	for _, argument := range launcherArguments {
		if strings.HasPrefix(argument, "$tmp/") {
			quotedArguments = append(quotedArguments, "\""+argument+"\"")
		} else {
			quotedArguments = append(quotedArguments, shellQuote(argument))
		}
	}
	parts := []string{
		"tmp=$(mktemp -d /tmp/gateway-vpn-deploy.XXXXXX)",
		"trap 'rm -rf -- \"$tmp\"' EXIT",
		"download() { if command -v curl >/dev/null 2>&1; then curl --fail --show-error --silent --location --max-redirs 5 --proto '=https' --proto-redir '=https' --tlsv1.2 --output \"$2\" \"$1\"; elif command -v wget >/dev/null 2>&1; then wget --quiet --https-only --max-redirect=5 --secure-protocol=TLSv1_2 --output-document=\"$2\" \"$1\"; else echo 'Gateway VPN deploy requires curl or GNU wget' >&2; return 1; fi; }",
		"download " + shellQuote(baseURL+deployArtifact.Filename) + " \"$tmp/deploy\"",
		"actual=$(sha256sum --binary \"$tmp/deploy\")",
		"actual=${actual%% *}",
		"test \"$actual\" = " + deployArtifact.SHA256,
		"download " + shellQuote(baseURL+manifestName) + " \"$tmp/" + manifestName + "\"",
		"download " + shellQuote(baseURL+signatureName) + " \"$tmp/" + signatureName + "\"",
		"download " + shellQuote(baseURL+"update-signing.pub") + " \"$tmp/update-signing.pub\"",
		"chmod 0700 \"$tmp/deploy\"",
		"\"$tmp/deploy\" " + strings.Join(quotedArguments, " "),
	}
	return "bash --norc -ceu " + shellQuote(strings.Join(parts, "; ")), nil
}

func bootstrapCommandPrefix(downloadURL, expectedSHA256 string, nonInteractiveRoot bool) []string {
	rootCommand := "sudo \"$@\""
	if nonInteractiveRoot {
		rootCommand = "sudo -n \"$@\""
	}
	return []string{
		"tmp=$(mktemp /tmp/gateway-vpn-bootstrap.XXXXXX)",
		"trap 'rm -f \"$tmp\"' EXIT",
		"if command -v curl >/dev/null 2>&1; then curl --fail --show-error --silent --location --max-redirs 5 --proto '=https' --proto-redir '=https' --tlsv1.2 --output \"$tmp\" " + downloadURL + "; elif command -v wget >/dev/null 2>&1; then wget --quiet --https-only --max-redirect=5 --secure-protocol=TLSv1_2 --output-document=\"$tmp\" " + downloadURL + "; else echo 'Gateway VPN bootstrap requires curl or GNU wget' >&2; exit 1; fi",
		"actual=$(sha256sum --binary \"$tmp\")",
		"actual=${actual%% *}",
		"test \"$actual\" = " + expectedSHA256,
		"chmod 0700 \"$tmp\"",
		"run_as_root() { if [ \"$(id -u)\" -eq 0 ]; then \"$@\"; else command -v sudo >/dev/null 2>&1 || { echo 'Gateway VPN bootstrap requires root or sudo' >&2; return 1; }; " + rootCommand + "; fi; }",
	}
}

func validRepository(value string) bool {
	if !repositoryPattern.MatchString(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") {
			return false
		}
	}
	return true
}

func validLANPrefix(value string) bool {
	return netutil.ValidGatewayLAN(value)
}

func validWGPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validPublicEndpoint(value string) bool {
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

func validGeneratedSSHDestination(value string) bool {
	if value == "" || len(value) > 255 || strings.HasPrefix(value, "-") || strings.ContainsAny(value, " \t\r\n/\\:[]") || strings.Count(value, "@") > 1 {
		return false
	}
	user, host, hasUser := strings.Cut(value, "@")
	if hasUser {
		if !regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`).MatchString(user) {
			return false
		}
	} else {
		host = user
	}
	if address := net.ParseIP(host); address != nil {
		return address.To4() != nil && !address.IsUnspecified() && !address.IsMulticast()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
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

func validAbsoluteLinuxPath(value string) bool {
	return strings.HasPrefix(value, "/") && path.IsAbs(value) && path.Clean(value) == value && len(value) <= 4096 && !strings.ContainsAny(value, " \t\x00\r\n")
}

func sameGeneratedSSHHost(left, right string) bool {
	leftHost := left
	if _, host, found := strings.Cut(left, "@"); found {
		leftHost = host
	}
	rightHost := right
	if _, host, found := strings.Cut(right, "@"); found {
		rightHost = host
	}
	return strings.EqualFold(strings.TrimSuffix(leftHost, "."), strings.TrimSuffix(rightHost, "."))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func expectedArtifactFilename(role, version string) string {
	suffix := ""
	if role == RoleGateway || role == RoleVPS {
		suffix = ".tar.gz"
	}
	return fmt.Sprintf("gateway-vpn-%s-%s-linux-amd64%s", role, version, suffix)
}
