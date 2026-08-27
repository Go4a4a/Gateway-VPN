package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gateway-vpn/internal/distribution"
	updatepkg "gateway-vpn/internal/update"
)

type artifactSpecs []string

func (values *artifactSpecs) String() string { return strings.Join(*values, ",") }

func (values *artifactSpecs) Set(value string) error {
	if value == "" {
		return errors.New("artifact must use ROLE=FILE")
	}
	*values = append(*values, value)
	return nil
}

func runChannelSign(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl channel-sign", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	channel := flags.String("channel", "stable", "signed release channel")
	version := flags.String("release-version", "", "exact release version")
	commit := flags.String("source-commit", "", "exact source commit")
	generatedAt := flags.String("generated-at", "", "RFC3339 generation time; defaults to now")
	privateKeyPath := flags.String("private-key", "", "PKCS#8 Ed25519 private key path")
	outputDirectory := flags.String("output-dir", "", "existing directory for channel files")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	var artifacts artifactSpecs
	flags.Var(&artifacts, "artifact", "role artifact as ROLE=FILE; repeat for each role")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *version == "" || *commit == "" || *privateKeyPath == "" || *outputDirectory == "" || len(artifacts) == 0 {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	generated := time.Now().UTC().Truncate(time.Second)
	if *generatedAt != "" {
		parsed, err := time.Parse(time.RFC3339, *generatedAt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid channel generation time")
			return 2
		}
		generated = parsed.UTC()
	}
	privateKey, err := updatepkg.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load channel signing key failed")
		return 1
	}
	built := make([]distribution.Artifact, 0, len(artifacts))
	seen := make(map[string]bool, len(artifacts))
	for _, specification := range artifacts {
		role, filename, ok := strings.Cut(specification, "=")
		if !ok || role == "" || filename == "" || seen[role] {
			fmt.Fprintln(os.Stderr, "each channel artifact must use one unique ROLE=FILE")
			return 2
		}
		artifact, err := distribution.ArtifactFromFile(role, "linux", "amd64", filename, *version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inspect %s artifact: %v\n", role, err)
			return 1
		}
		seen[role] = true
		built = append(built, artifact)
	}
	distribution.SortArtifacts(built)
	manifest := distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: *channel,
		ReleaseVersion: *version, GeneratedAt: generated.Format(time.RFC3339),
		SourceCommit: *commit, Artifacts: built,
	}
	content, signature, err := distribution.SignManifest(manifest, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign channel manifest: %v\n", err)
		return 1
	}
	manifestPath, signaturePath, err := writeChannelPair(*outputDirectory, *channel, content, signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write signed channel: %v\n", err)
		return 1
	}
	digest, _ := distribution.ManifestSHA256(content)
	fingerprint, _ := updatepkg.PublicKeyFingerprint(privateKey.Public().(ed25519.PublicKey))
	result := map[string]any{
		"manifest": manifestPath, "signature": signaturePath,
		"manifest_sha256": digest, "signer_key_sha256": fingerprint, "artifact_count": len(built),
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(result)
	} else {
		fmt.Printf("Signed %s channel %s written; manifest SHA-256=%s artifacts=%d\n", *channel, *version, digest, len(built))
	}
	return 0
}

func runChannelVerify(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl channel-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	manifestPath, signaturePath, publicKeyPath, channel, version, commit, maximumAge, jsonOutput := channelVerificationFlags(flags)
	var artifacts artifactSpecs
	flags.Var(&artifacts, "artifact", "local role artifact as ROLE=FILE; when present every signed artifact is re-hashed")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *channel == "" || *version == "" || *commit == "" {
		return 2
	}
	manifest, content, fingerprint, err := verifyChannelFiles(*manifestPath, *signaturePath, *publicKeyPath, *channel, *version, *commit, *maximumAge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed channel: %v\n", err)
		return 1
	}
	if len(artifacts) > 0 {
		if err := verifyLocalChannelArtifacts(manifest, artifacts); err != nil {
			fmt.Fprintf(os.Stderr, "verify local channel artifacts: %v\n", err)
			return 1
		}
	}
	digest, _ := distribution.ManifestSHA256(content)
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"channel": manifest.Channel, "release_version": manifest.ReleaseVersion, "source_commit": manifest.SourceCommit, "signer_key_sha256": fingerprint, "manifest_sha256": digest, "artifacts": manifest.Artifacts, "local_artifacts_verified": len(artifacts) > 0})
	} else {
		fmt.Printf("Signed channel %s release %s verified; signer=%s manifest=%s artifacts=%d local=%t\n", manifest.Channel, manifest.ReleaseVersion, fingerprint, digest, len(manifest.Artifacts), len(artifacts) > 0)
	}
	return 0
}

func verifyLocalChannelArtifacts(manifest distribution.Manifest, specifications []string) error {
	if len(specifications) != len(manifest.Artifacts) {
		return errors.New("every signed channel artifact must be provided exactly once")
	}
	seen := make(map[string]bool, len(specifications))
	for _, specification := range specifications {
		role, filename, ok := strings.Cut(specification, "=")
		if !ok || role == "" || filename == "" || seen[role] {
			return errors.New("each local channel artifact must use one unique ROLE=FILE")
		}
		seen[role] = true
		actual, err := distribution.ArtifactFromFile(role, "linux", "amd64", filename, manifest.ReleaseVersion)
		if err != nil {
			return fmt.Errorf("inspect %s artifact: %w", role, err)
		}
		expected, err := distribution.SelectArtifact(manifest, role, "linux", "amd64")
		if err != nil || actual != expected {
			return fmt.Errorf("%s artifact does not match signed filename, size, and SHA-256", role)
		}
	}
	return nil
}

func runChannelInstallCommand(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl channel-install-command", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	manifestPath, signaturePath, publicKeyPath, channel, version, commit, maximumAge, _ := channelVerificationFlags(flags)
	repository := flags.String("github-repository", "", "GitHub OWNER/REPOSITORY")
	releaseTag := flags.String("release-tag", "", "immutable GitHub Release tag; defaults to vVERSION")
	lanInterface := flags.String("lan-interface", "", "Ethernet interface connected to Keenetic WAN")
	lanAddress := flags.String("lan-address", "192.168.200.1/24", "Gateway transit LAN IPv4 CIDR")
	enableDHCP := flags.Bool("enable-dhcp", false, "include opt-in transit DHCP")
	installDependencies := flags.Bool("install-dependencies", false, "install missing managed Gateway packages after dependency-plan validation")
	apply := flags.Bool("apply", false, "include installation after read-only preflight")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *channel == "" || *version == "" || *commit == "" || *repository == "" || *lanInterface == "" {
		return 2
	}
	manifest, content, fingerprint, err := verifyChannelFiles(*manifestPath, *signaturePath, *publicKeyPath, *channel, *version, *commit, *maximumAge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed channel before command generation: %v\n", err)
		return 1
	}
	tag := *releaseTag
	if tag == "" {
		tag = "v" + manifest.ReleaseVersion
	}
	digest, _ := distribution.ManifestSHA256(content)
	command, err := distribution.GatewayInstallCommand(manifest, distribution.GatewayInstallCommandOptions{
		Repository: *repository, ReleaseTag: tag, ManifestSHA256: digest,
		SignerKeySHA256: fingerprint, LANInterface: *lanInterface, LANAddress: *lanAddress,
		InstallDependencies: *installDependencies, EnableDHCP: *enableDHCP, Apply: *apply,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate exact Gateway install command: %v\n", err)
		return 1
	}
	fmt.Println(command)
	return 0
}

func runChannelVPSInstallCommand(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl channel-vps-install-command", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	manifestPath, signaturePath, publicKeyPath, channel, version, commit, maximumAge, _ := channelVerificationFlags(flags)
	repository := flags.String("github-repository", "", "GitHub OWNER/REPOSITORY")
	releaseTag := flags.String("release-tag", "", "immutable GitHub Release tag; defaults to vVERSION")
	publicEndpoint := flags.String("public-endpoint", "", "public VPS HOST:51821")
	gatewayPublicKey := flags.String("gateway-public-key", "", "Gateway WireGuard public key")
	adminPublicKey := flags.String("admin-public-key", "", "administrator WireGuard public key")
	installDependencies := flags.Bool("install-dependencies", false, "install missing managed VPS packages after dependency-plan validation")
	allowGatewaySSH := flags.Bool("allow-gateway-ssh", false, "forward administrator SSH to Gateway")
	apply := flags.Bool("apply", false, "include installation after read-only preflight")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *channel == "" || *version == "" || *commit == "" || *repository == "" || *publicEndpoint == "" || *gatewayPublicKey == "" || *adminPublicKey == "" {
		return 2
	}
	manifest, content, fingerprint, err := verifyChannelFiles(*manifestPath, *signaturePath, *publicKeyPath, *channel, *version, *commit, *maximumAge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed channel before VPS command generation: %v\n", err)
		return 1
	}
	tag := *releaseTag
	if tag == "" {
		tag = "v" + manifest.ReleaseVersion
	}
	digest, _ := distribution.ManifestSHA256(content)
	command, err := distribution.VPSInstallCommand(manifest, distribution.VPSInstallCommandOptions{
		Repository: *repository, ReleaseTag: tag, ManifestSHA256: digest, SignerKeySHA256: fingerprint,
		PublicEndpoint: *publicEndpoint, GatewayPublicKey: *gatewayPublicKey, AdminPublicKey: *adminPublicKey,
		InstallDependencies: *installDependencies, AllowGatewaySSH: *allowGatewaySSH, Apply: *apply,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate exact VPS install command: %v\n", err)
		return 1
	}
	fmt.Println(command)
	return 0
}

func runChannelDeployCommand(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl channel-deploy-command", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	manifestPath, signaturePath, publicKeyPath, channel, version, commit, maximumAge, _ := channelVerificationFlags(flags)
	repository := flags.String("github-repository", "", "GitHub OWNER/REPOSITORY")
	releaseTag := flags.String("release-tag", "", "immutable GitHub Release tag; defaults to vVERSION")
	gatewaySSH := flags.String("gateway-ssh", "", "Gateway SSH destination USER@HOST")
	gatewayPort := flags.Int("gateway-port", 22, "Gateway SSH port")
	vpsSSH := flags.String("vps-ssh", "", "VPS SSH destination USER@HOST")
	vpsPort := flags.Int("vps-port", 22, "VPS SSH port")
	knownHosts := flags.String("known-hosts", "", "absolute Linux known_hosts path")
	gatewayIdentity := flags.String("gateway-identity", "", "optional absolute Gateway SSH identity path")
	vpsIdentity := flags.String("vps-identity", "", "optional absolute VPS SSH identity path")
	lanInterface := flags.String("lan-interface", "", "Ethernet interface connected to Keenetic WAN")
	lanAddress := flags.String("lan-address", "192.168.200.1/24", "Gateway transit LAN IPv4 CIDR")
	enableDHCP := flags.Bool("enable-dhcp", false, "enable transit DHCP after validation")
	publicEndpoint := flags.String("public-endpoint", "", "public VPS HOST:51821")
	adminPublicKey := flags.String("admin-public-key", "", "administrator WireGuard public key")
	adminConfig := flags.String("admin-config", "", "absolute administrator wg-quick config path created locally by deploy")
	noInstallDependencies := flags.Bool("no-install-dependencies", false, "require all managed dependencies to exist already")
	allowGatewaySSH := flags.Bool("allow-gateway-ssh", false, "forward administrator SSH to Gateway")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *channel == "" || *version == "" || *commit == "" || *repository == "" || *gatewaySSH == "" || *vpsSSH == "" || *knownHosts == "" || *lanInterface == "" || *publicEndpoint == "" || (*adminPublicKey == "") == (*adminConfig == "") {
		return 2
	}
	manifest, content, fingerprint, err := verifyChannelFiles(*manifestPath, *signaturePath, *publicKeyPath, *channel, *version, *commit, *maximumAge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed channel before deploy command generation: %v\n", err)
		return 1
	}
	tag := *releaseTag
	if tag == "" {
		tag = "v" + manifest.ReleaseVersion
	}
	digest, _ := distribution.ManifestSHA256(content)
	command, err := distribution.DeployCommand(manifest, distribution.DeployCommandOptions{
		Repository: *repository, ReleaseTag: tag, ManifestSHA256: digest, SignerKeySHA256: fingerprint,
		GatewaySSH: *gatewaySSH, GatewayPort: *gatewayPort, VPSSSH: *vpsSSH, VPSPort: *vpsPort,
		KnownHosts: *knownHosts, GatewayIdentity: *gatewayIdentity, VPSIdentity: *vpsIdentity,
		LANInterface: *lanInterface, LANAddress: *lanAddress, EnableDHCP: *enableDHCP,
		PublicEndpoint: *publicEndpoint, AdminPublicKey: *adminPublicKey, AdminConfig: *adminConfig,
		InstallDependencies: !*noInstallDependencies, AllowGatewaySSH: *allowGatewaySSH,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate exact two-host deploy command: %v\n", err)
		return 1
	}
	fmt.Println(command)
	return 0
}

func channelVerificationFlags(flags *flag.FlagSet) (*string, *string, *string, *string, *string, *string, *time.Duration, *bool) {
	manifestPath := flags.String("manifest", "", "signed channel manifest path")
	signaturePath := flags.String("signature", "", "detached channel signature path")
	publicKeyPath := flags.String("public-key", "", "trusted PKIX Ed25519 public key path")
	channel := flags.String("channel", "stable", "expected channel")
	version := flags.String("release-version", "", "expected exact release version")
	commit := flags.String("source-commit", "", "expected exact source commit")
	maximumAge := flags.Duration("maximum-age", 0, "optional manifest freshness limit")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	return manifestPath, signaturePath, publicKeyPath, channel, version, commit, maximumAge, jsonOutput
}

func verifyChannelFiles(manifestPath, signaturePath, publicKeyPath, channel, version, commit string, maximumAge time.Duration) (distribution.Manifest, []byte, string, error) {
	content, err := readCommandFile(manifestPath, distribution.MaximumManifestBytes)
	if err != nil {
		return distribution.Manifest{}, nil, "", err
	}
	signature, err := readCommandFile(signaturePath, distribution.MaximumSignatureBytes)
	if err != nil {
		return distribution.Manifest{}, nil, "", err
	}
	publicKey, err := updatepkg.LoadPublicKey(publicKeyPath)
	if err != nil {
		return distribution.Manifest{}, nil, "", err
	}
	manifest, err := distribution.VerifyManifest(content, signature, publicKey, distribution.VerificationPolicy{
		ExpectedChannel: channel, ExpectedVersion: version, ExpectedCommit: commit, MaximumAge: maximumAge,
	})
	if err != nil {
		return distribution.Manifest{}, nil, "", err
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	return manifest, content, fingerprint, nil
}

func writeChannelPair(directory, channel string, content, signature []byte) (string, string, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return "", "", errors.New("resolve channel output directory failed")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", errors.New("channel output directory must be a real existing directory")
	}
	manifestPath := filepath.Join(directory, "channel-"+channel+".json")
	signaturePath := filepath.Join(directory, "channel-"+channel+".sig")
	for _, filename := range []string{manifestPath, signaturePath} {
		if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
			return "", "", errors.New("refuse to replace existing channel output")
		}
	}
	if err := writeCommandFile(manifestPath, content); err != nil {
		return "", "", err
	}
	if err := writeCommandFile(signaturePath, signature); err != nil {
		_ = os.Remove(manifestPath)
		return "", "", err
	}
	return manifestPath, signaturePath, nil
}

func writeCommandFile(filename string, content []byte) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return errors.New("create channel output failed")
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		_ = os.Remove(filename)
		return errors.New("durably write channel output failed")
	}
	return nil
}

func readCommandFile(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("channel input must be a bounded regular non-symlink file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("open channel input failed")
	}
	openedInfo, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, openedInfo) || readErr != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("read channel input failed")
	}
	return content, nil
}
