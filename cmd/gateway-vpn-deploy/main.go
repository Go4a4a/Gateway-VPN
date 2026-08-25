// Command gateway-vpn-deploy performs the signed two-host installation from an
// administrative Linux workstation. Private WireGuard and SSH keys are never
// included in the deployment report or remote command arguments.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/deploy"
	"gateway-vpn/internal/distribution"
	updatepkg "gateway-vpn/internal/update"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println(buildinfo.String("gateway-vpn-deploy"))
		return 0
	}
	flags := flag.NewFlagSet("gateway-vpn-deploy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	manifestPath := flags.String("manifest", "", "local signed channel manifest")
	signaturePath := flags.String("signature", "", "local detached channel signature")
	publicKeyPath := flags.String("public-key", "", "local trusted Ed25519 public key")
	manifestSHA256 := flags.String("manifest-sha256", "", "expected exact channel manifest SHA-256")
	signerKeySHA256 := flags.String("signer-key-sha256", "", "expected trusted signer fingerprint")
	channel := flags.String("channel", "stable", "expected signed channel")
	version := flags.String("release-version", "", "expected exact release version")
	commit := flags.String("source-commit", "", "expected exact source commit")
	repository := flags.String("github-repository", "", "GitHub OWNER/REPOSITORY")
	releaseTag := flags.String("release-tag", "", "immutable GitHub release tag")
	gatewaySSH := flags.String("gateway-ssh", "", "Gateway SSH destination USER@HOST")
	gatewayPort := flags.Int("gateway-port", 22, "Gateway SSH port")
	vpsSSH := flags.String("vps-ssh", "", "VPS SSH destination USER@HOST")
	vpsPort := flags.Int("vps-port", 22, "VPS SSH port")
	knownHosts := flags.String("known-hosts", "", "absolute pinned OpenSSH known_hosts file")
	gatewayIdentity := flags.String("gateway-identity", "", "optional absolute Gateway SSH identity file")
	vpsIdentity := flags.String("vps-identity", "", "optional absolute VPS SSH identity file")
	lanInterface := flags.String("lan-interface", "", "Gateway Ethernet interface connected to Keenetic WAN")
	lanAddress := flags.String("lan-address", "192.168.200.1/24", "Gateway transit LAN IPv4 CIDR")
	enableDHCP := flags.Bool("enable-dhcp", false, "enable validated transit DHCP")
	publicEndpoint := flags.String("public-endpoint", "", "public VPS HOST:51821 endpoint")
	adminPublicKey := flags.String("admin-public-key", "", "administrator WireGuard public key")
	adminConfig := flags.String("admin-config", "", "absolute local wg-quick config path; creates or resumes the administrator private key locally")
	allowGatewaySSH := flags.Bool("allow-gateway-ssh", false, "forward administrator SSH to Gateway through VPS")
	installDependencies := flags.Bool("install-dependencies", true, "install exact missing managed dependencies after plan validation")
	readinessAttempts := flags.Int("readiness-attempts", 18, "bounded readiness attempts")
	readinessInterval := flags.Duration("readiness-interval", 5*time.Second, "delay between readiness attempts")
	timeout := flags.Duration("timeout", 45*time.Minute, "overall deployment timeout")
	apply := flags.Bool("apply", false, "authorize the two-host installation after all read-only preflights")
	jsonOutput := flags.Bool("json", false, "emit only the final redacted JSON report")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if !*apply || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *manifestSHA256 == "" || *signerKeySHA256 == "" || *version == "" || *commit == "" || *repository == "" || *releaseTag == "" || *gatewaySSH == "" || *vpsSSH == "" || *knownHosts == "" || *lanInterface == "" || *publicEndpoint == "" || (*adminPublicKey == "") == (*adminConfig == "") {
		usage(flags)
		return 2
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "this signed deploy artifact requires a Linux/amd64 administrative host")
		return 1
	}
	manifest, err := loadVerifiedManifest(*manifestPath, *signaturePath, *publicKeyPath, *manifestSHA256, *signerKeySHA256, *channel, *version, *commit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify local signed deploy channel: %v\n", err)
		return 1
	}
	if err := verifyRunningDeployArtifact(manifest); err != nil {
		fmt.Fprintf(os.Stderr, "verify running deploy artifact: %v\n", err)
		return 1
	}
	resolvedAdminPublicKey := *adminPublicKey
	var localAdminIdentity *deploy.AdminIdentity
	if *adminConfig != "" {
		identity, prepareErr := deploy.PrepareAdminIdentity(*adminConfig)
		if prepareErr != nil {
			fmt.Fprintf(os.Stderr, "prepare local administrator WireGuard identity: %v\n", prepareErr)
			return 1
		}
		resolvedAdminPublicKey = identity.PublicKey
		localAdminIdentity = &identity
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	request := deploy.Request{
		Manifest: manifest, ManifestSHA256: *manifestSHA256, SignerKeySHA256: *signerKeySHA256,
		Repository: *repository, ReleaseTag: *releaseTag,
		Gateway:      deploy.Host{Destination: *gatewaySSH, Port: *gatewayPort, Identity: *gatewayIdentity, KnownHosts: *knownHosts},
		VPS:          deploy.Host{Destination: *vpsSSH, Port: *vpsPort, Identity: *vpsIdentity, KnownHosts: *knownHosts},
		LANInterface: *lanInterface, LANAddress: *lanAddress, EnableDHCP: *enableDHCP,
		PublicEndpoint: *publicEndpoint, AdminPublicKey: resolvedAdminPublicKey,
		AllowGatewaySSH: *allowGatewaySSH, InstallDependencies: *installDependencies,
		ReadinessAttempts: *readinessAttempts, ReadinessInterval: *readinessInterval,
	}
	report, deployErr := (deploy.Orchestrator{Executor: deploy.SSHExecutor{Executable: deploy.DefaultSSHExecutable, OutputLimit: deploy.DefaultOutputLimit}}).Run(ctx, request)
	if localAdminIdentity == nil {
		report.AdminConfigState = "EXTERNAL_PUBLIC_KEY"
	} else if report.VPSPublicKey == "" {
		report.AdminConfigState = "PENDING_LOCAL_KEY"
	} else if finalizeErr := localAdminIdentity.Finalize(report.VPSPublicKey, *publicEndpoint); finalizeErr != nil {
		report.State = deploy.StateFailed
		report.FailurePhase = "LOCAL_ADMIN_CONFIG_FINALIZE"
		report.DiagnosticCodes = append(report.DiagnosticCodes, "LOCAL_ADMIN_CONFIG_FINALIZE_FAILED")
		deployErr = finalizeErr
		report.AdminConfigState = "PENDING_LOCAL_KEY"
	} else {
		report.AdminConfigState = "CONFIGURED"
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
		fmt.Fprintln(os.Stderr, "encode redacted deployment report failed")
		return 1
	}
	if deployErr != nil {
		fmt.Fprintf(os.Stderr, "Gateway VPN deployment stopped in phase %s; no private key material was returned\n", report.FailurePhase)
		return 1
	}
	if report.State == deploy.StateInstalledNotReady {
		if !*jsonOutput {
			fmt.Fprintln(os.Stderr, "Both roles are installed safely, but modem/subscription path or WireGuard handshake is not ready yet")
		}
		return 3
	}
	if report.State != deploy.StateReady {
		return 1
	}
	if !*jsonOutput {
		fmt.Fprintf(os.Stderr, "Gateway VPN %s is READY; Web UI: %s\n", report.ReleaseVersion, report.WebUIURL)
	}
	return 0
}

func loadVerifiedManifest(manifestPath, signaturePath, publicKeyPath, expectedManifestSHA256, expectedSignerSHA256, channel, version, commit string) (distribution.Manifest, error) {
	content, err := readBoundedRegular(manifestPath, distribution.MaximumManifestBytes)
	if err != nil {
		return distribution.Manifest{}, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedManifestSHA256 {
		return distribution.Manifest{}, errors.New("channel manifest SHA-256 mismatch")
	}
	signature, err := readBoundedRegular(signaturePath, distribution.MaximumSignatureBytes)
	if err != nil {
		return distribution.Manifest{}, err
	}
	publicKey, err := updatepkg.LoadPublicKey(publicKeyPath)
	if err != nil {
		return distribution.Manifest{}, err
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	if fingerprint != expectedSignerSHA256 {
		return distribution.Manifest{}, errors.New("trusted channel signer fingerprint mismatch")
	}
	manifest, err := distribution.VerifyManifest(content, signature, publicKey, distribution.VerificationPolicy{
		ExpectedChannel: channel, ExpectedVersion: version, ExpectedCommit: commit,
	})
	if err != nil {
		return distribution.Manifest{}, err
	}
	return manifest, nil
}

func verifyRunningDeployArtifact(manifest distribution.Manifest) error {
	artifact, err := distribution.SelectArtifact(manifest, distribution.RoleDeploy, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	if buildinfo.Version != manifest.ReleaseVersion || buildinfo.Commit != manifest.SourceCommit {
		return errors.New("deploy binary build identity differs from signed channel")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve running deploy executable failed")
	}
	info, err := os.Lstat(executable)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != artifact.Bytes {
		return errors.New("running deploy executable identity is unsafe")
	}
	file, err := os.Open(executable)
	if err != nil {
		return errors.New("open running deploy executable failed")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, artifact.Bytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != artifact.Bytes || !bytes.Equal(hash.Sum(nil), mustDecodeHex(artifact.SHA256)) {
		return errors.New("running deploy executable SHA-256 mismatch")
	}
	return nil
}

func readBoundedRegular(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("deploy trust input must be a bounded regular non-symlink file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("open deploy trust input failed")
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || readErr != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("read deploy trust input failed")
	}
	return content, nil
}

func mustDecodeHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func usage(flags *flag.FlagSet) {
	fmt.Fprintln(flags.Output(), "usage: gateway-vpn-deploy --manifest FILE --signature FILE --public-key FILE --manifest-sha256 SHA256 --signer-key-sha256 SHA256 --channel CHANNEL --release-version VERSION --source-commit COMMIT --github-repository OWNER/REPO --release-tag TAG --gateway-ssh USER@HOST --vps-ssh USER@HOST --known-hosts FILE --lan-interface IFACE --public-endpoint HOST:51821 (--admin-config FILE|--admin-public-key KEY) --apply [options]")
}
