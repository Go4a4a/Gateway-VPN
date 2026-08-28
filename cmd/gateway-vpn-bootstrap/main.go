// Command gateway-vpn-bootstrap is a separately distributed, externally
// SHA-256-pinned verifier for first installation. It authenticates the channel
// and complete role release before executing any candidate-provided installer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gateway-vpn/internal/bootstrapinstall"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/distribution"
	"gateway-vpn/internal/installwizard"
	"gateway-vpn/internal/platformexec"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println(buildinfo.String("gateway-vpn-bootstrap"))
		return 0
	}
	if len(args) > 0 && args[0] == "install-vps" {
		return runInstallVPS(args[1:])
	}
	if len(args) == 0 || args[0] != "install-gateway" {
		usage(os.Stderr)
		return 2
	}
	flags := flag.NewFlagSet("gateway-vpn-bootstrap install-gateway", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	channel := flags.String("channel", "stable", "signed release channel")
	version := flags.String("release-version", "", "exact immutable Gateway VPN version")
	commit := flags.String("source-commit", "", "optional exact signed source commit")
	manifestURL := flags.String("manifest-url", "", "versioned channel manifest HTTPS URL")
	manifestSHA256 := flags.String("manifest-sha256", "", "expected raw channel manifest SHA-256")
	signatureURL := flags.String("signature-url", "", "detached channel signature HTTPS URL")
	publicKeyURL := flags.String("public-key-url", "", "trusted Ed25519 public key HTTPS URL")
	signerKeySHA256 := flags.String("signer-key-sha256", "", "expected Ed25519 public key fingerprint")
	artifactBaseURL := flags.String("artifact-base-url", "", "versioned GitHub Release URL ending in slash")
	interactive := flags.Bool("interactive", false, "select Gateway LAN settings on the target through a real terminal")
	managementPeer := flags.String("management-peer", "", "optional current SSH client IP protected by interactive interface selection")
	lanInterface := flags.String("lan-interface", "", "explicit Ethernet interface connected to Keenetic WAN")
	lanAddress := flags.String("lan-address", "", "explicit Gateway transit LAN IPv4 CIDR; defaults to 192.168.200.1/24 in automation mode")
	enableDHCP := flags.Bool("enable-dhcp", false, "enable transit DHCP after validation")
	installDependencies := flags.Bool("install-dependencies", false, "install missing managed Gateway packages after dependency-plan validation")
	bootNetworkPolicy := flags.String("boot-network-policy", "", "boot network policy: gateway-nonblocking or keep")
	grubPolicy := flags.String("grub-policy", "", "GRUB policy: automatic-hidden, menu-5s, or keep")
	dependencyPreflightOnly := flags.Bool("dependency-preflight-only", false, "orchestrator-only read-only dependency gate that may defer APT index refresh to apply")
	apply := flags.Bool("apply", false, "apply after a successful read-only preflight")
	jsonOutput := flags.Bool("json", false, "emit final machine-readable result")
	manifestMaximumAge := flags.Duration("manifest-max-age", 0, "optional signed manifest freshness limit")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *interactive && (*lanInterface != "" || *lanAddress != "" || *enableDHCP || *installDependencies || *bootNetworkPolicy != "" || *grubPolicy != "" || *dependencyPreflightOnly || *apply || *jsonOutput) {
		fmt.Fprintln(os.Stderr, "--interactive chooses LAN, DHCP, dependencies, boot-network, GRUB, and apply confirmation itself; explicit installation policy flags are not allowed")
		return 2
	}
	if !*interactive && *managementPeer != "" {
		fmt.Fprintln(os.Stderr, "--management-peer is valid only with --interactive")
		return 2
	}
	if !*interactive && *lanInterface != "" && *lanAddress == "" {
		*lanAddress = "192.168.200.1/24"
	}
	if *dependencyPreflightOnly && (*apply || !*installDependencies) {
		fmt.Fprintln(os.Stderr, "--dependency-preflight-only requires --install-dependencies without --apply")
		return 2
	}
	if (*apply || *interactive) && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		fmt.Fprintln(os.Stderr, "Gateway apply/interactive installation requires Linux root after the bootstrap binary hash was verified externally")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var wizard *installwizard.Session
	var selection installwizard.Selection
	if *interactive {
		terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "interactive Gateway installation requires a real controlling terminal; use explicit flags for automation")
			return 1
		}
		defer terminal.Close()
		wizard, err = installwizard.NewSession(platformexec.OSExecutor{}, terminal, terminal)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		protectedPeer := *managementPeer
		if protectedPeer == "" {
			if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) == 4 {
				protectedPeer = fields[0]
			}
		}
		if protectedPeer != "" && !wizard.ProtectManagementPeer(protectedPeer) {
			fmt.Fprintln(os.Stderr, "invalid active management peer address")
			return 1
		}
		selection, err = wizard.Select(ctx)
		if err != nil {
			if errors.Is(err, installwizard.ErrCancelled) {
				fmt.Fprintln(terminal, "Gateway VPN installation cancelled; no persistent host changes were requested.")
				return 0
			}
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		*lanInterface = selection.LANInterface
		*lanAddress = selection.LANAddress
		*enableDHCP = selection.EnableDHCP
		*installDependencies = selection.InstallDependencies
		*bootNetworkPolicy = string(selection.BootNetworkPolicy)
		*grubPolicy = string(selection.GRUBPolicy)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	bootstrap := bootstrapinstall.Bootstrap{Downloader: bootstrapinstall.NewGitHubDownloader()}
	prepared, err := bootstrap.Prepare(ctx, bootstrapinstall.Request{
		Role: distribution.RoleGateway, Channel: *channel, Version: *version, SourceCommit: *commit,
		ManifestURL: *manifestURL, ManifestSHA256: *manifestSHA256,
		SignatureURL: *signatureURL, PublicKeyURL: *publicKeyURL, SignerKeySHA256: *signerKeySHA256,
		ArtifactBaseURL: *artifactBaseURL, OperatingSystem: "linux", Architecture: "amd64",
		ManifestMaximumAge: *manifestMaximumAge,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "independent bootstrap verification failed")
		return 1
	}
	defer prepared.Cleanup()
	installer := bootstrapinstall.Installer{Runner: bootstrapinstall.OSRunner{}, Bash: "/usr/bin/bash"}
	options := bootstrapinstall.GatewayOptions{
		LANInterface: *lanInterface, LANMembers: selection.LANMembers, LANAddress: *lanAddress, InstallDependencies: *installDependencies, EnableDHCP: *enableDHCP,
		BootNetworkPolicy: *bootNetworkPolicy, GRUBPolicy: *grubPolicy, Apply: *apply, DependencyPreflightOnly: *dependencyPreflightOnly,
	}
	if *interactive {
		dryRun := options
		dryRun.Apply = false
		dryRun.DependencyPreflightOnly = dryRun.InstallDependencies
		preflight, err := installer.InstallGateway(ctx, prepared, dryRun)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Gateway read-only preflight failed; no persistent host changes were requested")
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		confirmed, err := wizard.ConfirmApply(prepared.VerifiedRelease.Release.GatewayVersion, preflight.Preflight, selection)
		if err != nil {
			if errors.Is(err, installwizard.ErrCancelled) {
				fmt.Fprintln(os.Stderr, "Gateway VPN installation cancelled; no persistent host changes were requested.")
				return 0
			}
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if !confirmed {
			fmt.Fprintln(os.Stdout, "Gateway VPN installation cancelled; no persistent host changes were requested.")
			return 0
		}
		options.Apply = true
		options.DependencyPreflightOnly = false
	}
	result, err := installer.InstallGateway(ctx, prepared, options)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintln(os.Stderr, "Gateway bootstrap timed out")
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1
		}
		return 0
	}
	fmt.Printf("Gateway %s bootstrap: preflight=%s installation=%s signer=%s artifact=%s\n", result.Version, result.Preflight, result.Installation, result.SignerKeySHA256, result.ArtifactSHA256)
	return 0
}

func runInstallVPS(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-bootstrap install-vps", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	channel := flags.String("channel", "stable", "signed release channel")
	version := flags.String("release-version", "", "exact immutable Gateway VPN version")
	commit := flags.String("source-commit", "", "optional exact signed source commit")
	manifestURL := flags.String("manifest-url", "", "versioned channel manifest HTTPS URL")
	manifestSHA256 := flags.String("manifest-sha256", "", "expected raw channel manifest SHA-256")
	signatureURL := flags.String("signature-url", "", "detached channel signature HTTPS URL")
	publicKeyURL := flags.String("public-key-url", "", "trusted Ed25519 public key HTTPS URL")
	signerKeySHA256 := flags.String("signer-key-sha256", "", "expected Ed25519 public key fingerprint")
	artifactBaseURL := flags.String("artifact-base-url", "", "versioned GitHub Release URL ending in slash")
	publicEndpoint := flags.String("public-endpoint", "", "public VPS hostname or IPv4 with UDP port 51821")
	gatewayPublicKey := flags.String("gateway-public-key", "", "Gateway WireGuard public key")
	adminPublicKey := flags.String("admin-public-key", "", "administrator WireGuard public key")
	installDependencies := flags.Bool("install-dependencies", false, "install missing managed VPS packages after dependency-plan validation")
	dependencyPreflightOnly := flags.Bool("dependency-preflight-only", false, "orchestrator-only read-only dependency gate that may defer APT index refresh to apply")
	allowGatewaySSH := flags.Bool("allow-gateway-ssh", false, "forward administrator SSH to Gateway")
	apply := flags.Bool("apply", false, "apply after a successful read-only preflight")
	jsonOutput := flags.Bool("json", false, "emit final machine-readable result")
	manifestMaximumAge := flags.Duration("manifest-max-age", 0, "optional signed manifest freshness limit")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *dependencyPreflightOnly && (*apply || !*installDependencies) {
		fmt.Fprintln(os.Stderr, "--dependency-preflight-only requires --install-dependencies without --apply")
		return 2
	}
	if *apply && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		fmt.Fprintln(os.Stderr, "--apply requires Linux root after the bootstrap binary hash was verified externally")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	bootstrap := bootstrapinstall.Bootstrap{Downloader: bootstrapinstall.NewGitHubDownloader()}
	prepared, err := bootstrap.Prepare(ctx, bootstrapinstall.Request{
		Role: distribution.RoleVPS, Channel: *channel, Version: *version, SourceCommit: *commit,
		ManifestURL: *manifestURL, ManifestSHA256: *manifestSHA256,
		SignatureURL: *signatureURL, PublicKeyURL: *publicKeyURL, SignerKeySHA256: *signerKeySHA256,
		ArtifactBaseURL: *artifactBaseURL, OperatingSystem: "linux", Architecture: "amd64",
		ManifestMaximumAge: *manifestMaximumAge,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "independent VPS bootstrap verification failed")
		return 1
	}
	defer prepared.Cleanup()
	result, err := (bootstrapinstall.Installer{Runner: bootstrapinstall.OSRunner{}, Bash: "/usr/bin/bash"}).InstallVPS(ctx, prepared, bootstrapinstall.VPSOptions{
		PublicEndpoint: *publicEndpoint, GatewayPublicKey: *gatewayPublicKey, AdminPublicKey: *adminPublicKey,
		InstallDependencies: *installDependencies, AllowGatewaySSH: *allowGatewaySSH, Apply: *apply, DependencyPreflightOnly: *dependencyPreflightOnly,
	})
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintln(os.Stderr, "VPS bootstrap timed out")
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1
		}
		return 0
	}
	fmt.Printf("VPS %s bootstrap: preflight=%s installation=%s signer=%s artifact=%s\n", result.Version, result.Preflight, result.Installation, result.SignerKeySHA256, result.ArtifactSHA256)
	return 0
}

func usage(output *os.File) {
	fmt.Fprintln(output, "usage: gateway-vpn-bootstrap --version")
	fmt.Fprintln(output, "       gateway-vpn-bootstrap install-gateway --release-version VERSION --manifest-url HTTPS_URL --manifest-sha256 SHA256 --signature-url HTTPS_URL --public-key-url HTTPS_URL --signer-key-sha256 SHA256 --artifact-base-url HTTPS_URL/ --interactive")
	fmt.Fprintln(output, "       gateway-vpn-bootstrap install-gateway --release-version VERSION --manifest-url HTTPS_URL --manifest-sha256 SHA256 --signature-url HTTPS_URL --public-key-url HTTPS_URL --signer-key-sha256 SHA256 --artifact-base-url HTTPS_URL/ --lan-interface IFACE [--lan-address CIDR] [--install-dependencies] [--enable-dhcp] [--apply] [--json]")
	fmt.Fprintln(output, "       gateway-vpn-bootstrap install-vps --release-version VERSION --manifest-url HTTPS_URL --manifest-sha256 SHA256 --signature-url HTTPS_URL --public-key-url HTTPS_URL --signer-key-sha256 SHA256 --artifact-base-url HTTPS_URL/ --public-endpoint HOST:51821 --gateway-public-key KEY --admin-public-key KEY [--install-dependencies] [--allow-gateway-ssh] [--apply] [--json]")
}
