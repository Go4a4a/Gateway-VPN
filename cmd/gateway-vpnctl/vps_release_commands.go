package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/vpsrelease"
)

func runVPSReleaseSign(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl vps-release-sign", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	releaseDirectory := flags.String("release-dir", "", "prepared immutable VPS release directory")
	privateKeyPath := flags.String("private-key", "", "PKCS#8 Ed25519 private key path")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *releaseDirectory == "" || *privateKeyPath == "" {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	privateKey, err := updatepkg.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load VPS release signing key failed")
		return 1
	}
	manifest, err := vpsrelease.SignRelease(*releaseDirectory, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign VPS release: %v\n", err)
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"signer_key_sha256": manifest.SignerKeySHA256, "release_json_sha256": manifest.ReleaseJSONSHA256, "file_count": len(manifest.Files)})
	} else {
		fmt.Printf("VPS release signed by Ed25519 key %s; files=%d\n", manifest.SignerKeySHA256, len(manifest.Files))
	}
	return 0
}

func runVPSReleaseVerify(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl vps-release-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	releaseDirectory := flags.String("release-dir", "", "signed VPS release directory")
	publicKeyPath := flags.String("public-key", "", "trusted PKIX Ed25519 public key path")
	version := flags.String("release-version", "", "expected exact release version")
	profile := flags.String("profile", "", "optional expected OS profile")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *releaseDirectory == "" || *publicKeyPath == "" || *version == "" {
		return 2
	}
	publicKey, err := updatepkg.LoadPublicKey(*publicKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load trusted VPS release key failed")
		return 1
	}
	verified, err := vpsrelease.VerifyRelease(*releaseDirectory, vpsrelease.VerificationPolicy{
		PublicKey: publicKey, ExpectedVersion: *version, ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedProfile: *profile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed VPS release: %v\n", err)
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": verified.Release.Version, "role": verified.Release.Role, "signer_key_sha256": verified.Fingerprint, "profiles": verified.Release.SupportedProfiles, "file_count": len(verified.Manifest.Files)})
	} else {
		fmt.Printf("Signed VPS release %s verified; signer=%s files=%d\n", verified.Release.Version, verified.Fingerprint, len(verified.Manifest.Files))
	}
	return 0
}
