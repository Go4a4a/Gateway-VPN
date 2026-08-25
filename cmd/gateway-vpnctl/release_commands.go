package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"gateway-vpn/internal/config"
	updatepkg "gateway-vpn/internal/update"
)

func runReleaseKeygen(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-keygen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	privateKey := flags.String("private-key", "", "new PKCS#8 Ed25519 private key path")
	publicKey := flags.String("public-key", "", "new PKIX Ed25519 public key path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *privateKey == "" || *publicKey == "" {
		return 2
	}
	fingerprint, err := updatepkg.WriteKeyPair(*privateKey, *publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate release signing identity: %v\n", err)
		return 1
	}
	fmt.Printf("Ed25519 release signing identity created; public key SHA-256=%s\n", fingerprint)
	return 0
}

func runReleaseSign(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-sign", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	releaseDir := flags.String("release-dir", "", "prepared immutable release directory")
	privateKeyPath := flags.String("private-key", "", "PKCS#8 Ed25519 private key path")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *releaseDir == "" || *privateKeyPath == "" {
		return 2
	}
	privateKey, err := updatepkg.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load release signing key failed")
		return 1
	}
	manifest, err := updatepkg.SignRelease(*releaseDir, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign release: %v\n", err)
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"signer_key_sha256": manifest.SignerKeySHA256, "release_json_sha256": manifest.ReleaseJSONSHA256, "file_count": len(manifest.Files)})
	} else {
		fmt.Printf("Release signed by Ed25519 key %s; files=%d\n", manifest.SignerKeySHA256, len(manifest.Files))
	}
	return 0
}

func runReleaseVerify(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	releaseDir := flags.String("release-dir", "", "signed release directory")
	publicKeyPath := flags.String("public-key", "", "trusted PKIX Ed25519 public key path")
	currentVersion := flags.String("current-version", "", "currently installed Gateway version")
	currentSchema := flags.Int64("current-schema", 0, "current SQLite schema")
	initialInstall := flags.Bool("initial-install", false, "verify as a first installation without an existing version or schema")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *releaseDir == "" || *publicKeyPath == "" ||
		!*initialInstall && (*currentVersion == "" || *currentSchema < 1) ||
		*initialInstall && (*currentVersion != "" || *currentSchema != 0) {
		return 2
	}
	publicKey, err := updatepkg.LoadPublicKey(*publicKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load trusted release key failed")
		return 1
	}
	expectedOS, expectedArch := runtime.GOOS, runtime.GOARCH
	// Release signing/inspection on a non-Linux administrative workstation
	// still verifies the target artifact contract, not the workstation target.
	if expectedOS != "linux" {
		expectedOS, expectedArch = "linux", "amd64"
	}
	verified, err := updatepkg.VerifyRelease(*releaseDir, updatepkg.VerificationPolicy{
		PublicKey: publicKey, ExpectedOS: expectedOS, ExpectedArch: expectedArch,
		CurrentGatewayVersion: *currentVersion, CurrentSchemaVersion: *currentSchema,
		InitialInstall:   *initialInstall,
		ConfigGeneration: config.CurrentVersion, GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed release: %v\n", err)
		return 1
	}
	result := map[string]any{
		"gateway_version": verified.Release.GatewayVersion, "mihomo_version": verified.Release.MihomoVersion,
		"signer_key_sha256": verified.Fingerprint, "file_count": len(verified.Manifest.Files),
		"database_schema_minimum": verified.Release.DatabaseSchemaMinimum, "database_schema_maximum": verified.Release.DatabaseSchemaMaximum,
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(result)
	} else {
		fmt.Printf("Signed release %s verified; signer=%s files=%d\n", verified.Release.GatewayVersion, verified.Fingerprint, len(verified.Manifest.Files))
	}
	return 0
}
