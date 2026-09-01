package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gateway-vpn/internal/mihomochannel"
	updatepkg "gateway-vpn/internal/update"
)

type compatibleGatewayVersions []string

func (values *compatibleGatewayVersions) String() string { return fmt.Sprint([]string(*values)) }
func (values *compatibleGatewayVersions) Set(value string) error {
	if updatepkg.ValidateGatewayVersion(value) != nil {
		return errors.New("compatible Gateway version must be strict SemVer")
	}
	*values = append(*values, value)
	return nil
}

func runMihomoChannelSign(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl mihomo-channel-sign", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	channel := flags.String("channel", "stable", "approved Mihomo channel")
	releaseDirectory := flags.String("release-dir", "", "verified signed Gateway release directory")
	artifactPath := flags.String("artifact", "", "full immutable Gateway release archive")
	commit := flags.String("source-commit", "", "exact source commit")
	generatedAt := flags.String("generated-at", "", "RFC3339 generation time; defaults to now")
	urgency := flags.String("urgency", "", "routine, recommended, or security")
	summary := flags.String("summary", "", "bounded human-readable maintenance summary")
	privateKeyPath := flags.String("private-key", "", "PKCS#8 Ed25519 private key path")
	outputDirectory := flags.String("output-dir", "", "existing directory for Mihomo channel files")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	var compatible compatibleGatewayVersions
	flags.Var(&compatible, "compatible-gateway-version", "exact tested installed Gateway version; repeatable")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *releaseDirectory == "" || *artifactPath == "" || *commit == "" || *urgency == "" || *summary == "" || *privateKeyPath == "" || *outputDirectory == "" || len(compatible) == 0 {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	generated := time.Now().UTC().Truncate(time.Second)
	if *generatedAt != "" {
		parsed, err := time.Parse(time.RFC3339, *generatedAt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid Mihomo channel generation time")
			return 2
		}
		generated = parsed.UTC()
	}
	privateKey, err := updatepkg.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load Mihomo channel signing key failed")
		return 1
	}
	release, artifact, err := verifiedMihomoMaintenanceInputs(*releaseDirectory, *artifactPath, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify Mihomo maintenance inputs: %v\n", err)
		return 1
	}
	if release.BuildCommit != *commit {
		fmt.Fprintln(os.Stderr, "Mihomo maintenance source commit does not match the signed Gateway release")
		return 1
	}
	manifest := mihomochannel.Manifest{
		FormatVersion: mihomochannel.FormatVersion, Kind: mihomochannel.Kind, Channel: *channel,
		GatewayReleaseVersion: release.GatewayVersion, MihomoVersion: release.MihomoVersion,
		CompatibleGatewayVersions: append([]string(nil), compatible...), OS: release.OS, Arch: release.Arch,
		HostContractSHA256: release.HostContractSHA256, GatewayAPIContract: release.GatewayAPIContract,
		MihomoAPIContract: release.MihomoAPIContract, GeneratedAt: generated.Format(time.RFC3339),
		SourceCommit: *commit, Urgency: *urgency, Summary: *summary, Artifact: artifact,
	}
	content, signature, err := mihomochannel.SignManifest(manifest, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign Mihomo channel manifest: %v\n", err)
		return 1
	}
	manifestPath, signaturePath, err := writeMihomoChannelPair(*outputDirectory, *channel, content, signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write signed Mihomo channel: %v\n", err)
		return 1
	}
	digest, _ := mihomochannel.ManifestSHA256(content)
	fingerprint, _ := updatepkg.PublicKeyFingerprint(privateKey.Public().(ed25519.PublicKey))
	result := map[string]any{"manifest": manifestPath, "signature": signaturePath, "manifest_sha256": digest, "signer_key_sha256": fingerprint, "gateway_version": release.GatewayVersion, "mihomo_version": release.MihomoVersion}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(result)
	} else {
		fmt.Printf("Signed Mihomo %s channel %s for Gateway release %s written; manifest SHA-256=%s\n", *channel, release.MihomoVersion, release.GatewayVersion, digest)
	}
	return 0
}

func runMihomoChannelVerify(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl mihomo-channel-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	manifestPath := flags.String("manifest", "", "signed Mihomo manifest")
	signaturePath := flags.String("signature", "", "detached Mihomo manifest signature")
	publicKeyPath := flags.String("public-key", "", "trusted Ed25519 public key")
	releaseDirectory := flags.String("release-dir", "", "signed Gateway release directory")
	artifactPath := flags.String("artifact", "", "full immutable Gateway release archive")
	channel := flags.String("channel", "", "expected Mihomo channel")
	version := flags.String("release-version", "", "expected accompanying Gateway release version")
	commit := flags.String("source-commit", "", "expected exact source commit")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *releaseDirectory == "" || *artifactPath == "" || *channel == "" || *version == "" || *commit == "" {
		return 2
	}
	content, err := readCommandFile(*manifestPath, mihomochannel.MaximumManifestBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read Mihomo channel manifest failed")
		return 1
	}
	signature, err := readCommandFile(*signaturePath, mihomochannel.MaximumSignatureBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read Mihomo channel signature failed")
		return 1
	}
	publicKey, err := updatepkg.LoadPublicKey(*publicKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load Mihomo channel public key failed")
		return 1
	}
	manifest, err := mihomochannel.VerifyManifest(content, signature, publicKey, mihomochannel.VerificationPolicy{
		ExpectedChannel: *channel, ExpectedGatewayReleaseVersion: *version, ExpectedSourceCommit: *commit,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify signed Mihomo channel: %v\n", err)
		return 1
	}
	release, artifact, err := verifiedMihomoMaintenanceInputs(*releaseDirectory, *artifactPath, publicKey)
	if err != nil || release.GatewayVersion != manifest.GatewayReleaseVersion || release.MihomoVersion != manifest.MihomoVersion || release.BuildCommit != manifest.SourceCommit || release.OS != manifest.OS || release.Arch != manifest.Arch || release.HostContractSHA256 != manifest.HostContractSHA256 || release.GatewayAPIContract != manifest.GatewayAPIContract || release.MihomoAPIContract != manifest.MihomoAPIContract || artifact != manifest.Artifact {
		fmt.Fprintln(os.Stderr, "Mihomo channel does not match the exact signed Gateway release and archive")
		return 1
	}
	digest, _ := mihomochannel.ManifestSHA256(content)
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"manifest_sha256": digest, "gateway_version": manifest.GatewayReleaseVersion, "mihomo_version": manifest.MihomoVersion, "compatible_gateway_versions": manifest.CompatibleGatewayVersions})
	} else {
		fmt.Printf("Signed Mihomo channel %s verified; Gateway=%s Mihomo=%s manifest=%s compatible=%d\n", manifest.Channel, manifest.GatewayReleaseVersion, manifest.MihomoVersion, digest, len(manifest.CompatibleGatewayVersions))
	}
	return 0
}

func verifiedMihomoMaintenanceInputs(releaseDirectory, artifactPath string, publicKey ed25519.PublicKey) (updatepkg.Release, mihomochannel.Artifact, error) {
	verified, err := updatepkg.VerifyRelease(releaseDirectory, updatepkg.VerificationPolicy{PublicKey: publicKey, ExpectedOS: "linux", ExpectedArch: "amd64", InitialInstall: true})
	if err != nil {
		return updatepkg.Release{}, mihomochannel.Artifact{}, err
	}
	artifact, err := mihomochannel.ArtifactFromFile(artifactPath, verified.Release.GatewayVersion)
	if err != nil {
		return updatepkg.Release{}, mihomochannel.Artifact{}, err
	}
	archivedRelease, err := verifyMihomoMaintenanceArchive(artifactPath, artifact, publicKey)
	if err != nil {
		return updatepkg.Release{}, mihomochannel.Artifact{}, err
	}
	if archivedRelease != verified.Release {
		return updatepkg.Release{}, mihomochannel.Artifact{}, errors.New("Mihomo maintenance archive does not contain the exact verified Gateway release")
	}
	return verified.Release, artifact, nil
}

func verifyMihomoMaintenanceArchive(artifactPath string, artifact mihomochannel.Artifact, publicKey ed25519.PublicKey) (updatepkg.Release, error) {
	info, err := os.Lstat(artifactPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != artifact.Bytes {
		return updatepkg.Release{}, errors.New("Mihomo maintenance archive input is unsafe")
	}
	source, err := os.Open(artifactPath)
	if err != nil {
		return updatepkg.Release{}, errors.New("open Mihomo maintenance archive failed")
	}
	openedInfo, statErr := source.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		_ = source.Close()
		return updatepkg.Release{}, errors.New("Mihomo maintenance archive changed before verification")
	}
	temporaryRoot, err := os.MkdirTemp("", "gateway-vpn-mihomo-channel-")
	if err != nil {
		_ = source.Close()
		return updatepkg.Release{}, errors.New("create private Mihomo archive verification directory failed")
	}
	defer os.RemoveAll(temporaryRoot)
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		_ = source.Close()
		return updatepkg.Release{}, errors.New("secure Mihomo archive verification directory failed")
	}
	privateArchivePath := filepath.Join(temporaryRoot, "release.tar.gz")
	privateArchive, err := os.OpenFile(privateArchivePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = source.Close()
		return updatepkg.Release{}, errors.New("create private Mihomo archive copy failed")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(privateArchive, hash), io.LimitReader(source, updatepkg.MaximumArchiveBytes+1))
	sourceCloseErr := source.Close()
	syncErr := privateArchive.Sync()
	if copyErr != nil || sourceCloseErr != nil || syncErr != nil || written != artifact.Bytes || written <= 0 || written > updatepkg.MaximumArchiveBytes || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		_ = privateArchive.Close()
		return updatepkg.Release{}, errors.New("Mihomo maintenance archive copy does not match its signed size and SHA-256")
	}
	if _, err := privateArchive.Seek(0, io.SeekStart); err != nil {
		_ = privateArchive.Close()
		return updatepkg.Release{}, errors.New("rewind private Mihomo archive copy failed")
	}
	extractedRoot := filepath.Join(temporaryRoot, "extracted")
	if err := os.Mkdir(extractedRoot, 0o700); err != nil {
		_ = privateArchive.Close()
		return updatepkg.Release{}, errors.New("create Mihomo archive extraction directory failed")
	}
	_, _, extractErr := updatepkg.ExtractReleaseArchive(context.Background(), privateArchive, extractedRoot)
	closeErr := privateArchive.Close()
	if extractErr != nil || closeErr != nil {
		return updatepkg.Release{}, errors.New("strict extraction of Mihomo maintenance archive failed")
	}
	verified, err := updatepkg.VerifyRelease(extractedRoot, updatepkg.VerificationPolicy{PublicKey: publicKey, ExpectedOS: "linux", ExpectedArch: "amd64", InitialInstall: true})
	if err != nil {
		return updatepkg.Release{}, errors.New("Mihomo maintenance archive does not contain a valid signed Gateway release")
	}
	return verified.Release, nil
}

func writeMihomoChannelPair(directory, channel string, content, signature []byte) (string, string, error) {
	if channel != "stable" && channel != "testing" || len(content) == 0 || int64(len(content)) > mihomochannel.MaximumManifestBytes || len(signature) == 0 || int64(len(signature)) > mihomochannel.MaximumSignatureBytes {
		return "", "", errors.New("bounded stable or testing Mihomo channel output is required")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return "", "", errors.New("resolve Mihomo channel output directory failed")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", errors.New("Mihomo channel output directory must be a real existing directory")
	}
	manifestPath := filepath.Join(directory, "mihomo-channel-"+channel+".json")
	signaturePath := filepath.Join(directory, "mihomo-channel-"+channel+".sig")
	for _, filename := range []string{manifestPath, signaturePath} {
		if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
			return "", "", errors.New("refuse to replace existing Mihomo channel output")
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
