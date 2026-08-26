package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"gateway-vpn/internal/endurance"
)

const releaseHardwareConfirmation = "REAL_GATEWAY_MODEMS_KEENETIC_VPS"

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("gateway-vpn-endurance", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	profileName := flags.String("profile", "smoke", "smoke, developer, or release")
	environmentName := flags.String("environment", string(endurance.EnvironmentDeveloperLinux), "developer-linux or hardware-gateway")
	endpoint := flags.String("endpoint", "", "Gateway VPN HTTPS origin")
	caCertificate := flags.String("ca-cert", "", "absolute trusted Gateway TLS certificate path")
	username := flags.String("username", "admin", "Gateway VPN administrator username")
	passwordFile := flags.String("password-file", "", "absolute root/user-owned 0600 credential file")
	outputParent := flags.String("output-parent", "", "absolute non-writable-by-group/other artifact parent")
	smokeDuration := flags.Duration("smoke-duration", 2*time.Minute, "smoke-only duration")
	smokeInterval := flags.Duration("smoke-interval", 10*time.Second, "smoke-only sample interval")
	hardwareConfirmation := flags.String("release-hardware-confirmation", "", "required exact confirmation for release profile")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "endurance harness requires Linux so credential ownership/mode and process metrics are enforceable")
		return 2
	}
	policy, err := selectPolicy(*profileName, *smokeDuration, *smokeInterval)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	environment := endurance.Environment(*environmentName)
	if environment != endurance.EnvironmentDeveloperLinux && environment != endurance.EnvironmentHardwareGateway {
		fmt.Fprintln(os.Stderr, "environment must be developer-linux or hardware-gateway")
		return 2
	}
	if policy.Profile == endurance.ProfileRelease && environment != endurance.EnvironmentHardwareGateway {
		fmt.Fprintln(os.Stderr, "release profile requires --environment=hardware-gateway")
		return 2
	}
	if policy.Profile == endurance.ProfileRelease && *hardwareConfirmation != releaseHardwareConfirmation {
		fmt.Fprintln(os.Stderr, "release profile requires --release-hardware-confirmation="+releaseHardwareConfirmation)
		return 2
	}
	if *endpoint == "" || !filepath.IsAbs(*caCertificate) || !filepath.IsAbs(*passwordFile) || !filepath.IsAbs(*outputParent) {
		fmt.Fprintln(os.Stderr, "endpoint and absolute ca-cert/password-file/output-parent are required")
		return 2
	}
	caPEM, err := readTrustedFile(*caCertificate, 1<<20, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	password, err := readTrustedFile(*passwordFile, 1026, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	password = trimCredentialNewline(password)
	client, err := endurance.NewAPIClient(*endpoint, caPEM, *username, password)
	for index := range password {
		password[index] = 0
	}
	password = nil
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	directory, err := endurance.CreateRunDirectory(*outputParent, policy.Profile, time.Now())
	if err != nil {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = client.Close(closeContext)
		cancel()
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	revision, modified := sourceIdentity()
	report, err := (endurance.Runner{Client: client, Policy: policy, Environment: environment, HarnessRevision: revision, HarnessModified: modified, OutputDirectory: directory}).Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "endurance run failed; artifacts: %s\n", directory)
		return 1
	}
	fmt.Printf("status=%s profile=%s environment=%s samples=%d artifacts=%s\n", report.Status, report.Evaluation.Profile, report.Environment, report.Evaluation.Samples, directory)
	if !report.Evaluation.Passed {
		return 3
	}
	return 0
}

func sourceIdentity() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", true
	}
	revision := ""
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = strings.ToLower(setting.Value)
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	return revision, modified
}

func selectPolicy(name string, smokeDuration, smokeInterval time.Duration) (endurance.EvaluationPolicy, error) {
	switch name {
	case "smoke":
		policy := endurance.SmokePolicy(smokeDuration, smokeInterval)
		return policy, policy.Validate()
	case "developer":
		return endurance.DeveloperPolicy(), nil
	case "release":
		return endurance.ReleasePolicy(), nil
	default:
		return endurance.EvaluationPolicy{}, errors.New("profile must be smoke, developer, or release")
	}
}

func readTrustedFile(path string, maximum int64, credential bool) ([]byte, error) {
	if !filepath.IsAbs(path) || maximum < 1 {
		return nil, errors.New("absolute bounded trusted file path is required")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("trusted file type or size is invalid")
	}
	if credential {
		if before.Mode().Perm() != 0o600 || !credentialOwnerOK(before) {
			return nil, errors.New("credential file must be single-link, owned by the current user, and mode 0600")
		}
	} else if before.Mode().Perm()&0o022 != 0 || !trustFileOwnerOK(before) {
		return nil, errors.New("TLS trust file owner or mode is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open trusted file failed")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("trusted file changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum {
		return nil, errors.New("read trusted file failed")
	}
	return content, nil
}

func trimCredentialNewline(content []byte) []byte {
	if len(content) != 0 && content[len(content)-1] == '\n' {
		content = content[:len(content)-1]
		if len(content) != 0 && content[len(content)-1] == '\r' {
			content = content[:len(content)-1]
		}
	}
	if strings.ContainsAny(string(content), "\r\n\x00") {
		return nil
	}
	return content
}
