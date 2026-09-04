package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/distribution"
	"gateway-vpn/internal/installtopology"
)

const (
	StateReady             = "READY"
	StateInstalledNotReady = "INSTALLED_NOT_READY"
	StateFailed            = "FAILED"
)

type Request struct {
	Manifest             distribution.Manifest
	ManifestSHA256       string
	SignerKeySHA256      string
	Repository           string
	ReleaseTag           string
	Gateway              Host
	VPS                  Host
	LANInterface         string
	LANMembers           []string
	LANAddress           string
	InitialTopologyToken string
	EnableDHCP           bool
	PublicEndpoint       string
	AdminPublicKey       string
	AllowGatewaySSH      bool
	InstallDependencies  bool
	ReadinessAttempts    int
	ReadinessInterval    time.Duration
}

type Report struct {
	FormatVersion          int      `json:"format_version"`
	State                  string   `json:"state"`
	ReleaseVersion         string   `json:"release_version"`
	ManifestSHA256         string   `json:"manifest_sha256"`
	SignerKeySHA256        string   `json:"signer_key_sha256"`
	GatewayPreflight       string   `json:"gateway_preflight"`
	VPSPreflight           string   `json:"vps_preflight"`
	GatewayInstallation    string   `json:"gateway_installation"`
	VPSInstallation        string   `json:"vps_installation"`
	WireGuardConfigured    bool     `json:"wireguard_configured"`
	WireGuardHandshake     bool     `json:"wireguard_handshake"`
	InternetPathActive     bool     `json:"internet_path_active"`
	GatewayPublicKeySHA256 string   `json:"gateway_public_key_sha256,omitempty"`
	VPSPublicKeySHA256     string   `json:"vps_public_key_sha256,omitempty"`
	AdminConfigState       string   `json:"admin_config_state"`
	WebUIURL               string   `json:"web_ui_url,omitempty"`
	FailurePhase           string   `json:"failure_phase,omitempty"`
	DiagnosticCodes        []string `json:"diagnostic_codes"`
	VPSPublicKey           string   `json:"-"`
}

type Orchestrator struct {
	Executor RemoteExecutor
	Now      func() time.Time
	Sleep    func(context.Context, time.Duration) error
}

type phaseError struct {
	phase string
	cause error
}

func (err phaseError) Error() string { return err.phase + " failed: " + err.cause.Error() }
func (err phaseError) Unwrap() error { return err.cause }

func (orchestrator Orchestrator) Run(ctx context.Context, request Request) (Report, error) {
	report := Report{
		FormatVersion: 1, State: StateFailed, ReleaseVersion: request.Manifest.ReleaseVersion,
		ManifestSHA256: request.ManifestSHA256, SignerKeySHA256: request.SignerKeySHA256,
		GatewayPreflight: "NOT_RUN", VPSPreflight: "NOT_RUN",
		GatewayInstallation: "NOT_RUN", VPSInstallation: "NOT_RUN", DiagnosticCodes: []string{},
	}
	if err := validateRequest(request); err != nil {
		report.FailurePhase = "LOCAL_VALIDATION"
		report.DiagnosticCodes = append(report.DiagnosticCodes, "DEPLOY_INPUT_INVALID")
		return report, phaseError{phase: report.FailurePhase, cause: err}
	}
	if orchestrator.Executor == nil {
		report.FailurePhase = "LOCAL_VALIDATION"
		return report, phaseError{phase: report.FailurePhase, cause: errors.New("remote executor is required")}
	}
	if orchestrator.Now == nil {
		orchestrator.Now = time.Now
	}
	if orchestrator.Sleep == nil {
		orchestrator.Sleep = sleepContext
	}

	if err := orchestrator.runPhase(ctx, request.Gateway, "GATEWAY_SSH_PREFLIGHT", sshPrerequisiteCommand); err != nil {
		return failReport(report, "GATEWAY_SSH_PREFLIGHT", "GATEWAY_SSH_PREFLIGHT_FAILED", err)
	}
	if err := orchestrator.runPhase(ctx, request.VPS, "VPS_SSH_PREFLIGHT", sshPrerequisiteCommand); err != nil {
		return failReport(report, "VPS_SSH_PREFLIGHT", "VPS_SSH_PREFLIGHT_FAILED", err)
	}

	preflightGatewayKey := deployPlaceholderKey(1)
	if preflightGatewayKey == request.AdminPublicKey {
		preflightGatewayKey = deployPlaceholderKey(3)
	}
	// A clean host does not have this command yet. An already installed or
	// interrupted host can expose its public identity read-only so the initial
	// VPS preflight remains idempotent without creating new key material.
	if inspectedResult, inspectErr := orchestrator.Executor.Run(ctx, request.Gateway, gatewayInspectKeyCommand); inspectErr == nil {
		if inspected, decodeErr := decodeDeployKeyInspection(inspectedResult.Stdout); decodeErr == nil && inspected.PublicKey != "" {
			preflightGatewayKey = inspected.PublicKey
		}
	}
	gatewayPreflight, err := gatewayCommand(request, false)
	if err != nil {
		return failReport(report, "GATEWAY_COMMAND_BUILD", "SIGNED_COMMAND_INVALID", err)
	}
	vpsPreflight, err := vpsCommand(request, preflightGatewayKey, false)
	if err != nil {
		return failReport(report, "VPS_COMMAND_BUILD", "SIGNED_COMMAND_INVALID", err)
	}
	// Both role preflights complete before either host is mutated.
	gatewayPreflightErr := orchestrator.runPhase(ctx, request.Gateway, "GATEWAY_ROLE_PREFLIGHT", gatewayPreflight)
	if gatewayPreflightErr == nil {
		report.GatewayPreflight = dependencyGateState(request.InstallDependencies)
	}
	vpsPreflightErr := orchestrator.runPhase(ctx, request.VPS, "VPS_ROLE_PREFLIGHT", vpsPreflight)
	if vpsPreflightErr == nil {
		report.VPSPreflight = dependencyGateState(request.InstallDependencies)
	}
	if gatewayPreflightErr != nil {
		return failReport(report, "GATEWAY_ROLE_PREFLIGHT", "GATEWAY_ROLE_PREFLIGHT_FAILED", gatewayPreflightErr)
	}
	if vpsPreflightErr != nil {
		return failReport(report, "VPS_ROLE_PREFLIGHT", "VPS_ROLE_PREFLIGHT_FAILED", vpsPreflightErr)
	}

	gatewayApply, _ := gatewayCommand(request, true)
	if err := orchestrator.runPhase(ctx, request.Gateway, "GATEWAY_INSTALL", gatewayApply); err != nil {
		return failReport(report, "GATEWAY_INSTALL", "GATEWAY_INSTALL_FAILED", err)
	}
	report.GatewayInstallation = "APPLIED"

	preparedResult, err := orchestrator.Executor.Run(ctx, request.Gateway, gatewayPrepareKeyCommand)
	if err != nil {
		return failReport(report, "GATEWAY_KEY_PREPARE", "GATEWAY_KEY_PREPARE_FAILED", err)
	}
	prepared, err := decodeDeployKeyState(preparedResult.Stdout)
	if err != nil {
		return failReport(report, "GATEWAY_KEY_PREPARE", "GATEWAY_KEY_RESPONSE_INVALID", err)
	}
	report.GatewayPublicKeySHA256 = publicKeyFingerprint(prepared.PublicKey)

	// Re-run the VPS preflight with the exact Gateway public key. This catches
	// resume/config conflicts without ever sending the Gateway private key.
	vpsExactPreflight, err := vpsCommand(request, prepared.PublicKey, false)
	if err != nil {
		return failReport(report, "VPS_EXACT_PREFLIGHT", "SIGNED_COMMAND_INVALID", err)
	}
	if err := orchestrator.runPhase(ctx, request.VPS, "VPS_EXACT_PREFLIGHT", vpsExactPreflight); err != nil {
		return failReport(report, "VPS_EXACT_PREFLIGHT", "VPS_EXACT_PREFLIGHT_FAILED", err)
	}
	vpsApply, _ := vpsCommand(request, prepared.PublicKey, true)
	if err := orchestrator.runPhase(ctx, request.VPS, "VPS_INSTALL", vpsApply); err != nil {
		return failReport(report, "VPS_INSTALL", "VPS_INSTALL_FAILED", err)
	}
	report.VPSInstallation = "APPLIED"

	vpsReportResult, err := orchestrator.Executor.Run(ctx, request.VPS, vpsInstallReportCommand)
	if err != nil {
		return failReport(report, "VPS_REPORT", "VPS_REPORT_UNAVAILABLE", err)
	}
	vpsPublicKey, err := decodeVPSPublicKey(vpsReportResult.Stdout, request)
	if err != nil {
		return failReport(report, "VPS_REPORT", "VPS_REPORT_INVALID", err)
	}
	report.VPSPublicKeySHA256 = publicKeyFingerprint(vpsPublicKey)
	report.VPSPublicKey = vpsPublicKey

	finalizeCommand := gatewayFinalizeKeyCommand(request.PublicEndpoint, vpsPublicKey)
	finalizeResult, err := orchestrator.Executor.Run(ctx, request.Gateway, finalizeCommand)
	if err != nil {
		return failReport(report, "GATEWAY_KEY_FINALIZE", "GATEWAY_KEY_FINALIZE_FAILED", err)
	}
	finalized, err := decodeDeployKeyState(finalizeResult.Stdout)
	if err != nil || finalized.State != "CONFIGURED" || finalized.PublicKey != prepared.PublicKey {
		if err == nil {
			err = errors.New("finalized Gateway public key does not match prepared identity")
		}
		return failReport(report, "GATEWAY_KEY_FINALIZE", "GATEWAY_KEY_FINALIZE_INVALID", err)
	}
	report.WireGuardConfigured = true

	if err := orchestrator.runPhase(ctx, request.Gateway, "GATEWAY_BASE_READINESS", gatewayBaseReadinessCommand(request.LANAddress)); err != nil {
		return failReport(report, "GATEWAY_BASE_READINESS", "GATEWAY_BASE_READINESS_FAILED", err)
	}
	if err := orchestrator.runPhase(ctx, request.VPS, "VPS_BASE_READINESS", vpsBaseReadinessCommand); err != nil {
		return failReport(report, "VPS_BASE_READINESS", "VPS_BASE_READINESS_FAILED", err)
	}
	prefix, _ := netip.ParsePrefix(request.LANAddress)
	report.WebUIURL = "https://" + prefix.Addr().String() + ":8443/"

	for attempt := 0; attempt < request.ReadinessAttempts; attempt++ {
		handshakeResult, handshakeErr := orchestrator.Executor.Run(ctx, request.Gateway, gatewayHandshakeCommand)
		if handshakeErr == nil && recentExpectedHandshake(handshakeResult.Stdout, vpsPublicKey, orchestrator.Now().UTC()) {
			report.WireGuardHandshake = true
		}
		statusResult, statusErr := orchestrator.Executor.Run(ctx, request.Gateway, gatewayRuntimeStatusCommand)
		if statusErr == nil && activeInternetPath(statusResult.Stdout) {
			report.InternetPathActive = true
		}
		if report.WireGuardHandshake && report.InternetPathActive {
			report.State = StateReady
			return report, nil
		}
		if attempt+1 < request.ReadinessAttempts {
			if err := orchestrator.Sleep(ctx, request.ReadinessInterval); err != nil {
				return failReport(report, "READINESS_WAIT", "DEPLOY_INTERRUPTED", err)
			}
		}
	}
	report.State = StateInstalledNotReady
	if !report.WireGuardHandshake {
		report.DiagnosticCodes = append(report.DiagnosticCodes, "WIREGUARD_HANDSHAKE_PENDING")
	}
	if !report.InternetPathActive {
		report.DiagnosticCodes = append(report.DiagnosticCodes, "MODEM_SUBSCRIPTION_PATH_PENDING")
	}
	return report, nil
}

func validateRequest(request Request) error {
	if err := distribution.ValidateManifest(request.Manifest); err != nil {
		return err
	}
	if _, err := distribution.SelectArtifact(request.Manifest, distribution.RoleDeploy, "linux", "amd64"); err != nil {
		return err
	}
	if request.ManifestSHA256 == "" || request.SignerKeySHA256 != request.Manifest.SignerKeySHA256 || sameSSHEndpoint(request.Gateway, request.VPS) {
		return errors.New("exact signed deploy identity and distinct SSH destinations are required")
	}
	if err := ValidateHost(request.Gateway); err != nil {
		return fmt.Errorf("Gateway host: %w", err)
	}
	if err := ValidateHost(request.VPS); err != nil {
		return fmt.Errorf("VPS host: %w", err)
	}
	if !validPublicKey(request.AdminPublicKey) || request.ReadinessAttempts < 1 || request.ReadinessAttempts > 60 || request.ReadinessInterval < 0 || request.ReadinessInterval > time.Minute {
		return errors.New("admin public key or readiness policy is invalid")
	}
	plan, err := installtopology.DecodeToken(request.InitialTopologyToken)
	if err != nil || installtopology.ValidateInstallerBinding(plan, request.LANInterface, request.LANMembers) != nil {
		return errors.New("deploy initial topology does not match the supported Gateway LAN action")
	}
	if _, err := gatewayCommand(request, false); err != nil {
		return err
	}
	placeholder := deployPlaceholderKey(1)
	if placeholder == request.AdminPublicKey {
		placeholder = deployPlaceholderKey(3)
	}
	if _, err := vpsCommand(request, placeholder, false); err != nil {
		return err
	}
	return nil
}

func sameSSHEndpoint(left, right Host) bool {
	if left.Port != right.Port {
		return false
	}
	return strings.EqualFold(sshDestinationHost(left.Destination), sshDestinationHost(right.Destination))
}

func sshDestinationHost(value string) string {
	if _, host, found := strings.Cut(value, "@"); found {
		return strings.TrimSuffix(host, ".")
	}
	return strings.TrimSuffix(value, ".")
}

func gatewayCommand(request Request, apply bool) (string, error) {
	return distribution.GatewayInstallCommand(request.Manifest, distribution.GatewayInstallCommandOptions{
		Repository: request.Repository, ReleaseTag: request.ReleaseTag,
		ManifestSHA256: request.ManifestSHA256, SignerKeySHA256: request.SignerKeySHA256,
		LANInterface: request.LANInterface, LANMembers: request.LANMembers, LANAddress: request.LANAddress, InitialTopologyToken: request.InitialTopologyToken,
		InstallDependencies: request.InstallDependencies, EnableDHCP: request.EnableDHCP,
		BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "keep",
		Apply: apply, NonInteractiveRoot: true, DependencyPreflightOnly: request.InstallDependencies && !apply,
	})
}

func vpsCommand(request Request, gatewayPublicKey string, apply bool) (string, error) {
	return distribution.VPSInstallCommand(request.Manifest, distribution.VPSInstallCommandOptions{
		Repository: request.Repository, ReleaseTag: request.ReleaseTag,
		ManifestSHA256: request.ManifestSHA256, SignerKeySHA256: request.SignerKeySHA256,
		PublicEndpoint: request.PublicEndpoint, GatewayPublicKey: gatewayPublicKey,
		AdminPublicKey: request.AdminPublicKey, InstallDependencies: request.InstallDependencies,
		AllowGatewaySSH: request.AllowGatewaySSH, Apply: apply, NonInteractiveRoot: true,
		DependencyPreflightOnly: request.InstallDependencies && !apply,
	})
}

func dependencyGateState(installDependencies bool) string {
	if installDependencies {
		return "DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED"
	}
	return "PASSED"
}

func (orchestrator Orchestrator) runPhase(ctx context.Context, host Host, phase, command string) error {
	_, err := orchestrator.Executor.Run(ctx, host, command)
	if err != nil {
		return phaseError{phase: phase, cause: err}
	}
	return nil
}

func failReport(report Report, phase, code string, err error) (Report, error) {
	report.State = StateFailed
	report.FailurePhase = phase
	report.DiagnosticCodes = append(report.DiagnosticCodes, code)
	var diagnostic interface{ DiagnosticCode() string }
	if errors.As(err, &diagnostic) {
		if detail := diagnostic.DiagnosticCode(); detail != "" && detail != code {
			report.DiagnosticCodes = append(report.DiagnosticCodes, detail)
		}
	}
	return report, phaseError{phase: phase, cause: err}
}

type deployKeyResponse struct {
	State     string `json:"state"`
	PublicKey string `json:"public_key"`
}

func decodeDeployKeyState(content []byte) (deployKeyResponse, error) {
	var result deployKeyResponse
	if err := decodeStrictBounded(content, 4096, &result); err != nil || (result.State != "PENDING" && result.State != "CONFIGURED") || !validPublicKey(result.PublicKey) {
		return deployKeyResponse{}, errors.New("Gateway deploy key response is invalid")
	}
	return result, nil
}

func decodeDeployKeyInspection(content []byte) (deployKeyResponse, error) {
	var result deployKeyResponse
	if err := decodeStrictBounded(content, 4096, &result); err != nil {
		return deployKeyResponse{}, errors.New("Gateway deploy key inspection is invalid")
	}
	if result.State == "UNCONFIGURED" && result.PublicKey == "" {
		return result, nil
	}
	if (result.State == "PENDING" || result.State == "CONFIGURED") && validPublicKey(result.PublicKey) {
		return result, nil
	}
	return deployKeyResponse{}, errors.New("Gateway deploy key inspection is invalid")
}

type vpsInstallReport struct {
	Version        string `json:"version"`
	Profile        string `json:"profile"`
	PublicEndpoint string `json:"public_endpoint"`
	Interface      string `json:"interface"`
	VPSAddress     string `json:"vps_address"`
	GatewayAddress string `json:"gateway_address"`
	AdminAddress   string `json:"admin_address"`
	VPSPublicKey   string `json:"vps_public_key"`
	State          string `json:"state"`
}

func decodeVPSPublicKey(content []byte, request Request) (string, error) {
	var report vpsInstallReport
	if err := decodeStrictBounded(content, 16*1024, &report); err != nil || report.Version != request.Manifest.ReleaseVersion || report.PublicEndpoint != request.PublicEndpoint || report.Interface != "wg-mgmt" || report.VPSAddress != "10.80.0.1/24" || report.GatewayAddress != "10.80.0.2/32" || report.AdminAddress != "10.80.0.10/32" || report.State != StateInstalledNotReady || !validPublicKey(report.VPSPublicKey) {
		return "", errors.New("VPS installation report identity is invalid")
	}
	return report.VPSPublicKey, nil
}

func decodeStrictBounded(content []byte, maximum int, destination any) error {
	if len(content) == 0 || len(content) > maximum {
		return errors.New("bounded JSON response is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("JSON response has trailing data")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON response has trailing or malformed data")
	}
	return nil
}

func recentExpectedHandshake(content []byte, expectedPublicKey string, now time.Time) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != expectedPublicKey {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || seconds <= 0 {
			return false
		}
		handshake := time.Unix(seconds, 0).UTC()
		return !handshake.After(now.Add(5*time.Minute)) && now.Sub(handshake) <= 3*time.Minute
	}
	return false
}

func activeInternetPath(content []byte) bool {
	if len(content) == 0 || len(content) > 256*1024 {
		return false
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(content, &response); err != nil || len(response) != 2 {
		return false
	}
	if _, exists := response["paths"]; !exists {
		return false
	}
	var runtimeState map[string]json.RawMessage
	if err := json.Unmarshal(response["runtime"], &runtimeState); err != nil {
		return false
	}
	var gatewayState, pathState string
	if err := json.Unmarshal(runtimeState["GatewayState"], &gatewayState); err != nil {
		return false
	}
	if err := json.Unmarshal(runtimeState["PathState"], &pathState); err != nil {
		return false
	}
	return pathState == "PATH_ACTIVE" && (gatewayState == "ACTIVE" || gatewayState == "DEGRADED_TARGET")
}

func validPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func publicKeyFingerprint(value string) string {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(decoded)
	return hex.EncodeToString(digest[:])
}

func deployPlaceholderKey(seed byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func gatewayFinalizeKeyCommand(endpoint, peerPublicKey string) string {
	return "sudo -n -u gateway-vpn -- /opt/gateway-vpn/current/bin/gateway-vpnctl deploy-wireguard-finalize --endpoint " + endpoint + " --peer-public-key " + peerPublicKey + " --persistent-keepalive 25 --handshake-timeout 45 --json"
}

func gatewayBaseReadinessCommand(lanAddress string) string {
	prefix, _ := netip.ParsePrefix(lanAddress)
	url := "https://" + prefix.Addr().String() + ":8443/"
	return "sudo -n -- /usr/bin/test -f /var/lib/gateway-vpn/secrets/wireguard.yaml && sudo -n -- /usr/bin/systemctl is-active --quiet gateway-vpn.service && sudo -n -- /usr/bin/systemctl is-active --quiet gateway-vpn-watchdog.service && sudo -n -- /usr/bin/test -f /run/gateway-vpn-watchdog/status.json && sudo -n -- /usr/bin/test -f /run/gateway-vpn-watchdog/control.json && sudo -n -- /usr/bin/systemctl is-active --quiet gateway-vpn-firewall.service && sudo -n -- /usr/sbin/nft list table inet gateway_vpn >/dev/null && if command -v curl >/dev/null 2>&1; then curl --fail --silent --show-error --insecure --max-time 5 " + url + " >/dev/null; else wget --quiet --no-check-certificate --timeout=5 --spider " + url + "; fi"
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const (
	sshPrerequisiteCommand      = "test -x /usr/bin/bash && test -x /usr/bin/sudo && test \"$(uname -m)\" = x86_64 && sudo -n true"
	gatewayInspectKeyCommand    = "sudo -n -u gateway-vpn -- /opt/gateway-vpn/current/bin/gateway-vpnctl deploy-wireguard-inspect --json"
	gatewayPrepareKeyCommand    = "sudo -n -u gateway-vpn -- /opt/gateway-vpn/current/bin/gateway-vpnctl deploy-wireguard-prepare --json"
	vpsInstallReportCommand     = "sudo -n -- /usr/bin/cat /var/lib/gateway-vpn-vps/install-report.json"
	vpsBaseReadinessCommand     = "sudo -n -- /usr/bin/systemctl is-active --quiet gateway-vpn-vps-firewall.service && sudo -n -- /usr/bin/systemctl is-active --quiet wg-quick@wg-mgmt.service && sudo -n -- /usr/sbin/nft list table inet gateway_vpn_vps >/dev/null && sudo -n -- /usr/bin/wg show wg-mgmt listen-port | grep -Fxq 51821"
	gatewayHandshakeCommand     = "sudo -n -- /usr/bin/wg show wg-mgmt latest-handshakes"
	gatewayRuntimeStatusCommand = "sudo -n -u gateway-vpn -- /opt/gateway-vpn/current/bin/gateway-vpnctl status --json"
)
