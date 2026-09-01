// Command prepare-windows-targets creates two fresh, SSH-only Ubuntu systemd
// containers for the clean Windows deployment release gate. It is source-only
// test tooling: it is not packaged or installed by Gateway VPN.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	releaseGateEnvironment = "GATEWAY_VPN_RELEASE_GATE"
	defaultImage           = "gateway-vpn-systemd-rehearsal:ubuntu24-751669c"
	maximumCommandOutput   = 256 * 1024
	operationTimeout       = 2 * time.Minute
	windowsDocker          = `C:\Program Files\Docker\Docker\resources\bin\docker.exe`
	windowsSSH             = `C:\Windows\System32\OpenSSH\ssh.exe`
	windowsSSHKeygen       = `C:\Windows\System32\OpenSSH\ssh-keygen.exe`
)

var (
	runIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,19}$`)
	imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}:[a-z0-9][a-z0-9._-]{0,63}$`)
)

type options struct {
	releaseGateOnly bool
	apply           bool
	image           string
	runID           string
	listenAddress   string
	gatewayPort     int
	vpsPort         int
	identityPath    string
	evidenceDir     string
}

type targetNames struct {
	Role          string
	Stage         string
	Final         string
	PreparedImage string
	Port          int
}

type targetEvidence struct {
	Role             string `json:"role"`
	Container        string `json:"container"`
	ContainerID      string `json:"container_id"`
	PreparedImage    string `json:"prepared_image"`
	PreparedImageID  string `json:"prepared_image_id"`
	SSHAddress       string `json:"ssh_address"`
	SSHPort          int    `json:"ssh_port"`
	SSHHostKeySHA256 string `json:"ssh_host_key_sha256"`
}

type evidence struct {
	FormatVersion        int              `json:"format_version"`
	CreatedAt            string           `json:"created_at"`
	RunID                string           `json:"run_id"`
	BaseImage            string           `json:"base_image"`
	BaseImageID          string           `json:"base_image_id"`
	DockerExecutable     string           `json:"docker_executable"`
	DockerSHA256         string           `json:"docker_sha256"`
	OpenSSHExecutable    string           `json:"openssh_executable"`
	OpenSSHSHA256        string           `json:"openssh_sha256"`
	IdentityPublicSHA256 string           `json:"identity_public_sha256"`
	KnownHostsSHA256     string           `json:"known_hosts_sha256"`
	Targets              []targetEvidence `json:"targets"`
}

type dockerClient struct {
	executable string
}

type commandResult struct {
	stdout []byte
	stderr []byte
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare-windows-targets", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var settings options
	flags.BoolVar(&settings.releaseGateOnly, "release-gate-only", false, "acknowledge source-only release-gate tooling")
	flags.BoolVar(&settings.apply, "apply", false, "create and start the guarded disposable targets")
	flags.StringVar(&settings.image, "image", defaultImage, "existing exact local Ubuntu systemd image; never pulled")
	flags.StringVar(&settings.runID, "run-id", "", "unique lowercase release-gate run identifier")
	flags.StringVar(&settings.listenAddress, "listen-address", "", "exact assigned host IPv4 address; wildcard binding is forbidden")
	flags.IntVar(&settings.gatewayPort, "gateway-port", 0, "host TCP port mapped to clean Gateway SSH")
	flags.IntVar(&settings.vpsPort, "vps-port", 0, "host TCP port mapped to clean VPS SSH")
	flags.StringVar(&settings.identityPath, "identity", "", "absolute disposable Windows OpenSSH private-key path")
	flags.StringVar(&settings.evidenceDir, "evidence-dir", "", "absolute new directory for non-secret gate evidence")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if os.Getenv(releaseGateEnvironment) != "1" || !settings.releaseGateOnly {
		fmt.Fprintln(stderr, "prepare-windows-targets requires GATEWAY_VPN_RELEASE_GATE=1 and --release-gate-only")
		return 2
	}
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(stderr, "prepare-windows-targets must run on the Windows 10/11 x64 Docker host serving the clean guest")
		return 1
	}
	validated, err := validateOptions(settings)
	if err != nil {
		fmt.Fprintf(stderr, "validate target plan: %v\n", err)
		return 2
	}
	client, dockerPath, err := newDockerClient()
	if err != nil {
		fmt.Fprintf(stderr, "locate Docker CLI: %v\n", err)
		return 1
	}
	publicKey, err := deriveIdentityPublicKey(validated.identityPath)
	if err != nil {
		fmt.Fprintf(stderr, "derive disposable public key: %v\n", err)
		return 1
	}
	plan, err := preflight(client, validated, publicKey)
	if err != nil {
		fmt.Fprintf(stderr, "read-only target preflight: %v\n", err)
		return 1
	}
	plan["docker_executable"] = dockerPath
	plan["apply"] = validated.apply
	if !validated.apply {
		if err := json.NewEncoder(stdout).Encode(plan); err != nil {
			return 1
		}
		return 0
	}
	result, err := applyTargets(client, validated, publicKey, plan["base_image_id"].(string))
	if err != nil {
		fmt.Fprintf(stderr, "prepare clean Windows targets: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

func validateOptions(value options) (options, error) {
	if !runIDPattern.MatchString(value.runID) {
		return options{}, errors.New("run-id must be 1..20 lowercase letters, digits, or internal hyphens")
	}
	if !imagePattern.MatchString(value.image) || strings.HasSuffix(value.image, ":latest") || strings.Contains(value.image, "..") {
		return options{}, errors.New("an exact safe local image tag is required; latest and digest-less names are forbidden")
	}
	address := net.ParseIP(value.listenAddress)
	if address == nil || address.To4() == nil || address.IsUnspecified() || address.IsMulticast() || value.listenAddress == "255.255.255.255" {
		return options{}, errors.New("listen-address must be one exact non-wildcard IPv4 address")
	}
	if value.gatewayPort < 1024 || value.gatewayPort > 65535 || value.vpsPort < 1024 || value.vpsPort > 65535 || value.gatewayPort == value.vpsPort {
		return options{}, errors.New("two distinct unprivileged TCP ports are required")
	}
	for label, path := range map[string]string{"identity": value.identityPath, "evidence parent": filepath.Dir(value.evidenceDir)} {
		if path == "" || !filepath.IsAbs(path) {
			return options{}, fmt.Errorf("%s path must be absolute", label)
		}
	}
	if err := validateRegularFile(value.identityPath, 64*1024); err != nil {
		return options{}, fmt.Errorf("identity file: %w", err)
	}
	if info, err := os.Lstat(filepath.Dir(value.evidenceDir)); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return options{}, errors.New("evidence parent must be an existing non-symlink directory")
	}
	if _, err := os.Lstat(value.evidenceDir); !os.IsNotExist(err) {
		return options{}, errors.New("evidence directory must not already exist")
	}
	if err := requireAssignedAddress(value.listenAddress); err != nil {
		return options{}, err
	}
	for _, port := range []int{value.gatewayPort, value.vpsPort} {
		if err := requireAvailablePort(value.listenAddress, port); err != nil {
			return options{}, err
		}
	}
	for _, executable := range []string{windowsSSH, windowsSSHKeygen} {
		if err := validateRegularFile(executable, 16*1024*1024); err != nil {
			return options{}, fmt.Errorf("fixed Windows OpenSSH executable %s: %w", filepath.Base(executable), err)
		}
	}
	return value, nil
}

func requireAssignedAddress(expected string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("enumerate host network interfaces failed")
	}
	for _, networkInterface := range interfaces {
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			value, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && value.String() == expected {
				return nil
			}
		}
	}
	return errors.New("listen-address is not currently assigned to this Windows host")
}

func requireAvailablePort(address string, port int) error {
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("TCP port %d is unavailable on the exact listen address", port)
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("release temporary TCP port probe %d failed", port)
	}
	return nil
}

func validateRegularFile(path string, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return errors.New("a bounded regular non-symlink file is required")
	}
	return nil
}

func newDockerClient() (dockerClient, string, error) {
	if err := validateRegularFile(windowsDocker, 256*1024*1024); err != nil {
		return dockerClient{}, "", err
	}
	return dockerClient{executable: windowsDocker}, windowsDocker, nil
}

func deriveIdentityPublicKey(identity string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, windowsSSHKeygen, "-y", "-f", identity)
	command.Env = windowsCommandEnvironment()
	var stdout, stderr bytes.Buffer
	command.Stdout = &limitedWriter{writer: &stdout, remaining: 4096}
	command.Stderr = &limitedWriter{writer: &stderr, remaining: 4096}
	if err := command.Run(); err != nil {
		return "", errors.New("fixed ssh-keygen rejected the identity; use a dedicated unencrypted gate key")
	}
	return normalizeEd25519PublicKey(stdout.String())
}

func normalizeEd25519PublicKey(value string) (string, error) {
	if strings.HasSuffix(value, "\r\n") {
		value = strings.TrimSuffix(value, "\r\n")
	} else if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("public key has invalid framing")
	}
	fields := strings.Fields(value)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return "", errors.New("a disposable Ed25519 OpenSSH identity is required")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	if err != nil || !validEd25519WireKey(payload) {
		return "", errors.New("Ed25519 public key payload is invalid")
	}
	return "ssh-ed25519 " + fields[1], nil
}

func validEd25519WireKey(payload []byte) bool {
	readField := func(input []byte) ([]byte, []byte, bool) {
		if len(input) < 4 {
			return nil, nil, false
		}
		length := int(binary.BigEndian.Uint32(input[:4]))
		if length < 0 || length > len(input)-4 {
			return nil, nil, false
		}
		return input[4 : 4+length], input[4+length:], true
	}
	typeName, rest, ok := readField(payload)
	if !ok || string(typeName) != "ssh-ed25519" {
		return false
	}
	key, rest, ok := readField(rest)
	return ok && len(key) == 32 && len(rest) == 0
}

func preflight(client dockerClient, settings options, publicKey string) (map[string]any, error) {
	baseImageID, err := client.one(operationTimeout, "image", "inspect", "--format", "{{.Id}}", settings.image)
	if err != nil || !validDockerID(baseImageID) {
		return nil, errors.New("exact local base image is unavailable; this helper never pulls images")
	}
	names := allTargetNames(settings)
	containerListing, err := client.one(operationTimeout, "container", "ls", "-a", "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	existingContainers := stringSet(strings.Fields(containerListing))
	imageListing, err := client.one(operationTimeout, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}")
	if err != nil {
		return nil, err
	}
	existingImages := stringSet(strings.Fields(imageListing))
	for _, target := range names {
		if existingContainers[target.Stage] {
			return nil, fmt.Errorf("container %s already exists; resources are never silently reused or removed", target.Stage)
		}
		if existingContainers[target.Final] {
			return nil, fmt.Errorf("container %s already exists; resources are never silently reused or removed", target.Final)
		}
		if existingImages[target.PreparedImage] {
			return nil, fmt.Errorf("prepared image %s already exists; resources are never silently reused or removed", target.PreparedImage)
		}
	}
	publicDigest := sha256.Sum256([]byte(publicKey))
	return map[string]any{
		"state":                  "READY_TO_APPLY",
		"run_id":                 settings.runID,
		"base_image":             settings.image,
		"base_image_id":          strings.TrimSpace(baseImageID),
		"listen_address":         settings.listenAddress,
		"gateway_port":           settings.gatewayPort,
		"vps_port":               settings.vpsPort,
		"identity_public_sha256": hex.EncodeToString(publicDigest[:]),
		"automatic_cleanup":      false,
	}, nil
}

func allTargetNames(settings options) []targetNames {
	prefix := "gateway-vpn-win-gate-" + settings.runID
	imagePrefix := "gateway-vpn-windows-gate:"
	return []targetNames{
		{Role: "gateway", Stage: prefix + "-gateway-stage", Final: prefix + "-gateway", PreparedImage: imagePrefix + settings.runID + "-gateway-ssh", Port: settings.gatewayPort},
		{Role: "vps", Stage: prefix + "-vps-stage", Final: prefix + "-vps", PreparedImage: imagePrefix + settings.runID + "-vps-ssh", Port: settings.vpsPort},
	}
}

func applyTargets(client dockerClient, settings options, publicKey, baseImageID string) (_ evidence, resultErr error) {
	if err := os.Mkdir(settings.evidenceDir, 0o700); err != nil {
		return evidence{}, errors.New("create exclusive evidence directory failed")
	}
	started := make(map[string]bool)
	defer func() {
		if resultErr == nil {
			return
		}
		containers := make([]string, 0, len(started))
		for name, active := range started {
			if active {
				containers = append(containers, name)
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(containers)))
		for _, name := range containers {
			_, _ = client.run(45*time.Second, "stop", "--timeout", "30", name)
		}
	}()

	names := allTargetNames(settings)
	targets := make([]targetEvidence, 0, len(names))
	knownHostLines := make([]string, 0, len(names))
	for _, target := range names {
		inputDirectory := filepath.Join(settings.evidenceDir, "input-"+target.Role)
		if err := writeTargetInput(inputDirectory, publicKey, settings.runID); err != nil {
			return evidence{}, err
		}
		createArguments := baseCreateArguments(target.Stage, target.Stage)
		// Use the already inspected immutable content ID, not the mutable local
		// tag, so a concurrent retag cannot change the clean base after preflight.
		createArguments = append(createArguments, baseImageID, "/sbin/init")
		if _, err := client.run(operationTimeout, createArguments...); err != nil {
			return evidence{}, fmt.Errorf("create %s staging container: %w", target.Role, err)
		}
		if _, err := client.run(operationTimeout, "cp", filepath.Join(inputDirectory, "99-gateway-vpn-release-gate.conf"), target.Stage+":/etc/ssh/sshd_config.d/99-gateway-vpn-release-gate.conf"); err != nil {
			return evidence{}, fmt.Errorf("copy %s SSH policy: %w", target.Role, err)
		}
		if _, err := client.run(operationTimeout, "cp", filepath.Join(inputDirectory, ".ssh"), target.Stage+":/root/"); err != nil {
			return evidence{}, fmt.Errorf("copy %s authorized key: %w", target.Role, err)
		}
		if _, err := client.run(operationTimeout, "start", target.Stage); err != nil {
			return evidence{}, fmt.Errorf("start %s staging container: %w", target.Role, err)
		}
		started[target.Stage] = true
		if _, err := client.run(operationTimeout, "exec", target.Stage, "/bin/sh", "-ceu", hardenSSHScript); err != nil {
			return evidence{}, fmt.Errorf("harden %s staging SSH: %w", target.Role, err)
		}
		if _, err := client.run(45*time.Second, "stop", "--timeout", "30", target.Stage); err != nil {
			return evidence{}, fmt.Errorf("stop %s staging container: %w", target.Role, err)
		}
		started[target.Stage] = false
		if _, err := client.run(operationTimeout, "commit", target.Stage, target.PreparedImage); err != nil {
			return evidence{}, fmt.Errorf("commit %s prepared SSH image: %w", target.Role, err)
		}
		preparedImageID, err := client.one(operationTimeout, "image", "inspect", "--format", "{{.Id}}", target.PreparedImage)
		if err != nil || !validDockerID(preparedImageID) {
			return evidence{}, fmt.Errorf("verify %s prepared image failed", target.Role)
		}
		finalArguments := baseCreateArguments(target.Final, target.Final)
		// Likewise create the published target from the exact committed image ID,
		// while preserving the human-readable tag only as evidence.
		finalArguments = append(finalArguments, "--publish", net.JoinHostPort(settings.listenAddress, strconv.Itoa(target.Port))+":22/tcp", strings.TrimSpace(preparedImageID), "/sbin/init")
		if _, err := client.run(operationTimeout, finalArguments...); err != nil {
			return evidence{}, fmt.Errorf("create %s final container: %w", target.Role, err)
		}
		containerID, err := client.one(operationTimeout, "container", "inspect", "--format", "{{.Id}}", target.Final)
		if err != nil || !validContainerID(containerID) {
			return evidence{}, fmt.Errorf("verify %s final container identity failed", target.Role)
		}
		if _, err := client.run(operationTimeout, "start", target.Final); err != nil {
			return evidence{}, fmt.Errorf("start %s final container: %w", target.Role, err)
		}
		started[target.Final] = true
		if err := waitForSSH(client, target.Final); err != nil {
			return evidence{}, fmt.Errorf("wait for %s SSH: %w", target.Role, err)
		}
		if _, err := client.run(operationTimeout, "exec", target.Final, "/bin/sh", "-ceu", assertCleanTargetScript); err != nil {
			return evidence{}, fmt.Errorf("assert %s clean application state: %w", target.Role, err)
		}
		binding, err := client.one(operationTimeout, "port", target.Final, "22/tcp")
		if err != nil || strings.TrimSpace(binding) != net.JoinHostPort(settings.listenAddress, strconv.Itoa(target.Port)) {
			return evidence{}, fmt.Errorf("%s SSH port binding differs from the exact requested address", target.Role)
		}
		hostKey, err := client.one(operationTimeout, "exec", target.Final, "/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err != nil {
			return evidence{}, fmt.Errorf("read %s public SSH host key: %w", target.Role, err)
		}
		hostKey, err = normalizeEd25519PublicKey(hostKey)
		if err != nil {
			return evidence{}, fmt.Errorf("validate %s SSH host key: %w", target.Role, err)
		}
		hostDigest := sha256.Sum256([]byte(hostKey))
		knownHostLines = append(knownHostLines, fmt.Sprintf("[%s]:%d %s", settings.listenAddress, target.Port, hostKey))
		targets = append(targets, targetEvidence{
			Role: target.Role, Container: target.Final, ContainerID: strings.TrimSpace(containerID),
			PreparedImage: target.PreparedImage, PreparedImageID: strings.TrimSpace(preparedImageID),
			SSHAddress: settings.listenAddress, SSHPort: target.Port, SSHHostKeySHA256: hex.EncodeToString(hostDigest[:]),
		})
	}

	knownHosts := strings.Join(knownHostLines, "\n") + "\n"
	knownHostsPath := filepath.Join(settings.evidenceDir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(knownHosts), 0o600); err != nil {
		return evidence{}, errors.New("write pinned known_hosts failed")
	}
	for _, target := range targets {
		if err := verifyWindowsSSH(settings.identityPath, knownHostsPath, target.SSHAddress, target.SSHPort); err != nil {
			return evidence{}, fmt.Errorf("fixed Win32 OpenSSH smoke for %s: %w", target.Role, err)
		}
	}

	dockerHash, err := fileSHA256(client.executable)
	if err != nil {
		return evidence{}, err
	}
	sshHash, err := fileSHA256(windowsSSH)
	if err != nil {
		return evidence{}, err
	}
	publicHash := sha256.Sum256([]byte(publicKey))
	knownHostsHash := sha256.Sum256([]byte(knownHosts))
	result := evidence{
		FormatVersion: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), RunID: settings.runID,
		BaseImage: settings.image, BaseImageID: baseImageID,
		DockerExecutable: client.executable, DockerSHA256: dockerHash,
		OpenSSHExecutable: windowsSSH, OpenSSHSHA256: sshHash,
		IdentityPublicSHA256: hex.EncodeToString(publicHash[:]), KnownHostsSHA256: hex.EncodeToString(knownHostsHash[:]),
		Targets: targets,
	}
	manifestContent, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return evidence{}, err
	}
	manifestContent = append(manifestContent, '\n')
	if err := os.WriteFile(filepath.Join(settings.evidenceDir, "targets.json"), manifestContent, 0o600); err != nil {
		return evidence{}, errors.New("write target evidence manifest failed")
	}
	return result, nil
}

func baseCreateArguments(name, hostname string) []string {
	return []string{
		"create", "--name", name, "--hostname", hostname,
		"--privileged", "--cgroupns=private", "--security-opt", "label=disable",
		"--tmpfs", "/run:rw,nosuid,nodev,exec", "--tmpfs", "/run/lock:rw,nosuid,nodev,exec",
		"--mount", "type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup",
		"--stop-signal", "SIGRTMIN+3",
	}
}

func writeTargetInput(directory, publicKey, runID string) error {
	if err := os.Mkdir(directory, 0o700); err != nil {
		return errors.New("create target input directory failed")
	}
	sshDirectory := filepath.Join(directory, ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		return errors.New("create target SSH input directory failed")
	}
	authorized := publicKey + " gateway-vpn-windows-gate-" + runID + "\n"
	if err := os.WriteFile(filepath.Join(sshDirectory, "authorized_keys"), []byte(authorized), 0o600); err != nil {
		return errors.New("write target authorized key failed")
	}
	if err := os.WriteFile(filepath.Join(directory, "99-gateway-vpn-release-gate.conf"), []byte(sshdPolicy), 0o600); err != nil {
		return errors.New("write target SSH policy failed")
	}
	return nil
}

func waitForSSH(client dockerClient, container string) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := client.run(10*time.Second, "exec", container, "/usr/bin/systemctl", "is-active", "--quiet", "ssh.service"); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("ssh.service did not become active")
		}
		time.Sleep(time.Second)
	}
}

func verifyWindowsSSH(identity, knownHosts, address string, port int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	arguments := []string{
		"-F", "NUL", "-T", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=\"" + filepath.ToSlash(knownHosts) + "\"", "-o", "GlobalKnownHostsFile=NUL",
		"-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "RequestTTY=no",
		"-o", "ConnectTimeout=10", "-i", identity, "-p", strconv.Itoa(port), "--", "root@" + address, "true",
	}
	command := exec.CommandContext(ctx, windowsSSH, arguments...)
	command.Env = windowsCommandEnvironment()
	var stdout, stderr bytes.Buffer
	command.Stdout = &limitedWriter{writer: &stdout, remaining: 4096}
	command.Stderr = &limitedWriter{writer: &stderr, remaining: 4096}
	if err := command.Run(); err != nil {
		return errors.New("key-only pinned-host connection failed")
	}
	return nil
}

func windowsCommandEnvironment() []string {
	result := make([]string, 0, 16)
	for _, name := range []string{
		"SystemRoot", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN",
		"HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
	} {
		if value := os.Getenv(name); value != "" && !strings.ContainsRune(value, '\x00') {
			result = append(result, name+"="+value)
		}
	}
	result = append(result, `PATH=C:\Windows\System32\OpenSSH;C:\Windows\System32;C:\Windows`)
	return result
}

func (client dockerClient) one(timeout time.Duration, arguments ...string) (string, error) {
	result, err := client.run(timeout, arguments...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(result.stdout)), nil
}

func (client dockerClient) run(timeout time.Duration, arguments ...string) (commandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, client.executable, arguments...)
	var stdout, stderr bytes.Buffer
	stdoutWriter := &limitedWriter{writer: &stdout, remaining: maximumCommandOutput}
	stderrWriter := &limitedWriter{writer: &stderr, remaining: maximumCommandOutput}
	command.Stdout, command.Stderr = stdoutWriter, stderrWriter
	err := command.Run()
	result := commandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if ctx.Err() != nil {
		return result, errors.New("bounded Docker operation timed out")
	}
	if stdoutWriter.overflow || stderrWriter.overflow {
		return result, errors.New("bounded Docker operation output overflow")
	}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return result, fmt.Errorf("Docker operation failed with exit code %d", exitError.ExitCode())
		}
		return result, errors.New("start Docker operation failed")
	}
	return result, nil
}

type limitedWriter struct {
	writer    io.Writer
	remaining int
	overflow  bool
}

func (writer *limitedWriter) Write(content []byte) (int, error) {
	original := len(content)
	if original > writer.remaining {
		content = content[:writer.remaining]
		writer.overflow = true
	}
	if len(content) > 0 {
		written, err := writer.writer.Write(content)
		writer.remaining -= written
		if err != nil {
			return written, err
		}
	}
	return original, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("open release-gate executable for hashing failed")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256*1024*1024+1)); err != nil {
		return "", errors.New("hash release-gate executable failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func validDockerID(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validContainerID(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) == 64 && func() bool { _, err := hex.DecodeString(value); return err == nil }()
}

const sshdPolicy = `PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PermitEmptyPasswords no
AllowUsers root
`

const hardenSSHScript = `dpkg-query -W openssh-server >/dev/null
systemctl stop ssh.service || true
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
/usr/bin/ssh-keygen -A >/dev/null
install -d -o root -g root -m 0755 /run/sshd
chown -R root:root /root/.ssh /etc/ssh/sshd_config.d/99-gateway-vpn-release-gate.conf
chmod 0700 /root/.ssh
chmod 0600 /root/.ssh/authorized_keys /etc/ssh/sshd_config.d/99-gateway-vpn-release-gate.conf
/usr/sbin/sshd -t
systemctl enable ssh.service >/dev/null
systemctl start ssh.service
systemctl is-active --quiet ssh.service
` + assertCleanTargetScript

const assertCleanTargetScript = `for path in /opt/gateway-vpn /opt/gateway-vpn-vps /etc/gateway-vpn /etc/gateway-vpn-vps /var/lib/gateway-vpn /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-privileged /var/lib/gateway-vpn-vps-privileged; do
    test ! -e "$path"
done
`
