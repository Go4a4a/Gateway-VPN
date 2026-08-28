package packaging_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestPackagingKeepsControlPlaneUnprivilegedAndFirewallBlocked(t *testing.T) {
	root := repositoryRoot(t)
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	for _, required := range []string{"User=gateway-vpn", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=", "Requires=gateway-vpn-firewall.service"} {
		if !strings.Contains(control, required) {
			t.Errorf("control-plane unit missing %q", required)
		}
	}
	boot := read(t, filepath.Join(root, "packaging", "nftables", "boot.nft.in"))
	for _, required := range []string{"table inet gateway_vpn", "firewall_schema_generation", "type mark", "elements = { 3 }", "active_direct_interfaces", "active_direct_context", "active_direct_marks", "active_route_generation", "chain prerouting", "chain postrouting", "counter user_upload", "counter user_download", "counter service_upload", "counter service_download", "chain input", "chain forward", "chain output", "policy drop", "gateway-vpn PATH_BLOCKED"} {
		if !strings.Contains(boot, required) {
			t.Errorf("boot ruleset missing %q", required)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "policy accept", "type integer", "oifname @hilink_interfaces accept"} {
		if strings.Contains(boot, forbidden) {
			t.Errorf("boot ruleset contains forbidden %q", forbidden)
		}
	}
	for _, unitName := range []string{"gateway-vpn-firewall.service", "gateway-vpn-firewall-guard.service", "gateway-vpn-watchdog.service", "gateway-vpn-database-restore-boot.service", "gateway-vpn-network-broker.socket", "gateway-vpn.service", "gateway-vpn-mihomo.service", "gateway-vpn-dnsmasq.service"} {
		unit := read(t, filepath.Join(root, "packaging", "systemd", unitName))
		for _, gate := range []string{"ConditionPathExists=|!/var/lib/gateway-vpn-privileged/install-transactions/active", "ConditionPathExists=|/run/gateway-vpn-install-authorized", "ConditionPathIsSymbolicLink=!/var/lib/gateway-vpn-privileged/install-transactions/active", "ConditionPathIsSymbolicLink=!/run/gateway-vpn-install-authorized"} {
			if !strings.Contains(unit, gate) {
				t.Errorf("%s can start during an incomplete install: missing %q", unitName, gate)
			}
		}
	}
}

func TestWatchdogUsesFixedBoundedRootSurfaceAndControlHangDetection(t *testing.T) {
	root := repositoryRoot(t)
	unit := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-watchdog.service"))
	for _, required := range []string{
		"Type=notify", "NotifyAccess=all", "WatchdogSec=10min", "Group=gateway-vpn",
		"RuntimeDirectory=gateway-vpn-watchdog", "RuntimeDirectoryMode=0770", "RuntimeDirectoryPreserve=restart",
		"gateway-vpn watchdog --config /etc/gateway-vpn/config.yaml --history-root /var/lib/gateway-vpn-privileged/watchdog --status-path /run/gateway-vpn-watchdog/status.json --apply",
		"Restart=always", "NoNewPrivileges=yes", "ProtectSystem=strict",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_BOOT CAP_DAC_READ_SEARCH",
		"ReadOnlyPaths=/etc/gateway-vpn /opt/gateway-vpn /var/lib/gateway-vpn",
		"ReadWritePaths=/var/lib/gateway-vpn-privileged/watchdog /run/gateway-vpn-watchdog",
	} {
		if !strings.Contains(unit, required) {
			t.Errorf("watchdog unit missing %q", required)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "bash -c", "%i", "EnvironmentFile=", "User=gateway-vpn\n"} {
		if strings.Contains(unit, forbidden) {
			t.Errorf("watchdog unit contains unsafe dynamic surface %q", forbidden)
		}
	}
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	for _, required := range []string{"Type=notify", "NotifyAccess=all", "WatchdogSec=120s", "Requires=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-watchdog.service", "Wants=network-online.target gateway-vpn-network-broker.socket", "PartOf=gateway-vpn-watchdog.service", "ReadWritePaths=/var/lib/gateway-vpn /run/gateway-vpn-watchdog"} {
		if !strings.Contains(control, required) {
			t.Errorf("control hang-detection contract missing %q", required)
		}
	}
	for filename, required := range map[string]string{
		"gateway-vpn-install-recovery.service":      "Before=network-pre.target gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service gateway-vpn-watchdog.service",
		"gateway-vpn-update-recovery.service":       "gateway-vpn-network-recovery.service gateway-vpn-watchdog.service",
		"gateway-vpn-database-restore-boot.service": "Before=gateway-vpn-network-recovery.service gateway-vpn-watchdog.service",
		"gateway-vpn-network-recovery.service":      "Before=gateway-vpn-watchdog.service",
	} {
		content := read(t, filepath.Join(root, "packaging", "systemd", filename))
		if !strings.Contains(content, required) {
			t.Errorf("%s does not order recovery before watchdog: missing %q", filename, required)
		}
	}
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	if !strings.Contains(tmpfiles, "d /var/lib/gateway-vpn-privileged/watchdog 0700 root root") {
		t.Fatal("tmpfiles does not create the root-only durable watchdog history root")
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{"systemctl restart gateway-vpn-watchdog.service", "systemctl is-active --quiet gateway-vpn-watchdog.service", "watchdog_runtime_ready", "/run/gateway-vpn-watchdog/status.json", "/run/gateway-vpn-watchdog/control.json", `"database_ok":true`, `"workers_ok":true`, "status_age <= 660", "control_age <= 30"} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer watchdog acceptance missing %q", required)
		}
	}
	last := -1
	for _, command := range []string{
		"systemctl restart gateway-vpn-update-recovery.service",
		"systemctl restart gateway-vpn-network-recovery.service",
		"systemctl restart gateway-vpn-network-broker.socket",
		"systemctl restart gateway-vpn-watchdog.service",
		"systemctl restart gateway-vpn.service",
	} {
		position := strings.Index(installer, command)
		if position < 0 || position <= last {
			t.Fatalf("installer recovery/watchdog startup order is unsafe at %q", command)
		}
		last = position
	}
}

func TestInstallerIsExplicitAndUbuntuScoped(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{"VERSION_ID:-} == 24.04", "manifest.sha256", "manifest.json", "release.sig", "--trusted-update-key", "release-verify", "release.json", "mihomo-api-secret", "--install-dependencies", "--dependency-preflight-only", "iproute2", "nftables", "wireguard-tools", "kmod", "procps", "dnsmasq-base", "openssh-server", "apt-get -s install --no-install-recommends --no-remove --no-upgrade", "APT Gateway dependency plan attempts to remove packages", "APT Gateway dependency plan attempts to upgrade installed packages", "full host preflight NOT_RUN", "ss -H -ltn \"sport = :53\"", "ss -H -lun \"sport = :53\"", "DHCP/DNS enable conflicts with an existing wildcard or Gateway LAN port 53 listener", "/run/lock/gateway-vpn-install.lock", "recover-gateway-install.sh", "gateway-vpn-install-recovery.service", "old_ipv4_forward=%s", "preserve_state_root=%s", "lan_members=%s", "ssh_was_enabled=%s", "ssh_was_active=%s", "90-gateway-vpn-ipv4-forwarding.conf", "05-gateway-vpn-lan.network", "05-gateway-vpn-lan.netdev", "gateway-install-preflight", "INSTALLED_NOT_READY", "--apply", "nft --check", "nft --file /etc/gateway-vpn/nftables/boot.nft", "Gateway VPN requires Ubuntu 24.04"} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer missing %q", required)
		}
	}
	for _, required := range []string{
		"APPLY == 0 || SIMULATION_RESULT != 10",
		"Refreshing configured APT indexes before installing exact missing Gateway packages",
		"APT Gateway dependency simulation failed after index refresh",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway clean-host dependency refresh contract missing %q", required)
		}
	}
	if strings.Contains(installer, "apt upgrade") || strings.Contains(installer, "apt-get upgrade") || strings.Contains(installer, "apt-get full-upgrade") || strings.Contains(installer, "apt-get dist-upgrade") || strings.Contains(installer, "autoremove") || strings.Contains(installer, "curl |") {
		t.Fatal("installer contains an unsafe opaque upgrade/download path")
	}
}

func TestGatewayInstallerPinsRuntimeLANAndActivatesNetworkBroker(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{
		`sed -E -e "s|^([[:space:]]*)lan_interface:.*|\1lan_interface: $LAN_INTERFACE|"`,
		`grep -Fxq "  lan_interface: $LAN_INTERFACE" /etc/gateway-vpn/config.yaml`,
		`"$DEST/bin/gateway-vpn" --check-config /etc/gateway-vpn/config.yaml`,
		"systemctl restart gateway-vpn-network-broker.socket",
		"systemctl is-active --quiet gateway-vpn-network-broker.socket",
		"systemctl is-active --quiet gateway-vpn-network-broker.service",
		"[[ -S /run/gateway-vpn/network-broker.sock ]]",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer LAN/broker readiness contract missing %q", required)
		}
	}
	if strings.Contains(installer, `s|__LAN_INTERFACE__|$LAN_INTERFACE|g" -e "s|192.168.200.1/24|$LAN_ADDRESS|g" -e "s|192.168.200.1|$LAN_IP|g" "$ROOT_DIR/config.example.yaml"`) {
		t.Fatal("Gateway installer still expects a nonexistent LAN placeholder in config.example.yaml")
	}
}

func TestGatewayInstallerAllowsOnlyStrictCompletedInstallToBypassDirectDNS(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{
		"if ! getent ahostsv4 github.com >/dev/null; then",
		"COMPLETED_INSTALL_HINT=0",
		`$(stat -c '%u:%g:%a' /var/lib/gateway-vpn/install-report.json) == "0:0:600"`,
		`$(readlink /opt/gateway-vpn/current) == "releases/v$RELEASE_VERSION"`,
		`$(readlink /opt/gateway-vpn/recovery) == "releases/v$RELEASE_VERSION"`,
		`grep -Fq "\"version\": \"$RELEASE_VERSION\"" /var/lib/gateway-vpn/install-report.json`,
		`grep -Fq "\"lan_interface\": \"$LAN_INTERFACE\"" /var/lib/gateway-vpn/install-report.json`,
		`grep -Fq "\"lan_address\": \"$LAN_ADDRESS\"" /var/lib/gateway-vpn/install-report.json`,
		"((COMPLETED_INSTALL_HINT == 1)) || { echo \"Gateway DNS resolution failed\"",
		"continuing with strict existing-install verification",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer completed-install DNS exception missing %q", required)
		}
	}
}

func TestGatewayServicesUseBoundedJournaldNamespace(t *testing.T) {
	root := repositoryRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "packaging", "systemd"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
			continue
		}
		unit := read(t, filepath.Join(root, "packaging", "systemd", entry.Name()))
		if !strings.Contains(unit, "LogNamespace=gateway-vpn") {
			t.Errorf("service %s is outside the bounded journal namespace", entry.Name())
		}
	}
	policy := read(t, filepath.Join(root, "packaging", "journald", "gateway-vpn.conf"))
	for _, required := range []string{"Storage=persistent", "Compress=yes", "SystemMaxUse=256M", "RuntimeMaxUse=64M", "MaxRetentionSec=14day"} {
		if !strings.Contains(policy, required) {
			t.Errorf("journald policy missing %q", required)
		}
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	if !strings.Contains(installer, "/etc/systemd/journald@gateway-vpn.conf.d/retention.conf") || !strings.Contains(installer, "systemd-journald@gateway-vpn.service") {
		t.Fatal("installer does not activate the bounded Gateway VPN journal namespace")
	}
}

func TestReleaseBuilderPinsMihomoVersionHashAndAPIContract(t *testing.T) {
	root := repositoryRoot(t)
	builder := read(t, filepath.Join(root, "scripts", "build-release.sh"))
	for _, required := range []string{"MIHOMO_VERSION", "SIGNING_PRIVATE_KEY", "buildinfo.MihomoVersion", "mihomo_sha256", "gateway_api_contract", "mihomo_api_contract", "database_schema_maximum", "host_contract_sha256", "release-host-contract", "manifest.json", "release.sig", "release-sign", "sbom.spdx.json", "provenance.intoto.json", "release.json", "sha256sum --binary"} {
		if !strings.Contains(builder, required) {
			t.Errorf("release builder missing %q", required)
		}
	}
	for _, required := range []string{"gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz", "gateway-vpn-bootstrap-$VERSION-linux-amd64", "./cmd/gateway-vpn-bootstrap", "scripts/install-gateway.sh", "scripts/recover-gateway-install.sh", "scripts/uninstall.sh", "config.example.yaml", "$ROOT/packaging", "Gateway archive SHA-256", "Bootstrap SHA-256"} {
		if !strings.Contains(builder, required) {
			t.Errorf("installable release builder missing %q", required)
		}
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{"find \"$RELEASE_DIR\" -type f -print0", "relative=${source#\"$RELEASE_DIR/\"}", "install -D -m \"$mode\"", "release-verify --release-dir \"$DEST\""} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer does not preserve the complete signed release: missing %q", required)
		}
	}
}

func TestRoleBuildersExcludeStrictArchiveRootEntry(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{"build-release.sh", "build-vps-release.sh"} {
		builder := read(t, filepath.Join(root, "scripts", name))
		for _, required := range []string{
			`find "$DEST" -mindepth 1 -maxdepth 1 -printf '%f\0'`,
			`ARCHIVE_ENTRIES+=("$entry")`,
			`-- "${ARCHIVE_ENTRIES[@]}"`,
		} {
			if !strings.Contains(builder, required) {
				t.Errorf("%s does not build from explicit safe top-level entries: missing %q", name, required)
			}
		}
		if strings.Contains(builder, `-czf "$ARCHIVE" .`) {
			t.Errorf("%s archives a standalone root entry rejected by the production strict extractor", name)
		}
	}
}

func TestChannelBuilderPinsBootstrapBeforeSudoAndProducesExactCommand(t *testing.T) {
	root := repositoryRoot(t)
	builder := read(t, filepath.Join(root, "scripts", "build-channel.sh"))
	for _, required := range []string{
		"channel-sign", "channel-verify", "channel-install-command",
		"channel-$CHANNEL.json", "channel-$CHANNEL.sig", "update-signing.pub",
		"--github-repository", "--release-tag", "--source-commit", "--interactive",
		"install-gateway-$VERSION.command.txt", "clean committed worktree",
	} {
		if !strings.Contains(builder, required) {
			t.Errorf("channel builder missing %q", required)
		}
	}
	for _, forbidden := range []string{"LAN_INTERFACE=", "LAN_ADDRESS=", "--lan-interface", "--lan-address", "--enable-dhcp", "--apply"} {
		if strings.Contains(builder, forbidden) {
			t.Errorf("generic channel builder contains target-specific policy %q", forbidden)
		}
	}
}

func TestReleaseBundleIsCanonicalReverifiedAndDraftOnly(t *testing.T) {
	root := repositoryRoot(t)
	for _, path := range []string{
		filepath.Join(root, "scripts", "build-release.sh"),
		filepath.Join(root, "scripts", "build-vps-release.sh"),
		filepath.Join(root, "scripts", "build-deploy.sh"),
		filepath.Join(root, "scripts", "build-channel.sh"),
	} {
		builder := read(t, path)
		for _, required := range []string{"git -C \"$ROOT\" show -s --format=%ct", "date -u -d \"@"} {
			if !strings.Contains(builder, required) {
				t.Errorf("%s does not derive canonical metadata from commit time: missing %q", path, required)
			}
		}
		if strings.Contains(builder, "date -u +%s") {
			t.Errorf("%s still uses invocation time for signed release identity", path)
		}
	}

	bundle := read(t, filepath.Join(root, "scripts", "build-release-bundle.sh"))
	for _, required := range []string{
		"build-release.sh", "build-vps-release.sh", "build-deploy.sh", "build-channel.sh",
		"release-key-verify", "release-verify", "--initial-install", "vps-release-verify", "channel-verify",
		"--artifact \"bootstrap=", "--artifact \"deploy=", "--artifact \"gateway=", "--artifact \"vps=",
		"bootstrap=$ROOT/dist/", "deploy=$ROOT/dist/", "gateway=$ROOT/dist/", "vps=$ROOT/dist/",
		"regular non-symlink files", "PRIVATE_MODE", "absent dist directory", "clean committed worktree",
	} {
		if !strings.Contains(bundle, required) {
			t.Errorf("release bundle builder missing %q", required)
		}
	}

	fetcher := read(t, filepath.Join(root, "scripts", "fetch-mihomo-release.sh"))
	for _, required := range []string{
		"https://github.com/MetaCubeX/mihomo/releases/download/", "mihomo-linux-amd64-v1-",
		"--proto '=https'", "--max-filesize 67108864", "sha256sum --binary", "ulimit -f 262144",
		"BINARY_SIZE <= 134217728", "timeout 10s", "does not report the requested version",
	} {
		if !strings.Contains(fetcher, required) {
			t.Errorf("Mihomo release fetcher missing %q", required)
		}
	}

	publisher := read(t, filepath.Join(root, "scripts", "create-github-release-draft.sh"))
	for _, required := range []string{
		"GH_TOKEN", "REMOTE_COMMIT", "--verify-tag --draft", "go run ./cmd/gateway-vpnctl", "--artifact \"bootstrap=",
		"gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz",
		"gateway-vpn-vps-$VERSION-linux-amd64.tar.gz", "gateway-vpn-bootstrap-$VERSION-linux-amd64",
		"gateway-vpn-deploy-$VERSION-linux-amd64", "channel-$CHANNEL.json", "update-signing.pub",
		"Draft created only", "enable GitHub release immutability",
	} {
		if !strings.Contains(publisher, required) {
			t.Errorf("GitHub draft publisher missing %q", required)
		}
	}
	for _, forbidden := range []string{"--draft=false", "release edit", "release delete", "private-key"} {
		if strings.Contains(publisher, forbidden) {
			t.Errorf("GitHub draft publisher contains forbidden %q", forbidden)
		}
	}
	keygen := read(t, filepath.Join(root, "cmd", "gateway-vpnctl", "release_commands.go"))
	for _, required := range []string{"requireTrustedLinuxKeyOperation", "release signing identity operations require", "updatepkg.WriteKeyPair", "updatepkg.VerifyKeyPair", "updatepkg.BackupKeyPair"} {
		if !strings.Contains(keygen, required) {
			t.Errorf("release key generator missing %q", required)
		}
	}
	keyContract := read(t, filepath.Join(root, "internal", "update", "contract.go"))
	for _, required := range []string{"absolute private and public key paths", "one secure directory", "must not contain symlink components", "must not be accessible to group or others", "must not be created inside a Git worktree", "verify written release signing key pair", "release signing backup must use a different secure directory", "release signing private and public keys do not match", "syncDirectory"} {
		if !strings.Contains(keyContract, required) {
			t.Errorf("release key custody contract missing %q", required)
		}
	}
	encryptedKeyContract := read(t, filepath.Join(root, "internal", "update", "keyfile.go"))
	for _, required := range []string{
		"GATEWAY-VPN-KEY1", "AES-256-GCM", "argon2id", "64 * 1024", ".gvkey",
		"encrypted release key files must not be stored inside a Git worktree",
		"encrypted release key backup must use a different destination directory",
		"writeVerifiedKeyPair", "VerifyEncryptedKeyFile", "syncDirectory",
	} {
		if !strings.Contains(encryptedKeyContract, required) {
			t.Errorf("encrypted release key contract missing %q", required)
		}
	}
	createEncrypted := read(t, filepath.Join(root, "scripts", "create-release-key-file.sh"))
	for _, required := range []string{
		"stat -f -c %T /dev/shm", "== tmpfs", "set +x", "release-keyfile-create", "release-keyfile-backup", "release-keyfile-verify", "trap cleanup EXIT",
		`PASSPHRASE_FILE="$SECRET_ROOT/passphrase"`, `CONTROL="$BUILD_ROOT/gateway-vpnctl"`, "/tmp/gateway-vpn-key-helper.",
	} {
		if !strings.Contains(createEncrypted, required) {
			t.Errorf("encrypted release key creator missing %q", required)
		}
	}
	buildEncrypted := read(t, filepath.Join(root, "scripts", "build-release-bundle-encrypted.sh"))
	for _, required := range []string{
		"stat -f -c %T /dev/shm", "== tmpfs", "set +x", "release-keyfile-unlock", "build-release-bundle.sh", "trap cleanup EXIT", "--passphrase-file",
		`PASSPHRASE_FILE="$SECRET_ROOT/passphrase"`, `UNLOCKED="$SECRET_ROOT/unlocked"`, `CONTROL="$BUILD_ROOT/gateway-vpnctl"`, "/tmp/gateway-vpn-key-helper.",
	} {
		if !strings.Contains(buildEncrypted, required) {
			t.Errorf("encrypted release bundle wrapper missing %q", required)
		}
	}
	for name, content := range map[string]string{"creator": createEncrypted, "builder": buildEncrypted} {
		for _, forbidden := range []string{"--passphrase \"$PASSPHRASE\"", "PASSPHRASE=\"$PASSPHRASE\"", "export PASSPHRASE", `CONTROL="$SECRET_ROOT`} {
			if strings.Contains(content, forbidden) {
				t.Errorf("encrypted key %s exposes passphrase through forbidden pattern %q", name, forbidden)
			}
		}
	}
}

func TestGitHubCIUsesPinnedActionsWithoutReleaseSecrets(t *testing.T) {
	root := repositoryRoot(t)
	workflow := read(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(workflow), &parsed); err != nil {
		t.Fatalf("parse GitHub CI workflow: %v", err)
	}
	for _, required := range []string{
		"permissions:\n  contents: read", "runs-on: ubuntu-24.04", "go test -race ./... -count=1",
		"go vet ./...", "CGO_ENABLED=0 GOOS=linux GOARCH=amd64", "node --check", "bash -n scripts/*.sh", "test/release-gate/*.sh",
		"sudo apt-get install --yes --no-install-recommends --no-upgrade", "firewall_guard.sh /tmp/gateway-vpn-netns",
		"startup_policy.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-app-test",
		"persist-credentials: false",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("GitHub CI workflow missing %q", required)
		}
	}
	if strings.Contains(workflow, "pull_request_target") || strings.Contains(strings.ToLower(workflow), "release_signing") || strings.Contains(workflow, "secrets.") {
		t.Fatal("GitHub CI can expose release secrets or runs privileged fork code with base context")
	}
	usesPattern := regexp.MustCompile(`(?m)^\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$`)
	matches := usesPattern.FindAllStringSubmatch(workflow, -1)
	if len(matches) != 4 {
		t.Fatalf("expected four full-SHA official Action references, got %d", len(matches))
	}
	if strings.Count(workflow, "uses:") != len(matches) {
		t.Fatal("GitHub CI contains an unpinned Action reference")
	}
	dependabot := read(t, filepath.Join(root, ".github", "dependabot.yml"))
	if !strings.Contains(dependabot, "package-ecosystem: github-actions") || !strings.Contains(dependabot, "interval: weekly") {
		t.Fatal("GitHub Action pins do not have a reviewable update feed")
	}
}

func TestDeployLauncherBuilderAndCommandArePinnedAndPrivateKeyFree(t *testing.T) {
	root := repositoryRoot(t)
	builder := read(t, filepath.Join(root, "scripts", "build-deploy.sh"))
	for _, required := range []string{"gateway-vpn-deploy-$VERSION-linux-amd64", "./cmd/gateway-vpn-deploy", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "clean committed worktree", "spdxVersion", "provenance", "sha256sum --binary"} {
		if !strings.Contains(builder, required) {
			t.Errorf("deploy builder missing %q", required)
		}
	}
	if strings.Contains(builder, "private-key") {
		t.Fatal("deploy builder unexpectedly accepts private key material")
	}
	commandSource := read(t, filepath.Join(root, "internal", "distribution", "install_command.go"))
	for _, required := range []string{"func DeployCommand", "RoleDeploy", "test \\\"$actual\\\"", "--gateway-ssh", "--vps-ssh", "--known-hosts", "--admin-public-key", "--apply"} {
		if !strings.Contains(commandSource, required) {
			t.Errorf("deploy command generator missing %q", required)
		}
	}
	if strings.Contains(commandSource, "--admin-private-key") || strings.Contains(commandSource, "--gateway-private-key") {
		t.Fatal("deploy command generator transports private key arguments")
	}
	generator := read(t, filepath.Join(root, "scripts", "generate-deploy-command.sh"))
	for _, required := range []string{"channel-deploy-command", "deploy-gateway-vps-$VERSION.command.txt", "--gateway-ssh", "--vps-ssh", "--known-hosts", "--public-endpoint", "--admin-public-key"} {
		if !strings.Contains(generator, required) {
			t.Errorf("deploy command file generator missing %q", required)
		}
	}
}

func TestVPSRoleIsSignedProfileScopedRecoverableAndOwned(t *testing.T) {
	root := repositoryRoot(t)
	builder := read(t, filepath.Join(root, "scripts", "build-vps-release.sh"))
	for _, required := range []string{
		"gateway-vpn-vps-$VERSION-linux-amd64.tar.gz", "vps-release-sign",
		"debian-12", "ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04",
		"scripts/install-vps.sh", "scripts/uninstall-vps.sh", "scripts/recover-vps-install.sh",
		"sbom.spdx.json", "provenance.intoto.json", "clean committed worktree",
	} {
		if !strings.Contains(builder, required) {
			t.Errorf("VPS release builder missing %q", required)
		}
	}
	installer := read(t, filepath.Join(root, "scripts", "install-vps.sh"))
	for _, required := range []string{
		"ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12",
		"pro status --format=json", "esm-infra", "esm-apps", "apt-get -s upgrade",
		"--public-endpoint", "--gateway-public-key", "--admin-public-key", "--install-dependencies", "--dependency-preflight-only", "--allow-gateway-ssh",
		"iproute2", "nftables", "wireguard-tools", "kmod", "procps", "python3-minimal", "prerequisite_package in ubuntu-advantage-tools python3-minimal",
		"apt-get -s install --no-install-recommends --no-remove --no-upgrade", "apt-get update", "apt-get install --yes --no-install-recommends --no-remove --no-upgrade",
		"full host preflight NOT_RUN", "APT dependency plan attempts to remove packages", "APT dependency plan attempts to upgrade installed packages", "exit 10",
		"vps-release-verify", "manifest.sha256", "--apply", "nft --check",
		"gateway_vpn_vps", "10.80.0.1/24", "AllowedIPs = 10.80.0.2/32", "AllowedIPs = 10.80.0.10/32",
		"gateway-vpn-vps-install-recovery.service", "install-transactions/active", "Validated harmless pre-transaction VPS marker artifact", "Orphan VPS installation artifact requires operator recovery",
		"trap 'rollback_install $?' ERR EXIT", "trap 'rollback_install 130' INT", "trap 'rollback_install 143' TERM",
		"validate_preserved_wg_config", "PRESERVED_WG_CONFIG", "preserve_wg_config=%s", ".gateway-vpn-wg-mgmt.conf.tmp",
		"/run/lock/gateway-vpn-vps-install.lock", "set -o noclobber", "0:0:600", "flock -n 9", "flock -u 9",
		"ip -4 route get 10.80.0.2", "ip -4 route get 10.80.0.10", "INSTALLED_NOT_READY",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("VPS installer missing %q", required)
		}
	}
	for _, required := range []string{
		"APPLY == 0 || SIMULATION_RESULT != 10",
		"Refreshing configured APT indexes before installing exact missing VPS packages",
		"APT dependency simulation failed after index refresh",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("VPS clean-host dependency refresh contract missing %q", required)
		}
	}
	for _, forbidden := range []string{"apt upgrade", "apt-get upgrade", "apt-get full-upgrade", "apt-get dist-upgrade", "nft flush ruleset", "AllowedIPs = 10.80.0.0/24"} {
		if strings.Contains(installer, forbidden) {
			t.Errorf("VPS installer contains forbidden %q", forbidden)
		}
	}
	firewall := read(t, filepath.Join(root, "packaging", "vps", "nftables", "gateway-vpn-vps.nft.in"))
	for _, required := range []string{"table inet gateway_vpn_vps", "iifname \"wg-mgmt\"", "ip saddr 10.80.0.10", "ip daddr 10.80.0.2", "reject with icmpx type admin-prohibited"} {
		if !strings.Contains(firewall, required) {
			t.Errorf("VPS firewall missing %q", required)
		}
	}
	if strings.Contains(firewall, "192.168.") || strings.Contains(firewall, "flush ruleset") {
		t.Fatal("VPS role unexpectedly exposes a home/transit LAN or flushes global firewall state")
	}
	for _, unitPath := range []string{
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-firewall.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "wg-quick@wg-mgmt.service.d", "gateway-vpn.conf"),
	} {
		unit := read(t, unitPath)
		if !strings.Contains(unit, "ConditionPathExists=|!/var/lib/gateway-vpn-vps/install-transactions/active") || !strings.Contains(unit, "ConditionPathExists=|/run/gateway-vpn-vps-install-authorized") || !strings.Contains(unit, "ConditionPathIsSymbolicLink=!/var/lib/gateway-vpn-vps/install-transactions/active") || !strings.Contains(unit, "ConditionPathIsSymbolicLink=!/run/gateway-vpn-vps-install-authorized") {
			t.Errorf("VPS unit %s can start during an incomplete install", unitPath)
		}
	}
	recovery := read(t, filepath.Join(root, "scripts", "recover-vps-install.sh"))
	for _, required := range []string{"nft delete table inet gateway_vpn_vps", "old_ipv4_forward", "preserve_wg_config", "PRESERVE_WG_CONFIG", "active marker retained for retry", ".gateway-vpn-wg-mgmt.conf.tmp", "install-report.json", "/run/lock/gateway-vpn-vps-install.lock", "flock -n 9", "marker field count is invalid", "duplicate or missing field", "wg-mgmt remained enabled", "if ((FAILED))"} {
		if !strings.Contains(recovery, required) {
			t.Errorf("VPS recovery missing %q", required)
		}
	}
	if strings.Contains(recovery, "flush ruleset") || strings.Contains(recovery, "set +e") || strings.Index(recovery, "if ((FAILED))") > strings.Index(recovery, "mv -f \"$MARKER\"") {
		t.Fatal("VPS first-install recovery does not restore only owned state")
	}
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall-vps.sh"))
	if !strings.Contains(uninstaller, "--purge-keys") || !strings.Contains(uninstaller, "WireGuard keys are preserved") || strings.Contains(uninstaller, "flush ruleset") {
		t.Fatal("VPS uninstall key-preservation or firewall ownership contract is incomplete")
	}
	commandGenerator := read(t, filepath.Join(root, "scripts", "generate-vps-install-command.sh"))
	for _, required := range []string{"channel-vps-install-command", "install-vps-$VERSION.command.txt", "--gateway-public-key", "--admin-public-key", "--install-dependencies", "--apply"} {
		if !strings.Contains(commandGenerator, required) {
			t.Errorf("VPS command generator missing %q", required)
		}
	}
}

func TestSafeApplyPrivilegesAreIsolatedBehindSocketAndIndependentTimer(t *testing.T) {
	root := repositoryRoot(t)
	socket := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.socket"))
	for _, required := range []string{"ListenStream=/run/gateway-vpn/network-broker.sock", "SocketUser=gateway-vpn", "SocketMode=0600"} {
		if !strings.Contains(socket, required) {
			t.Errorf("broker socket missing %q", required)
		}
	}
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	for _, required := range []string{"network-broker", "User=" /* root is intentionally implicit */, "CAP_NET_ADMIN", "CAP_NET_RAW", "NoNewPrivileges=yes", "/var/lib/gateway-vpn-privileged/network-transactions"} {
		if required == "User=" {
			if strings.Contains(broker, required) {
				t.Error("broker service must run as the default root user, not switch identities")
			}
			continue
		}
		if !strings.Contains(broker, required) {
			t.Errorf("broker service missing %q", required)
		}
	}
	timer := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-rollback@.timer"))
	service := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-rollback@.service"))
	if !strings.Contains(timer, "OnActiveSec=60s") || !strings.Contains(service, "network-rollback --id %i") {
		t.Fatal("independent rollback timer/helper contract is incomplete")
	}
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	if !strings.Contains(tmpfiles, "d /var/lib/gateway-vpn-privileged/network-transactions 0700 root root") {
		t.Fatal("network transaction root is not root-owned")
	}
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	if strings.Contains(control, "CAP_NET_ADMIN") || !strings.Contains(control, "gateway-vpn-network-recovery.service") {
		t.Fatal("control plane gained privileges or lost boot recovery ordering")
	}
	if !strings.Contains(control, "systemd-networkd.service") || !strings.Contains(control, "AF_NETLINK") {
		t.Fatal("control plane lacks networkd lease or link-event runtime contract")
	}
	if !strings.Contains(broker, "/etc/systemd/journald@gateway-vpn.conf.d") {
		t.Fatal("root broker cannot atomically synchronize the fixed journald namespace drop-in")
	}
	recovery := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-recovery.service"))
	for name, unit := range map[string]string{"broker": broker, "recovery": recovery} {
		if !strings.Contains(unit, "CAP_FOWNER") {
			t.Errorf("%s cannot enforce modes on gateway-vpn-owned SQLite recovery directories", name)
		}
		if !strings.Contains(unit, "ReadWritePaths=") || !strings.Contains(unit, "/var/lib/gateway-vpn ") {
			t.Errorf("%s cannot create SQLite WAL/recovery state under the managed state root", name)
		}
		for _, protected := range []string{"/var/lib/gateway-vpn/secrets", "/var/lib/gateway-vpn/tls", "/var/lib/gateway-vpn/subscriptions", "/var/lib/gateway-vpn/mihomo", "/var/lib/gateway-vpn/update-staging"} {
			if !strings.Contains(unit, "ReadOnlyPaths=") || !strings.Contains(unit, protected) {
				t.Errorf("%s does not retain a read-only mount for %s", name, protected)
			}
		}
		for _, line := range strings.Split(unit, "\n") {
			if strings.HasPrefix(line, "ReadWritePaths=") && strings.Contains(line, "/var/lib/gateway-vpn/state.db") {
				t.Errorf("%s relies on a not-yet-existing SQLite file instead of a writable state root", name)
			}
		}
	}
	for _, required := range []string{
		"ExecStartPost=/usr/bin/chown -R --no-dereference gateway-vpn:gateway-vpn /var/lib/gateway-vpn/backups /var/lib/gateway-vpn/recovery",
		"ExecStartPost=/usr/bin/chown --no-dereference gateway-vpn:gateway-vpn /var/lib/gateway-vpn/state.db",
		"ExecStartPost=/usr/bin/find /var/lib/gateway-vpn -maxdepth 1 -type f -name state.db-* -exec /usr/bin/chown --no-dereference gateway-vpn:gateway-vpn {} +",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("network recovery does not return managed database state to the control-plane identity: missing %q", required)
		}
	}
	networkd := read(t, filepath.Join(root, "packaging", "systemd-networkd", "80-gateway-vpn-hilink.network"))
	for _, required := range []string{"ID_VENDOR_ID=12d1", "DHCP=ipv4", "UseRoutes=no", "UseGateway=no", "IPv6AcceptRA=no"} {
		if !strings.Contains(networkd, required) {
			t.Errorf("HiLink networkd policy missing %q", required)
		}
	}
	lanNetwork := read(t, filepath.Join(root, "packaging", "systemd-networkd", "05-gateway-vpn-lan.network.in"))
	for _, required := range []string{"Name=__LAN_INTERFACE__", "Address=__LAN_ADDRESS__", "DHCP=no", "IPv6AcceptRA=no", "LinkLocalAddressing=no"} {
		if !strings.Contains(lanNetwork, required) {
			t.Errorf("persistent LAN networkd policy missing %q", required)
		}
	}
	lanNetDev := read(t, filepath.Join(root, "packaging", "systemd-networkd", "05-gateway-vpn-lan.netdev"))
	for _, required := range []string{"Name=gateway-vpn-lan", "Kind=bridge", "STP=yes"} {
		if !strings.Contains(lanNetDev, required) {
			t.Errorf("persistent LAN bridge netdev policy missing %q", required)
		}
	}
	lanMember := read(t, filepath.Join(root, "packaging", "systemd-networkd", "06-gateway-vpn-lan-member.network.in"))
	for _, required := range []string{"Name=__LAN_MEMBER__", "Bridge=gateway-vpn-lan", "DHCP=no", "IPv6AcceptRA=no", "RequiredForOnline=no"} {
		if !strings.Contains(lanMember, required) {
			t.Errorf("persistent LAN bridge member policy missing %q", required)
		}
	}
}

func TestGatewayFirstInstallRecoveryIsDurableOwnedAndSerialized(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{"trap 'rollback_install $?' ERR EXIT", "trap 'rollback_install 130' INT", "trap 'rollback_install 143' TERM"} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer does not recover nonzero exit/signal: missing %q", required)
		}
	}
	recovery := read(t, filepath.Join(root, "scripts", "recover-gateway-install.sh"))
	for _, required := range []string{"/run/lock/gateway-vpn-install.lock", "flock -n 9", "Gateway recovery marker field count is invalid", "old_ipv4_forward", "preserve_state_root", "preserve_lan_address", "lan_members", "lan_member_was_up", "ssh_was_enabled", "ssh_was_active", "ip link set dev \"$member\" nomaster", "ip link delete dev \"$LAN_INTERFACE\" type bridge", "systemctl stop ssh.service", "nft delete table inet gateway_vpn", "ip link delete dev wg-mgmt", "active marker retained for retry", "if ((FAILED))", "rolled-back-"} {
		if !strings.Contains(recovery, required) {
			t.Errorf("Gateway recovery missing %q", required)
		}
	}
	if strings.Contains(recovery, "flush ruleset") || strings.Index(recovery, "if ((FAILED))") > strings.Index(recovery, "mv -f \"$MARKER\"") {
		t.Fatal("Gateway recovery can discard its marker before verified owned-state cleanup")
	}
	installRecovery := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-install-recovery.service"))
	for _, required := range []string{"gateway-vpn-update-recovery.service", "gateway-vpn-database-restore-boot.service", "gateway-vpn-network-recovery.service", "gateway-vpn-network-broker.socket", "gateway-vpn-network-broker.service"} {
		if !strings.Contains(installRecovery, required) {
			t.Errorf("first-install boot recovery is not ordered before %q", required)
		}
	}
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	for _, required := range []string{"/run/lock/gateway-vpn-install.lock", "Recover the interrupted Gateway install", "05-gateway-vpn-lan.network", "05-gateway-vpn-lan.netdev", "lan_members", "ip link set dev \"$member\" nomaster", "ip link delete dev \"$LAN_INTERFACE\" type bridge", "systemctl stop ssh.service", "nft delete table inet gateway_vpn", "ip link delete dev wg-mgmt"} {
		if !strings.Contains(uninstaller, required) {
			t.Errorf("Gateway uninstall missing %q", required)
		}
	}
}

func TestFirewallGuardIsIndependentPrivilegedQuarantineService(t *testing.T) {
	root := repositoryRoot(t)
	guard := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-firewall-guard.service"))
	for _, required := range []string{
		"firewall-guard --config /etc/gateway-vpn/config.yaml --apply",
		"Requires=gateway-vpn-firewall.service",
		"RuntimeDirectory=gateway-vpn-firewall-guard",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"Restart=always",
	} {
		if !strings.Contains(guard, required) {
			t.Errorf("firewall guard unit missing %q", required)
		}
	}
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	if !strings.Contains(control, "Requires=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service") {
		t.Fatal("control plane can start without the independent firewall guard")
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	if !strings.Contains(installer, "systemctl enable gateway-vpn-firewall.service gateway-vpn-firewall-guard.service") {
		t.Fatal("installer does not enable the firewall guard")
	}
}

func TestFirewallGuardNetNSHarnessCoversOwnedDeleteAndGlobalFlush(t *testing.T) {
	root := repositoryRoot(t)
	harness := read(t, filepath.Join(root, "test", "netns", "firewall_guard.sh"))
	for _, required := range []string{
		"nft delete table inet gateway_vpn",
		"nft flush ruleset",
		"firewall_schema_generation",
		"active_tun_interfaces",
		"useradd --system --no-create-home --shell /usr/sbin/nologin",
		"gateway-vpn-mihomo",
		"ip route get 1.1.1.1 mark 0x1101",
		"ip route get 1.1.1.1 >/dev/null",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("firewall netns harness missing %q", required)
		}
	}
	if strings.Contains(harness, "| grep -q") {
		t.Fatal("firewall netns harness uses grep -q under pipefail and can fail on upstream SIGPIPE")
	}
}

func TestStartupPolicyNetNSHarnessCoversBootRestartAndDirectIsolation(t *testing.T) {
	root := repositoryRoot(t)
	harness := read(t, filepath.Join(root, "test", "netns", "startup_policy.sh"))
	for _, required := range []string{
		"GATEWAY_VPN_STARTUP_POLICY_INTEGRATION=1",
		"gated-boot", "ungated-activate", "same-boot-restart", "next-gated-boot",
		"firewall-boot --config", "PATH_BLOCKED",
		"ip route get 1.1.1.1 mark 0x1101", "ip route get 1.1.1.1 >/dev/null",
		"useradd --system --no-create-home --shell /usr/sbin/nologin",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("startup policy netns harness missing %q", required)
		}
	}
	if strings.Contains(harness, "| grep -q") {
		t.Fatal("startup policy netns harness uses grep -q under pipefail and can fail on upstream SIGPIPE")
	}
}

func TestLANBridgeSSHHarnessCoversTwoMembersAndUplinkIsolation(t *testing.T) {
	root := repositoryRoot(t)
	harness := read(t, filepath.Join(root, "test", "netns", "lan_bridge_ssh.sh"))
	for _, required := range []string{
		"type bridge stp_state 1 forward_delay 4",
		"link set lanp1 master gateway-vpn-lan",
		"link set lanp2 master gateway-vpn-lan",
		"address add 192.168.200.1/24 dev gateway-vpn-lan",
		`iifname "gateway-vpn-lan" tcp dport 22 accept`,
		"/dev/tcp/192.168.200.1/22",
		"/dev/tcp/192.168.8.2/22",
		"TCP/22 was exposed through the non-LAN uplink",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("LAN bridge SSH netns harness missing %q", required)
		}
	}
}

func TestGitHubCIUsesPinnedUbuntuSystemdGate(t *testing.T) {
	root := repositoryRoot(t)
	workflow := read(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	script := read(t, filepath.Join(root, "test", "systemd", "verify_units.sh"))
	for _, required := range []string{
		"ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
		"/workspace/test/systemd/verify_units.sh",
		"systemd-analyze verify",
		"wg-quick@.service",
		"packaging/vps/systemd",
	} {
		if !strings.Contains(workflow+script, required) {
			t.Errorf("pinned systemd CI gate missing %q", required)
		}
	}
	if strings.Contains(workflow, "ubuntu:24.04") {
		t.Fatal("systemd CI gate uses a mutable Ubuntu image tag")
	}
}

func TestSystemdRehearsalImageIsPinnedAndTargetScoped(t *testing.T) {
	root := repositoryRoot(t)
	dockerfile := read(t, filepath.Join(root, "test", "systemd", "Dockerfile.ubuntu24"))
	for _, required := range []string{
		"FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
		"systemd-networkd.service",
		"systemd-timesyncd.service",
		"ConditionVirtualization=",
		"dbus",
		"wireguard-tools",
		"CMD [\"/sbin/init\"]",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("systemd rehearsal image missing %q", required)
		}
	}
	for _, forbidden := range []string{"FROM ubuntu:24.04", "apt-get upgrade", "apt-get dist-upgrade", "curl |"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Errorf("systemd rehearsal image contains forbidden %q", forbidden)
		}
	}
}

func TestInstallersPreserveReleaseVersionAcrossOSRelease(t *testing.T) {
	root := repositoryRoot(t)
	bareVersion := regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_])VERSION=|\$VERSION(?:[^_A-Za-z0-9]|$)`)
	for _, name := range []string{"install-gateway.sh", "install-vps.sh"} {
		installer := read(t, filepath.Join(root, "scripts", name))
		for _, required := range []string{
			`RELEASE_VERSION=""`,
			`--version) RELEASE_VERSION=${2:?}`,
			`source /etc/os-release`,
			`releases/v$RELEASE_VERSION`,
		} {
			if !strings.Contains(installer, required) {
				t.Errorf("%s does not preserve release identity across os-release: missing %q", name, required)
			}
		}
		if match := bareVersion.FindString(installer); match != "" {
			t.Errorf("%s reuses os-release's reserved VERSION variable: %q", name, match)
		}
	}
}

func TestMihomoServiceConditionAndPermissionsAreFailClosed(t *testing.T) {
	root := repositoryRoot(t)
	service := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-mihomo.service"))
	if !strings.Contains(service, "ConditionPathExists=/var/lib/gateway-vpn/mihomo/active/config.yaml") || !strings.Contains(service, "Requires=gateway-vpn-firewall.service") {
		t.Fatal("Mihomo service can start without firewall or an active generation")
	}
	if strings.Contains(service, "ReadWritePaths=/var/lib/gateway-vpn/mihomo") || !strings.Contains(service, "ReadOnlyPaths=/var/lib/gateway-vpn/mihomo") {
		t.Fatal("Mihomo service can mutate immutable generations")
	}
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	for _, required := range []string{
		"d /var/lib/gateway-vpn/mihomo 0750 gateway-vpn gateway-vpn",
		"d /var/lib/gateway-vpn/mihomo/generations 0750 gateway-vpn gateway-vpn",
		"d /var/lib/gateway-vpn/mihomo/state 0700 gateway-vpn gateway-vpn",
	} {
		if !strings.Contains(tmpfiles, required) {
			t.Errorf("Mihomo tmpfiles policy missing %q", required)
		}
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	if !strings.Contains(installer, "gateway-vpn-mihomo.service gateway-vpn.service") {
		t.Fatal("installer does not enable conditional Mihomo service for reboot LKG recovery")
	}
}

func TestIsolatedDataPlaneUsersHaveSeparatedStateDirectories(t *testing.T) {
	root := repositoryRoot(t)
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	for _, required := range []string{
		"d /var/lib/gateway-vpn 0710 gateway-vpn gateway-vpn",
		"d /var/lib/gateway-vpn/secrets 0700 gateway-vpn gateway-vpn",
		"d /var/lib/gateway-vpn/mihomo 0750 gateway-vpn gateway-vpn",
	} {
		if !strings.Contains(tmpfiles, required) {
			t.Errorf("service state traversal policy missing %q", required)
		}
	}
	if strings.Contains(tmpfiles, "d /var/lib/gateway-vpn 0750") || strings.Contains(tmpfiles, "d /var/lib/gateway-vpn 0770") {
		t.Fatal("shared service group must not be able to list or write the state root")
	}
	sysusers := read(t, filepath.Join(root, "packaging", "sysusers.d", "gateway-vpn.conf"))
	if !strings.Contains(sysusers, "m gateway-vpn-mihomo gateway-vpn") {
		t.Fatal("Mihomo service user is missing traversal-only group membership")
	}
	if !strings.Contains(sysusers, `u gateway-vpn-dns - "Gateway VPN dnsmasq" /var/lib/gateway-vpn-dnsmasq /usr/sbin/nologin`) {
		t.Fatal("dnsmasq service user does not have the isolated state root as its home")
	}
	if strings.Contains(tmpfiles, "/var/lib/gateway-vpn/dnsmasq") {
		t.Fatal("dnsmasq state must not be created inside the application state tree")
	}
	dnsmasqService := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-dnsmasq.service"))
	for _, required := range []string{"User=gateway-vpn-dns", "Group=gateway-vpn", "UMask=0077", "StateDirectory=gateway-vpn-dnsmasq", "StateDirectoryMode=0700", "ReadWritePaths=/var/lib/gateway-vpn-dnsmasq"} {
		if !strings.Contains(dnsmasqService, required) {
			t.Errorf("dnsmasq service identity policy missing %q", required)
		}
	}
	for _, forbidden := range []string{"CAP_SETUID", "CAP_SETGID"} {
		if strings.Contains(dnsmasqService, forbidden) {
			t.Errorf("dnsmasq service retains unnecessary privilege %q", forbidden)
		}
	}
	dnsmasqConfig := read(t, filepath.Join(root, "packaging", "dnsmasq", "dnsmasq.conf.in"))
	if !strings.Contains(dnsmasqConfig, "dhcp-leasefile=/var/lib/gateway-vpn-dnsmasq/dnsmasq.leases") || strings.Contains(dnsmasqConfig, "/var/lib/gateway-vpn/dnsmasq") {
		t.Fatal("dnsmasq lease path is not isolated from the application state tree")
	}
	for _, forbidden := range []string{"user=", "group="} {
		if strings.Contains(dnsmasqConfig, forbidden) {
			t.Errorf("dnsmasq duplicates systemd privilege drop with %q", forbidden)
		}
	}
	backend := read(t, filepath.Join(root, "internal", "networkapply", "ubuntu_backend.go"))
	if !strings.Contains(backend, "dhcp-leasefile=/var/lib/gateway-vpn-dnsmasq/dnsmasq.leases") || strings.Contains(backend, "/var/lib/gateway-vpn/dnsmasq") {
		t.Fatal("safe-apply renderer does not preserve the isolated dnsmasq lease path")
	}
	rollback := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-rollback@.service"))
	if !strings.Contains(rollback, "/var/lib/gateway-vpn-dnsmasq") || strings.Contains(rollback, "/var/lib/gateway-vpn/dnsmasq") {
		t.Fatal("network rollback unit does not use the isolated dnsmasq state root")
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	recovery := read(t, filepath.Join(root, "scripts", "recover-gateway-install.sh"))
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	for name, content := range map[string]string{"installer": installer, "recovery": recovery, "uninstaller": uninstaller} {
		if !strings.Contains(content, "/var/lib/gateway-vpn-dnsmasq") {
			t.Errorf("%s does not manage the isolated dnsmasq state root", name)
		}
	}
	for _, required := range []string{
		`$(stat -c '%U:%G:%a' /var/lib/gateway-vpn-dnsmasq/dnsmasq.leases) == "gateway-vpn-dns:gateway-vpn:644"`,
		`Installed Gateway dnsmasq config differs from the requested LAN policy`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("existing-install dnsmasq audit missing %q", required)
		}
	}
	listenerGate := strings.Index(installer, `mapfile -t DNS_LISTEN_ADDRESSES`)
	freshInstallBranch := strings.Index(installer, "  EXISTING=1\nelse\n")
	if listenerGate < 0 || freshInstallBranch < 0 || listenerGate < freshInstallBranch {
		t.Fatal("port-53 conflict gate must run only for a fresh install, after exact existing-install classification")
	}
}

func TestDatabaseRestoreIsBootOrderedFailClosedAndRootTransactionScoped(t *testing.T) {
	root := repositoryRoot(t)
	restore := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-database-restore.service"))
	for _, required := range []string{
		"ConditionPathExists=/var/lib/gateway-vpn/recovery/pending-restore.json",
		"ExecStartPre=/opt/gateway-vpn/current/bin/gateway-vpn firewall-boot --config /etc/gateway-vpn/config.yaml --apply",
		"database-restore --config /etc/gateway-vpn/config.yaml --transaction-root /var/lib/gateway-vpn-privileged/restore-transactions --apply",
		"GATEWAY_VPN_DATABASE_RESTORE_UNIT=1",
		"Conflicts=gateway-vpn.service gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service",
		"OnSuccess=gateway-vpn-database-restore-resume.service",
		"OnFailure=gateway-vpn-database-restore-resume.service",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN",
		"ReadWritePaths=/etc/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged/restore-transactions /run",
	} {
		if !strings.Contains(restore, required) {
			t.Errorf("database restore unit missing %q", required)
		}
	}
	if strings.Contains(restore, "WantedBy=") || strings.Contains(restore, "gateway-vpn-database-restore-boot.service") {
		t.Fatal("destructive runtime restore unit must never join a boot target transaction")
	}
	dispatch := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-database-restore-dispatch.service"))
	for _, required := range []string{
		"ConditionPathExists=/var/lib/gateway-vpn/recovery/pending-restore.json",
		"ExecStartPre=/usr/bin/sleep 1",
		"ExecStart=/usr/bin/systemctl start --no-block gateway-vpn-database-restore.service",
		"CapabilityBoundingSet=",
	} {
		if !strings.Contains(dispatch, required) {
			t.Errorf("database restore dispatcher missing %q", required)
		}
	}
	if strings.Contains(dispatch, "WantedBy=") || strings.Contains(dispatch, "CAP_") {
		t.Fatal("database restore dispatcher must be static and capability-free")
	}
	bootRestore := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-database-restore-boot.service"))
	for _, required := range []string{
		"DefaultDependencies=no",
		"ConditionPathExists=/var/lib/gateway-vpn/recovery/pending-restore.json",
		"Requires=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service",
		"Before=gateway-vpn-network-recovery.service gateway-vpn-watchdog.service gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service",
		"GATEWAY_VPN_DATABASE_RESTORE_UNIT=1",
		"RemainAfterExit=yes",
		"ExecStartPre=/opt/gateway-vpn/current/bin/gateway-vpn firewall-boot --config /etc/gateway-vpn/config.yaml --apply",
		"database-restore --config /etc/gateway-vpn/config.yaml --transaction-root /var/lib/gateway-vpn-privileged/restore-transactions --apply --boot-recovery",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(bootRestore, required) {
			t.Errorf("database boot restore unit missing %q", required)
		}
	}
	for _, forbidden := range []string{"Conflicts=", "OnSuccess=", "OnFailure="} {
		if strings.Contains(bootRestore, forbidden) {
			t.Errorf("database boot restore unit contains runtime-only directive %q", forbidden)
		}
	}
	resume := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-database-restore-resume.service"))
	if !strings.Contains(resume, "systemctl start gateway-vpn-network-broker.socket") || !strings.Contains(resume, "systemctl start gateway-vpn.service") || strings.Contains(resume, "gateway-vpn-mihomo.service") {
		t.Fatal("restore resume must restart management while leaving Mihomo to verified reconciliation")
	}
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	socket := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.socket"))
	if !strings.Contains(control, "gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service") || strings.Contains(control, "gateway-vpn-database-restore.service") || !strings.Contains(broker, "gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service") || strings.Contains(broker, "gateway-vpn-database-restore.service") || !strings.Contains(socket, "DefaultDependencies=no") || !strings.Contains(socket, "WantedBy=multi-user.target") || strings.Contains(socket, "WantedBy=sockets.target") {
		t.Fatal("control plane or broker can race a boot-time pending restore")
	}
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	if !strings.Contains(tmpfiles, "d /var/lib/gateway-vpn-privileged/restore-transactions 0700 root root") {
		t.Fatal("restore transaction journal is not root-owned")
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	for _, unit := range []string{"gateway-vpn-database-restore-boot.service", "gateway-vpn-database-restore-dispatch.service", "gateway-vpn-database-restore.service", "gateway-vpn-database-restore-resume.service"} {
		if !strings.Contains(installer, unit) || !strings.Contains(uninstaller, unit) {
			t.Errorf("installer lifecycle is missing %s", unit)
		}
	}
	if !strings.Contains(installer, "gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service") || strings.Contains(installer, "gateway-vpn-network-recovery.service gateway-vpn-database-restore.service gateway-vpn-network-broker.socket") {
		t.Fatal("installer must enable only the non-conflicting database boot recovery unit")
	}
}

func TestSignedUpdateIsBootRecoverableAndRootTransactionScoped(t *testing.T) {
	root := repositoryRoot(t)
	update := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update.service"))
	for _, required := range []string{
		"ConditionPathExists=/var/lib/gateway-vpn/update-staging/pending-update.json",
		"GATEWAY_VPN_UPDATE_UNIT=1",
		"ExecStartPre=/opt/gateway-vpn/recovery/bin/gateway-vpn firewall-boot --config /etc/gateway-vpn/config.yaml --apply",
		"update-apply --config /etc/gateway-vpn/config.yaml --apply",
		"Wants=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service",
		"Requires=gateway-vpn-update-recovery.service",
		"OnFailure=gateway-vpn-update-resume.service",
		"ReadWritePaths=/opt/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged /run",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN",
	} {
		if !strings.Contains(update, required) {
			t.Errorf("signed update unit missing %q", required)
		}
	}
	recovery := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-recovery.service"))
	for _, required := range []string{
		"DefaultDependencies=no",
		"RemainAfterExit=yes",
		"GATEWAY_VPN_UPDATE_RECOVERY_UNIT=1",
		"ExecStart=/opt/gateway-vpn/recovery/bin/gateway-vpn update-recover",
		"update-recover --config /etc/gateway-vpn/config.yaml --apply",
		"Before=gateway-vpn-database-restore-boot.service gateway-vpn-database-restore.service gateway-vpn-network-recovery.service gateway-vpn-watchdog.service gateway-vpn-network-broker.socket",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("update recovery unit missing %q", required)
		}
	}
	if strings.Contains(recovery, "ExecStartPost=") || strings.Contains(recovery, "systemctl start --no-block") {
		t.Fatal("update recovery must finish before a separate owner resumes management")
	}
	for name, unit := range map[string]string{"update": update, "recovery": recovery} {
		for _, line := range strings.Split(unit, "\n") {
			if strings.HasPrefix(line, "Requires=") && (strings.Contains(line, "gateway-vpn-firewall.service") || strings.Contains(line, "gateway-vpn-firewall-guard.service")) {
				t.Errorf("%s unit can self-terminate while replacing firewall schema: %s", name, line)
			}
		}
	}
	finalize := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-finalize.service"))
	timer := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-finalize.timer"))
	if !strings.Contains(finalize, "GATEWAY_VPN_UPDATE_FINALIZE_UNIT=1") || !strings.Contains(finalize, "ExecStart=/opt/gateway-vpn/recovery/bin/gateway-vpn update-finalize") || !strings.Contains(finalize, "OnFailure=gateway-vpn-update-resume.service") || !strings.Contains(timer, "OnUnitActiveSec=15min") || !strings.Contains(timer, "Persistent=true") {
		t.Fatal("stability-window finalization contract is incomplete")
	}
	resume := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-resume.service"))
	if !strings.Contains(resume, "systemctl restart gateway-vpn-update-recovery.service") || !strings.Contains(resume, "systemctl start gateway-vpn-network-broker.socket") || !strings.Contains(resume, "systemctl start gateway-vpn.service") || !strings.Contains(resume, "systemctl reset-failed gateway-vpn-update.service gateway-vpn-update-finalize.service") {
		t.Fatal("failed update does not recover before resuming management")
	}
	if !strings.Contains(resume, "Wants=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service") || strings.Contains(resume, "Requires=gateway-vpn-firewall.service") {
		t.Fatal("update resume can self-terminate while recovery replaces firewall schema")
	}
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	for _, required := range []string{
		"d /var/lib/gateway-vpn/update-staging 0700 gateway-vpn gateway-vpn",
		"d /var/lib/gateway-vpn-privileged 0700 root root",
		"d /var/lib/gateway-vpn-privileged/update-transactions 0700 root root",
		"d /var/lib/gateway-vpn-privileged/update-snapshots 0700 root root",
	} {
		if !strings.Contains(tmpfiles, required) {
			t.Errorf("update tmpfiles policy missing %q", required)
		}
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	if !strings.Contains(installer, "/opt/gateway-vpn/recovery") {
		t.Fatal("installer does not pin an independent recovery release pointer")
	}
	for _, unit := range []string{"gateway-vpn-update.service", "gateway-vpn-update-recovery.service", "gateway-vpn-update-resume.service", "gateway-vpn-update-finalize.service", "gateway-vpn-update-finalize.timer"} {
		if !strings.Contains(installer, unit) || !strings.Contains(uninstaller, unit) {
			t.Errorf("installer lifecycle is missing %s", unit)
		}
	}
	if !strings.Contains(installer, "systemctl enable --now gateway-vpn-update-finalize.timer") || !strings.Contains(installer, "systemctl is-active --quiet gateway-vpn-update-finalize.timer") {
		t.Fatal("installer does not activate and verify the stability-window timer")
	}
	updateUnit := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update.service"))
	if !strings.Contains(updateUnit, "ExecStartPost=/usr/bin/systemctl start gateway-vpn-update-finalize.timer") {
		t.Fatal("successful signed update does not ensure the stability-window timer is active")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func read(t *testing.T, filename string) string {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
