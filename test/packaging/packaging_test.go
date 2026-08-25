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
	for _, required := range []string{"table inet gateway_vpn", "firewall_schema_generation", "type mark", "elements = { 1 }", "chain input", "chain forward", "chain output", "policy drop", "gateway-vpn PATH_BLOCKED"} {
		if !strings.Contains(boot, required) {
			t.Errorf("boot ruleset missing %q", required)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "policy accept", "type integer", "oifname @hilink_interfaces accept"} {
		if strings.Contains(boot, forbidden) {
			t.Errorf("boot ruleset contains forbidden %q", forbidden)
		}
	}
	for _, unitName := range []string{"gateway-vpn-firewall.service", "gateway-vpn-firewall-guard.service", "gateway-vpn.service", "gateway-vpn-mihomo.service", "gateway-vpn-dnsmasq.service"} {
		unit := read(t, filepath.Join(root, "packaging", "systemd", unitName))
		for _, gate := range []string{"ConditionPathExists=|!/var/lib/gateway-vpn-privileged/install-transactions/active", "ConditionPathExists=|/run/gateway-vpn-install-authorized", "ConditionPathIsSymbolicLink=!/var/lib/gateway-vpn-privileged/install-transactions/active", "ConditionPathIsSymbolicLink=!/run/gateway-vpn-install-authorized"} {
			if !strings.Contains(unit, gate) {
				t.Errorf("%s can start during an incomplete install: missing %q", unitName, gate)
			}
		}
	}
}

func TestInstallerIsExplicitAndUbuntuScoped(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{"VERSION_ID:-} == 24.04", "manifest.sha256", "manifest.json", "release.sig", "--trusted-update-key", "release-verify", "release.json", "mihomo-api-secret", "--install-dependencies", "--dependency-preflight-only", "iproute2", "nftables", "wireguard-tools", "kmod", "procps", "dnsmasq", "apt-get -s install --no-install-recommends --no-remove --no-upgrade", "APT Gateway dependency plan attempts to remove packages", "APT Gateway dependency plan attempts to upgrade installed packages", "full host preflight NOT_RUN", "/run/lock/gateway-vpn-install.lock", "recover-gateway-install.sh", "gateway-vpn-install-recovery.service", "old_ipv4_forward=%s", "preserve_state_root=%s", "90-gateway-vpn-ipv4-forwarding.conf", "70-gateway-vpn-lan.network", "gateway-install-preflight", "INSTALLED_NOT_READY", "--apply", "nft --check", "nft --file /etc/gateway-vpn/nftables/boot.nft", "Gateway VPN requires Ubuntu 24.04"} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer missing %q", required)
		}
	}
	if strings.Contains(installer, "apt upgrade") || strings.Contains(installer, "apt-get upgrade") || strings.Contains(installer, "apt-get full-upgrade") || strings.Contains(installer, "apt-get dist-upgrade") || strings.Contains(installer, "autoremove") || strings.Contains(installer, "curl |") {
		t.Fatal("installer contains an unsafe opaque upgrade/download path")
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
	for _, required := range []string{"MIHOMO_VERSION", "SIGNING_PRIVATE_KEY", "buildinfo.MihomoVersion", "mihomo_sha256", "gateway_api_contract", "mihomo_api_contract", "database_schema_maximum", "manifest.json", "release.sig", "release-sign", "sbom.spdx.json", "provenance.intoto.json", "release.json", "sha256sum --binary"} {
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

func TestChannelBuilderPinsBootstrapBeforeSudoAndProducesExactCommand(t *testing.T) {
	root := repositoryRoot(t)
	builder := read(t, filepath.Join(root, "scripts", "build-channel.sh"))
	for _, required := range []string{
		"channel-sign", "channel-verify", "channel-install-command",
		"channel-$CHANNEL.json", "channel-$CHANNEL.sig", "update-signing.pub",
		"--github-repository", "--release-tag", "--source-commit", "--apply",
		"install-gateway-$VERSION.command.txt", "clean committed worktree",
	} {
		if !strings.Contains(builder, required) {
			t.Errorf("channel builder missing %q", required)
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
		"release-verify", "--initial-install", "vps-release-verify", "channel-verify",
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
		"go vet ./...", "CGO_ENABLED=0 GOOS=linux GOARCH=amd64", "node --check", "bash -n scripts/*.sh",
		"sudo apt-get install --yes --no-install-recommends --no-upgrade", "firewall_guard.sh /tmp/gateway-vpn-netns",
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
		"validate_preserved_wg_config", "PRESERVED_WG_CONFIG", "preserve_wg_config=%s", ".gateway-vpn-wg-mgmt.conf.tmp",
		"/run/lock/gateway-vpn-vps-install.lock", "set -o noclobber", "0:0:600", "flock -n 9", "flock -u 9",
		"ip -4 route get 10.80.0.2", "ip -4 route get 10.80.0.10", "INSTALLED_NOT_READY",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("VPS installer missing %q", required)
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
	for _, required := range []string{"network-broker", "User=" /* root is intentionally implicit */, "CAP_NET_ADMIN", "CAP_NET_RAW", "NoNewPrivileges=yes", "/var/lib/gateway-vpn-privileged/network-transactions", "/var/lib/gateway-vpn/secrets/wireguard.yaml"} {
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
	networkd := read(t, filepath.Join(root, "packaging", "systemd-networkd", "80-gateway-vpn-hilink.network"))
	for _, required := range []string{"ID_VENDOR_ID=12d1", "DHCP=ipv4", "UseRoutes=no", "UseGateway=no", "IPv6AcceptRA=no"} {
		if !strings.Contains(networkd, required) {
			t.Errorf("HiLink networkd policy missing %q", required)
		}
	}
	lanNetwork := read(t, filepath.Join(root, "packaging", "systemd-networkd", "70-gateway-vpn-lan.network.in"))
	for _, required := range []string{"Name=__LAN_INTERFACE__", "Address=__LAN_ADDRESS__", "DHCP=no", "IPv6AcceptRA=no", "LinkLocalAddressing=no"} {
		if !strings.Contains(lanNetwork, required) {
			t.Errorf("persistent LAN networkd policy missing %q", required)
		}
	}
}

func TestGatewayFirstInstallRecoveryIsDurableOwnedAndSerialized(t *testing.T) {
	root := repositoryRoot(t)
	recovery := read(t, filepath.Join(root, "scripts", "recover-gateway-install.sh"))
	for _, required := range []string{"/run/lock/gateway-vpn-install.lock", "flock -n 9", "Gateway recovery marker field count is invalid", "old_ipv4_forward", "preserve_state_root", "preserve_lan_address", "nft delete table inet gateway_vpn", "ip link delete dev wg-mgmt", "active marker retained for retry", "if ((FAILED))", "rolled-back-"} {
		if !strings.Contains(recovery, required) {
			t.Errorf("Gateway recovery missing %q", required)
		}
	}
	if strings.Contains(recovery, "flush ruleset") || strings.Index(recovery, "if ((FAILED))") > strings.Index(recovery, "mv -f \"$MARKER\"") {
		t.Fatal("Gateway recovery can discard its marker before verified owned-state cleanup")
	}
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	for _, required := range []string{"/run/lock/gateway-vpn-install.lock", "Recover the interrupted Gateway install", "70-gateway-vpn-lan.network", "nft delete table inet gateway_vpn", "ip link delete dev wg-mgmt"} {
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
	resume := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-database-restore-resume.service"))
	if !strings.Contains(resume, "systemctl start gateway-vpn-network-broker.socket") || !strings.Contains(resume, "systemctl start gateway-vpn.service") || strings.Contains(resume, "gateway-vpn-mihomo.service") {
		t.Fatal("restore resume must restart management while leaving Mihomo to verified reconciliation")
	}
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	if !strings.Contains(control, "After=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service gateway-vpn-network-recovery.service gateway-vpn-database-restore.service") || !strings.Contains(control, "gateway-vpn-database-restore.service") || !strings.Contains(broker, "After=gateway-vpn-update-recovery.service gateway-vpn-network-recovery.service gateway-vpn-database-restore.service") {
		t.Fatal("control plane or broker can race a boot-time pending restore")
	}
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	if !strings.Contains(tmpfiles, "d /var/lib/gateway-vpn-privileged/restore-transactions 0700 root root") {
		t.Fatal("restore transaction journal is not root-owned")
	}
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	for _, unit := range []string{"gateway-vpn-database-restore.service", "gateway-vpn-database-restore-resume.service"} {
		if !strings.Contains(installer, unit) || !strings.Contains(uninstaller, unit) {
			t.Errorf("installer lifecycle is missing %s", unit)
		}
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
		"Requires=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service",
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
		"Before=gateway-vpn-database-restore.service gateway-vpn-network-recovery.service gateway-vpn-network-broker.socket",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("update recovery unit missing %q", required)
		}
	}
	finalize := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-finalize.service"))
	timer := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-finalize.timer"))
	if !strings.Contains(finalize, "GATEWAY_VPN_UPDATE_FINALIZE_UNIT=1") || !strings.Contains(finalize, "ExecStart=/opt/gateway-vpn/recovery/bin/gateway-vpn update-finalize") || !strings.Contains(finalize, "OnFailure=gateway-vpn-update-resume.service") || !strings.Contains(timer, "OnUnitActiveSec=15min") || !strings.Contains(timer, "Persistent=true") {
		t.Fatal("stability-window finalization contract is incomplete")
	}
	resume := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-resume.service"))
	if !strings.Contains(resume, "systemctl restart gateway-vpn-update-recovery.service") || !strings.Contains(resume, "systemctl start gateway-vpn-network-broker.socket") || !strings.Contains(resume, "systemctl start gateway-vpn.service") {
		t.Fatal("failed update does not recover before resuming management")
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
