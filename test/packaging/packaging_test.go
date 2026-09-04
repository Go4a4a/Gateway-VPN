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
	for _, required := range []string{"table inet gateway_vpn", "firewall_schema_generation", "type mark", "elements = { 8 }", "user_ingress_interfaces", "local_management_interfaces", "wireguard_ingress_listeners", "active_direct_interfaces", "active_direct_context", "active_direct_marks", "active_route_generation", "management_fabric_interfaces", "management_fabric_endpoints", "management_fabric_generation", "management_fabric_input", "management_fabric_forward", "management_fabric_postrouting", "management_fabric_prerouting", "chain prerouting", "chain postrouting", "chain forward_mss", "hook forward priority mangle; policy accept", "tcp flags syn tcp option maxseg size set rt mtu", "counter user_upload", "counter user_download", "counter service_upload", "counter service_download", "chain input", "chain forward", "chain output", "policy drop", "gateway-vpn PATH_BLOCKED"} {
		if !strings.Contains(boot, required) {
			t.Errorf("boot ruleset missing %q", required)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "type integer", "oifname @hilink_interfaces accept", "@LAN_INTERFACE@"} {
		if strings.Contains(boot, forbidden) {
			t.Errorf("boot ruleset contains forbidden %q", forbidden)
		}
	}
	if strings.Count(boot, "policy accept") != 1 || !strings.Contains(boot, "hook forward priority mangle; policy accept") {
		t.Fatal("only the non-filtering MSS mangle hook may use policy accept")
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

func TestReadmeKeepsVolatileReleaseStatusInProjectJournal(t *testing.T) {
	root := repositoryRoot(t)
	readme := read(t, filepath.Join(root, "README.md"))
	for _, required := range []string{
		"docs/PROJECT_STATUS.md",
		"bounded component watchdog",
		"текущий exact disposable-signed install/reinstall/uninstall/update/rollback rehearsal обеих ролей",
		"clean-Windows two-target deploy",
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README current-state boundary missing %q", required)
		}
	}
	for _, forbidden := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)schema-v?\d+`),
		regexp.MustCompile(`(?i)\d+-component watchdog`),
		regexp.MustCompile(`(?i)rehearsal[^.\n]*(ещё выполня|in progress|pending)`),
	} {
		if forbidden.MatchString(readme) {
			t.Errorf("README contains volatile or stale release-state snapshot %q", forbidden.String())
		}
	}
}

func TestOperationalDocsDoNotKeepObsoleteArchitectureSnapshots(t *testing.T) {
	root := repositoryRoot(t)
	for _, relative := range []string{
		filepath.Join("docs", "OPERATIONS.md"),
		filepath.Join("docs", "SECURITY.md"),
	} {
		document := read(t, filepath.Join(root, relative))
		for _, forbidden := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b17-component`),
			regexp.MustCompile(`(?i)fixed signed 17`),
			regexp.MustCompile(`(?i)schema-25 release supports only`),
		} {
			if forbidden.MatchString(document) {
				t.Errorf("%s contains obsolete architecture snapshot %q", relative, forbidden.String())
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
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{
		`$(stat -c '%U:%G:%a' /var/lib/gateway-vpn/secrets/management) == "root:root:700"`,
		`$(stat -c '%U:%G:%a' /var/lib/gateway-vpn-privileged/backup-exports) == "root:root:700"`,
		`$(stat -c '%U:%G:%a' /var/lib/gateway-vpn-privileged/management-fabric) == "root:root:700"`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway Management Fabric installer audit missing %q", required)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "bash -c", "%i", "EnvironmentFile=", "User=gateway-vpn\n"} {
		if strings.Contains(unit, forbidden) {
			t.Errorf("watchdog unit contains unsafe dynamic surface %q", forbidden)
		}
	}
	control := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn.service"))
	for _, required := range []string{"Type=notify", "NotifyAccess=all", "WatchdogSec=120s", "Requires=gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-watchdog.service", "Wants=gateway-vpn-network-broker.socket", "PartOf=gateway-vpn-watchdog.service", "ReadWritePaths=/var/lib/gateway-vpn /run/gateway-vpn-watchdog"} {
		if !strings.Contains(control, required) {
			t.Errorf("control hang-detection contract missing %q", required)
		}
	}
	if strings.Contains(control, "network-online.target") {
		t.Fatal("Gateway control plane must not wait for external network-online.target")
	}
	mihomo := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-mihomo.service"))
	if strings.Contains(mihomo, "network-online.target") {
		t.Fatal("Mihomo must start independently and tolerate dynamic/offline modems")
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
	installer = read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{"systemctl restart gateway-vpn-watchdog.service", "systemctl is-active --quiet gateway-vpn-watchdog.service", "watchdog_runtime_ready", "/run/gateway-vpn-watchdog/status.json", "/run/gateway-vpn-watchdog/control.json", `grep -Fq '"schema_version":1' /run/gateway-vpn-watchdog/status.json`, `grep -Fq '"schema_version":2' /run/gateway-vpn-watchdog/control.json`, `"database_ok":true`, `"workers_ok":true`, "status_age <= 660", "control_age <= 30"} {
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
	for _, required := range []string{"VERSION_ID:-} == 24.04", "manifest.sha256", "manifest.json", "release.sig", "--trusted-update-key", "release-verify", "release.json", "mihomo-api-secret", "--install-dependencies", "--dependency-preflight-only", "iproute2", "nftables", "wireguard-tools", "kmod", "procps", "dnsmasq-base", "openssh-server", "apt-get -s install --no-install-recommends --no-remove --no-upgrade", "APT Gateway dependency plan attempts to remove packages", "APT Gateway dependency plan attempts to upgrade installed packages", "full host preflight NOT_RUN", "ss -H -ltn \"sport = :53\"", "ss -H -lun \"sport = :53\"", "DHCP/DNS enable conflicts with an existing wildcard or Gateway LAN port 53 listener", "/run/lock/gateway-vpn-install.lock", "recover-gateway-install.sh", "gateway-vpn-install-recovery.service", "old_ipv4_forward=%s", "old_ipv4_src_valid_mark=%s", "preserve_state_root=%s", "lan_members=%s", "ssh_was_enabled=%s", "ssh_was_active=%s", "90-gateway-vpn-ipv4-forwarding.conf", "05-gateway-vpn-lan.network", "05-gateway-vpn-lan.netdev", "gateway-install-preflight", "INSTALLED_NOT_READY", "--apply", "nft --check", "nft --file /etc/gateway-vpn/nftables/boot.nft", "Gateway VPN requires Ubuntu 24.04"} {
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

func TestGatewayHostContractUpgradeIsSignedColdAndRecoverable(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	upgrader := read(t, filepath.Join(root, "scripts", "upgrade-gateway-host.sh"))
	recovery := read(t, filepath.Join(root, "scripts", "recover-gateway-host-upgrade.sh"))
	installRecovery := read(t, filepath.Join(root, "scripts", "recover-gateway-install.sh"))
	unit := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-host-upgrade-recovery.service"))

	for _, required := range []string{
		`exec "$ROOT_DIR/scripts/upgrade-gateway-host.sh"`,
		"--host-upgrade-inner",
		"Inherited host-upgrade transaction lock is invalid",
		"host_upgrade_inner_authorized",
		"Gateway NTP is unavailable inside the signed host-upgrade transaction; continuing with strict offline release and host verification",
		"Gateway NTP is blocked by the installed fail-closed policy; continuing with strict signed existing/upgrade verification",
		"Gateway clock is not reported as NTP-synchronized",
		"Gateway DNS is blocked by the installed fail-closed policy; continuing with strict signed existing/upgrade verification",
		"Requested Gateway version does not match signed release metadata",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer host-upgrade dispatch missing %q", required)
		}
	}
	if strings.Index(installer, `gateway-install-preflight --lan-interface`) > strings.Index(installer, `exec "$ROOT_DIR/scripts/upgrade-gateway-host.sh"`) {
		t.Fatal("host-upgrade dispatch occurs before the complete local host preflight")
	}
	if strings.Index(installer, `release-verify --release-dir "$RELEASE_DIR"`) < 0 ||
		strings.Index(installer, `release-verify --release-dir "$RELEASE_DIR"`) > strings.Index(installer, "Gateway NTP is blocked by the installed fail-closed policy") {
		t.Fatal("installed-host NTP exception occurs before candidate signature verification")
	}
	if strings.Count(installer, "host_upgrade_inner_authorized") < 3 ||
		!strings.Contains(installer, `[[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a' "$marker") == "0:0:600" ]]`) ||
		!strings.Contains(installer, `[[ $(sed -n 's/^state=//p' "$marker") == APPLYING ]]`) ||
		strings.Contains(installer, "$VERSION_PATTERN") {
		t.Fatal("inner host-upgrade NTP/DNS exception is not bound to the strict inherited transaction marker")
	}
	for _, required := range []string{
		`OLD_METADATA_VERSION=$(release_string gateway_version`,
		`NEW_METADATA_VERSION=$(release_string gateway_version`,
		`"$OLD_RELEASE/bin/gateway-vpnctl" release-verify`,
		`"$RELEASE_DIR/bin/gateway-vpnctl" release-verify`,
		"validate_completed_install_marker",
		"Host upgrade cannot combine release replacement with LAN reconfiguration",
		"Host upgrade cannot change DHCP policy",
		"Host upgrade cannot change SSH/SFTP policy",
		"Host upgrade cannot change WireGuard ingress policy",
		"Host upgrade cannot change boot or GRUB policy",
		`database-verify --database "$ROOTFS/var/lib/gateway-vpn/state.db"`,
		`/etc/systemd/system/multi-user.target.wants/gateway-vpn-host-upgrade-recovery.service`,
		`install -m 0700 "$OLD_RELEASE/bin/gateway-vpnctl" "$TOOLING/old-gateway-vpnctl"`,
		"write_marker SNAPSHOT_READY",
		"write_marker APPLYING",
		"write_marker CANDIDATE_READY",
		`GATEWAY_VPN_HOST_UPGRADE_INNER=1 "$RELEASE_DIR/scripts/install-gateway.sh"`,
		`--trusted-update-key "$TOOLING/update-signing.pub"`,
		"candidate_runtime_ready",
		"status_age <= 30 && control_age >= -5 && control_age <= 30",
		"Candidate Gateway runtime did not converge to a fresh healthy state",
		`if [[ $OLD_MARKER_FIELD_COUNT == 20 || $OLD_MARKER_FIELD_COUNT == 21 ]]; then`,
		`new_marker_value old_ipv4_src_valid_mark`,
		`($OLD_MARKER_FIELD_COUNT == 20 || $OLD_MARKER_FIELD_COUNT == 21) && $MERGED_FIELD_COUNT == 21`,
		`($OLD_MARKER_FIELD_COUNT != 20 && $OLD_MARKER_FIELD_COUNT != 21) && $MERGED_FIELD_COUNT == 18`,
		"Merged host-upgrade install marker does not preserve the original OS state",
		"/var/lib/gateway-vpn-privileged/update-rollback/pending.json",
		"update-lifecycle-check",
		"assert_no_conflicting_lifecycle",
	} {
		if !strings.Contains(upgrader, required) {
			t.Errorf("signed host upgrade contract missing %q", required)
		}
	}
	if strings.Contains(upgrader, "rm -rf /etc/gateway-vpn") {
		t.Fatal("host upgrade destroys persistent Gateway configuration instead of preserving it")
	}
	if strings.Contains(upgrader, `old_or_default ssh_socket_was_enabled`) || strings.Contains(upgrader, `new_marker_value ssh_socket_was_enabled`) {
		t.Fatal("host upgrade guesses unknown legacy pre-install ssh.socket state from the post-install marker")
	}
	for _, required := range []string{
		"ConditionPathExists=/var/lib/gateway-vpn-host-upgrade/active",
		"Before=gateway-vpn-install-recovery.service gateway-vpn-firewall.service",
		"GATEWAY_VPN_HOST_UPGRADE_RECOVERY_BOOT=1",
		"ReadWritePaths=/etc -/boot/grub /usr/libexec /usr/lib/sysusers.d /usr/lib/tmpfiles.d /opt /var/lib /var/log /run",
	} {
		if !strings.Contains(unit, required) {
			t.Errorf("host-upgrade boot recovery unit missing %q", required)
		}
	}
	if strings.Contains(unit, "ReadWritePaths=/etc /boot/grub") {
		t.Fatal("host-upgrade boot recovery incorrectly requires optional /boot/grub to exist")
	}
	if strings.Contains(unit, "ReadWritePaths=/etc -/boot/grub /usr/libexec /usr/lib/sysusers.d /usr/lib/tmpfiles.d /opt/gateway-vpn") {
		t.Fatal("host-upgrade recovery cannot remove owned root directories when each root is a separate mount point")
	}
	if strings.Contains(unit, "ProtectKernelTunables=yes") {
		t.Fatal("host-upgrade recovery cannot restore snapshotted sysctls while ProtectKernelTunables is enabled")
	}
	for _, required := range []string{
		`verifier=$TOOLING/gateway-vpnctl`,
		`old_verifier=$TOOLING/old-gateway-vpnctl`,
		`restore_snapshot_item()`,
		`"$old_verifier" release-verify --release-dir "/opt/gateway-vpn/releases/v$OLD_VERSION"`,
		`ip link add name "$LAN_INTERFACE" type bridge`,
		`ip -4 address replace "$LAN_ADDRESS" dev "$LAN_INTERFACE"`,
		`systemctl start --no-block "${START_UNITS[@]}"`,
		`[[ ! -f /var/lib/gateway-vpn/mihomo/active/config.yaml ]] || START_UNITS+=(gateway-vpn-mihomo.service)`,
		`[[ $path == "$RECOVERY_UNIT" ]] || rm -f -- "$path"`,
		`[[ $link == "$RECOVERY_WANTS" ]] ||`,
		"restore_recovery_guard_projection",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("host-upgrade recovery missing %q", required)
		}
	}
	if strings.Contains(recovery, `cp -a "$ROOTFS"/. /`) {
		t.Fatal("host-upgrade recovery can overwrite host directory metadata from synthetic snapshot parents")
	}
	if strings.LastIndex(recovery, `mv -T "$ACTIVE" "$ROLLED_BACK"`) > strings.LastIndex(recovery, "restore_recovery_guard_projection") {
		t.Fatal("host-upgrade recovery removes its boot guardian before the terminal rollback marker is durable")
	}
	if !strings.Contains(installRecovery, `if [[ ${GATEWAY_VPN_HOST_UPGRADE_INNER:-} != 1 ]]; then`) ||
		!strings.Contains(installer, "if ((HOST_UPGRADE_INNER == 0)); then\n    flock -u 9") {
		t.Fatal("nested first-install rollback can release the outer lock or remove its recovery helper")
	}
}

func TestGatewayInstallerPreparesFixedOpenSSHRuntimeDirectorySafely(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{
		"prepare_sshd_runtime_directory",
		"validate_openssh_configuration",
		`$(stat -c '%u:%g:%a' /run) == "0:0:755"`,
		`$(stat -c '%u:%g:%a' /run/sshd) == "0:0:755"`,
		"[[ -d /run/sshd && ! -L /run/sshd",
		"install -d -m 0755 -o root -g root -- /run/sshd",
		"rmdir -- /run/sshd",
		"validate_openssh_configuration 1",
		"validate_openssh_configuration ||",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway clean-host OpenSSH runtime contract missing %q", required)
		}
	}
	if strings.Contains(installer, "mkdir -p /run/sshd") || strings.Contains(installer, "chmod 0755 /run/sshd") {
		t.Fatal("Gateway installer uses an unchecked or path-following OpenSSH runtime preparation")
	}
	if got := strings.Count(installer, "/usr/sbin/sshd -t"); got != 1 {
		t.Fatalf("sshd validation bypasses the fixed safe helper: raw command count = %d", got)
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

func TestGatewayInstallerAllowsOnlyStrictCompletedOrSignedUpgradeToBypassDirectNetworkPreflight(t *testing.T) {
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
		`grep -Fq "\"wireguard_endpoint_host\": \"$WIREGUARD_ENDPOINT_HOST\"" /var/lib/gateway-vpn/install-report.json`,
		`grep -Fq "\"wireguard_subnet\": \"$WIREGUARD_SUBNET\"" /var/lib/gateway-vpn/install-report.json`,
		`grep -Fq "\"wireguard_listen_port\": $WIREGUARD_LISTEN_PORT" /var/lib/gateway-vpn/install-report.json`,
		`grep -Fq "\"wireguard_client_dns\": \"$WIREGUARD_CLIENT_DNS\"" /var/lib/gateway-vpn/install-report.json`,
		"HOST_UPGRADE_REQUIRED=0",
		"INNER_UPGRADE_HINT=0",
		`$(readlink -f /proc/$$/fd/9) == "$lock"`,
		"HOST_UPGRADE_REQUIRED == 1",
		"COMPLETED_INSTALL_HINT == 1 || HOST_UPGRADE_REQUIRED == 1 || INNER_UPGRADE_HINT == 1",
		"continuing with strict signed existing/upgrade verification",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer completed-install DNS exception missing %q", required)
		}
	}
	hint := strings.Index(installer, "COMPLETED_INSTALL_HINT=0")
	ntp := strings.Index(installer, "if [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) != yes ]]; then")
	dns := strings.Index(installer, "if ! getent ahostsv4 github.com >/dev/null; then")
	if hint < 0 || ntp < 0 || dns < 0 || hint >= ntp || ntp >= dns {
		t.Fatal("strict completed-install hint must be established before both NTP and DNS offline exceptions")
	}
	if !strings.Contains(installer, "COMPLETED_INSTALL_HINT == 1 || HOST_UPGRADE_REQUIRED == 1") {
		t.Fatal("same-version same-policy completed install cannot bypass unavailable NTP")
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
	for _, required := range []string{"gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz", "gateway-vpn-bootstrap-$VERSION-linux-amd64", "./cmd/gateway-vpn-bootstrap", "scripts/install-gateway.sh", "scripts/recover-gateway-install.sh", "scripts/run-gateway-uninstall-job.sh", "scripts/uninstall.sh", "config.example.yaml", "$ROOT/packaging", "Gateway archive SHA-256", "Bootstrap SHA-256"} {
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
		"channel-sign", "channel-verify", "channel-install-command", "channel-windows-deploy-command",
		"channel-$CHANNEL.json", "channel-$CHANNEL.sig", "update-signing.pub",
		"--github-repository", "--release-tag", "--source-commit", "--interactive",
		"install-gateway-$VERSION.command.txt", "install-deploy-windows-$VERSION.command.txt", "clean committed worktree",
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
		"--mihomo-maintenance", "--mihomo-channel", "--mihomo-urgency", "--mihomo-summary", "--compatible-gateway-version", "build-mihomo-channel.sh",
		"release-key-verify", "release-verify", "--initial-install", "vps-release-verify", "channel-verify",
		"--artifact \"bootstrap=", "--artifact \"deploy=", "--artifact \"deploy-windows=", "--artifact \"gateway=", "--artifact \"vps=",
		"bootstrap=$ROOT/dist/", "deploy=$ROOT/dist/", "deploy-windows=$ROOT/dist/", "gateway=$ROOT/dist/", "vps=$ROOT/dist/",
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
		"RELEASE_CLASS_ARGS", `if [[ "$CHANNEL" != stable ]]`, "--prerelease",
		"mihomo-channel-$mihomo_channel.json", "mihomo-channel-$mihomo_channel.sig", "mihomo-channel-verify", "one safe manifest/signature pair", "MIHOMO_CHANNELS",
		"gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz",
		"gateway-vpn-vps-$VERSION-linux-amd64.tar.gz", "gateway-vpn-bootstrap-$VERSION-linux-amd64",
		"gateway-vpn-deploy-$VERSION-linux-amd64", "gateway-vpn-deploy-$VERSION-windows-amd64.exe",
		"install-deploy-windows-$VERSION.command.txt", "channel-$CHANNEL.json", "update-signing.pub",
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
		"--mihomo-maintenance", "--mihomo-channel", "--mihomo-urgency", "--mihomo-summary", "--compatible-gateway-version", "BUNDLE_EXTRA_ARGS",
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
	gitleaksIgnore := read(t, filepath.Join(root, ".gitleaksignore"))
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(workflow), &parsed); err != nil {
		t.Fatalf("parse GitHub CI workflow: %v", err)
	}
	for _, required := range []string{
		"permissions:\n  contents: read", "runs-on: ubuntu-24.04", "go test -race ./... -count=1",
		"go vet ./...", "CGO_ENABLED=0 GOOS=linux GOARCH=amd64", "node --check", "bash -n .githooks/pre-commit scripts/*.sh", "test/release-gate/*.sh",
		"sudo apt-get install --yes --no-install-recommends --no-upgrade", "firewall_guard.sh /tmp/gateway-vpn-netns",
		"startup_policy.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-app-test",
		"persist-credentials: false", "fetch-depth: 0", "Repository secret history gate",
		"needs: secret-scan",
		"gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e", "GITHUB_TOKEN: ${{ github.token }}",
		`GITLEAKS_VERSION: "8.29.0"`,
		`GITLEAKS_ENABLE_COMMENTS: "false"`, `GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "false"`,
		"FuzzImport", "FuzzNormalizeTarget", "FuzzGenerate", "FuzzExtractReleaseArchive", "-fuzztime=5s",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("GitHub CI workflow missing %q", required)
		}
	}
	if strings.Contains(workflow, "pull_request_target") || strings.Contains(strings.ToLower(workflow), "release_signing") || strings.Contains(workflow, "secrets.") {
		t.Fatal("GitHub CI can expose release secrets or runs privileged fork code with base context")
	}
	if !strings.Contains(gitleaksIgnore, "Reviewed historical false positives") || strings.Contains(gitleaksIgnore, "*") || strings.Contains(gitleaksIgnore, "test/**") || strings.Count(gitleaksIgnore, ":curl-auth-header:") != 6 {
		t.Fatal("Gitleaks exceptions must remain six reviewed exact fingerprints, never a wildcard fixture exclusion")
	}
	usesPattern := regexp.MustCompile(`(?m)^\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$`)
	matches := usesPattern.FindAllStringSubmatch(workflow, -1)
	if len(matches) != 8 {
		t.Fatalf("expected eight full-SHA reviewed Action references, got %d", len(matches))
	}
	if strings.Count(workflow, "uses:") != len(matches) {
		t.Fatal("GitHub CI contains an unpinned Action reference")
	}
	dependabot := read(t, filepath.Join(root, ".github", "dependabot.yml"))
	if !strings.Contains(dependabot, "package-ecosystem: github-actions") || !strings.Contains(dependabot, "interval: weekly") {
		t.Fatal("GitHub Action pins do not have a reviewable update feed")
	}
}

func TestOptInPreCommitSecretGuardScansStagedSnapshot(t *testing.T) {
	root := repositoryRoot(t)
	hook := read(t, filepath.Join(root, ".githooks", "pre-commit"))
	scanner := read(t, filepath.Join(root, "scripts", "pre-commit-secret-scan.sh"))
	for name, content := range map[string]string{"hook": hook, "scanner": scanner} {
		for _, required := range []string{"#!/usr/bin/env bash", "set -euo pipefail"} {
			if !strings.Contains(content, required) {
				t.Errorf("pre-commit %s missing %q", name, required)
			}
		}
	}
	if !strings.Contains(hook, "pre-commit-secret-scan.sh") {
		t.Fatal("pre-commit hook does not delegate to the reviewed scanner")
	}
	for _, required := range []string{"protect", "--staged", "--redact", "--no-banner", ".gitleaksignore", "test/fixtures", "server-side GitHub full-history secret gate"} {
		if !strings.Contains(scanner, required) {
			t.Errorf("pre-commit scanner missing %q", required)
		}
	}
	if strings.Contains(scanner, "test/**") || strings.Contains(scanner, "fixtures/**") || strings.Contains(scanner, "--no-git") {
		t.Fatal("pre-commit scanner must not exclude fixtures or bypass Git history semantics")
	}
}

func TestDeployLauncherBuilderAndCommandArePinnedAndPrivateKeyFree(t *testing.T) {
	root := repositoryRoot(t)
	builder := read(t, filepath.Join(root, "scripts", "build-deploy.sh"))
	for _, required := range []string{"gateway-vpn-deploy-$VERSION-linux-amd64", "gateway-vpn-deploy-$VERSION-windows-amd64.exe", "./cmd/gateway-vpn-deploy", "CGO_ENABLED=0", "GOOS=linux", "GOOS=windows", "GOARCH=amd64", "clean committed worktree", "spdxVersion", "provenance", "sha256sum --binary"} {
		if !strings.Contains(builder, required) {
			t.Errorf("deploy builder missing %q", required)
		}
	}
	if strings.Contains(builder, "private-key") {
		t.Fatal("deploy builder unexpectedly accepts private key material")
	}
	commandSource := read(t, filepath.Join(root, "internal", "distribution", "install_command.go"))
	for _, required := range []string{"func DeployCommand", "func WindowsDeployCommand", "RoleDeploy", "test \\\"$actual\\\"", "Get-FileHash", "--interactive", "--gateway-ssh", "--vps-ssh", "--known-hosts", "--admin-public-key", "--apply"} {
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
		"iproute2", "nftables", "wireguard-tools", "kmod", "procps", "python3", "prerequisite_package in ubuntu-advantage-tools python3",
		"apt-get -s install --no-install-recommends --no-remove --no-upgrade", "apt-get update", "apt-get install --yes --no-install-recommends --no-remove --no-upgrade",
		"full host preflight NOT_RUN", "APT dependency plan attempts to remove packages", "APT dependency plan attempts to upgrade installed packages", "exit 10",
		"vps-release-verify", "manifest.sha256", "--apply", "nft --check",
		"gateway_vpn_vps", "10.80.0.1/24", "AllowedIPs = 10.80.0.2/32", "AllowedIPs = 10.80.0.10/32",
		"gateway-vpn-vps-install-recovery.service", "install-transactions/active", "Validated harmless pre-transaction VPS marker artifact", "Orphan VPS installation artifact requires operator recovery",
		"trap 'rollback_install $?' ERR EXIT", "trap 'rollback_install 130' INT", "trap 'rollback_install 143' TERM",
		"validate_preserved_wg_config", "PRESERVED_WG_CONFIG", "preserve_wg_config=%s", ".gateway-vpn-wg-mgmt.conf.tmp",
		"/run/lock/gateway-vpn-vps-install.lock", "set -o noclobber", "0:0:600", "flock -n 9", "flock -u 9",
		"ip -4 -o address show dev wg-mgmt", "fabric/applied.json", "INSTALLED_NOT_READY",
		"-g \"$AGENT_USER\" -m 0710 /var/lib/gateway-vpn-vps-privileged", "-g root -m 0700 /var/lib/gateway-vpn-vps-privileged/restore-transactions", "-m 0750 /var/lib/gateway-vpn-vps-privileged/operations", "root:gateway-vpn-vps:640",
		"--hub-admin-password-file", "--check-password-file", "preserve_agent_user=%s", "$AGENT_STATE/vps-agent.db",
		"install -d -o root -g \"$AGENT_USER\" -m 0710 /var/lib/gateway-vpn-vps",
		"gateway-vpn-vps-agent.service", "gateway-vpn-vps-restore.service", "gateway-vpn-vps-restore.path", "gateway-vpn-vps-restore-recovery.service",
		"gateway-vpn-vps-fabric.service", "gateway-vpn-vps-fabric.path", "gateway-vpn-vps-fabric-recovery.service", "gateway-vpn-vps-fabric-watchdog.service", "gateway-vpn-vps-fabric-watchdog.timer", "gateway-vpn-vps-operations.service", "gateway-vpn-vps-operations.timer", "legacy-adopt", "fabric-apply",
		"gateway-vpn-vps-update.service", "gateway-vpn-vps-update.path", "gateway-vpn-vps-update-recovery.service", "gateway-vpn-vps-update-finalize.service", "gateway-vpn-vps-update-finalize.timer", "/opt/gateway-vpn-vps/recovery", "update-transactions",
		"identity-init", "init-admin", "systemctl is-active --quiet gateway-vpn-vps-agent.service", "127.0.0.1:9443", "10.80.0.1:9443",
		"wait_for_vps_agent_listeners", "attempt < 100", "sleep 0.1", "VPS Agent stopped before both HTTPS listeners became ready",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("VPS installer missing %q", required)
		}
	}
	if strings.Contains(installer, "python3-minimal") {
		t.Fatal("VPS installer cannot rely on python3-minimal because strict JSON gates require the full Python standard library")
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
	for _, required := range []string{"table inet gateway_vpn_vps", "iifname \"wg-mgmt\"", "ip saddr 10.80.0.10", "ip daddr 10.80.0.2", "ip daddr 10.80.0.1", "tcp dport { 22, 9443 }", "VPS Hub administrator access", "deny VPS Hub to non-admin peers", "reject with icmpx type admin-prohibited"} {
		if !strings.Contains(firewall, required) {
			t.Errorf("VPS firewall missing %q", required)
		}
	}
	if strings.Contains(firewall, "192.168.") || strings.Contains(firewall, "flush ruleset") {
		t.Fatal("VPS role unexpectedly exposes a home/transit LAN or flushes global firewall state")
	}
	for _, unitPath := range []string{
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-firewall.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-agent.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-restore-recovery.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-restore.path"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-fabric-recovery.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-fabric.path"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-fabric-watchdog.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-operations.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-update.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-update-recovery.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-update-finalize.service"),
		filepath.Join(root, "packaging", "vps", "systemd", "gateway-vpn-vps-update.path"),
		filepath.Join(root, "packaging", "vps", "systemd", "wg-quick@wg-mgmt.service.d", "gateway-vpn.conf"),
	} {
		unit := read(t, unitPath)
		if !strings.Contains(unit, "ConditionPathExists=|!/var/lib/gateway-vpn-vps/install-transactions/active") || !strings.Contains(unit, "ConditionPathExists=|/run/gateway-vpn-vps-install-authorized") || !strings.Contains(unit, "ConditionPathIsSymbolicLink=!/var/lib/gateway-vpn-vps/install-transactions/active") || !strings.Contains(unit, "ConditionPathIsSymbolicLink=!/run/gateway-vpn-vps-install-authorized") {
			t.Errorf("VPS unit %s can start during an incomplete install", unitPath)
		}
	}
	recovery := read(t, filepath.Join(root, "scripts", "recover-vps-install.sh"))
	for _, required := range []string{"nft delete table inet gateway_vpn_vps", "old_ipv4_forward", "preserve_wg_config", "PRESERVE_WG_CONFIG", "preserve_agent_user", "PRESERVE_AGENT_USER", "gateway-vpn-vps-agent.service", "gateway-vpn-vps-restore.path", "gateway-vpn-vps-fabric.path", "gateway-vpn-vps-operations.timer", "gateway-vpn-vps-update.path", "gateway-vpn-vps-update-finalize.timer", "/opt/gateway-vpn-vps/recovery", "update-status.json", "update-staging", "remove newly created VPS Agent state", "active marker retained for retry", ".gateway-vpn-wg-mgmt.conf.tmp", "install-report.json", "/run/lock/gateway-vpn-vps-install.lock", "flock -n 9", "marker field count is invalid", "duplicate or missing field", "wg-mgmt remained enabled", "if ((FAILED))"} {
		if !strings.Contains(recovery, required) {
			t.Errorf("VPS recovery missing %q", required)
		}
	}
	if strings.Contains(recovery, "flush ruleset") || strings.Contains(recovery, "set +e") || strings.Index(recovery, "if ((FAILED))") > strings.Index(recovery, "mv -f \"$MARKER\"") {
		t.Fatal("VPS first-install recovery does not restore only owned state")
	}
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall-vps.sh"))
	if !strings.Contains(uninstaller, "--purge-keys") || !strings.Contains(uninstaller, "WireGuard keys are preserved") || !strings.Contains(uninstaller, "VPS Hub settings/backups/account") || !strings.Contains(uninstaller, "gateway-vpn-vps-restore.path") || !strings.Contains(uninstaller, "gateway-vpn-vps-fabric.path") || !strings.Contains(uninstaller, "gateway-vpn-vps-operations.timer") || !strings.Contains(uninstaller, "gateway-vpn-vps-update.path") || !strings.Contains(uninstaller, "update-lifecycle-check") || !strings.Contains(uninstaller, "update-staging") || strings.Contains(uninstaller, "flush ruleset") {
		t.Fatal("VPS uninstall key-preservation or firewall ownership contract is incomplete")
	}
	if strings.Contains(uninstaller, "/var/lib/gateway-vpn-vps-privileged/update-transactions/active.json") || strings.Contains(installer, "/var/lib/gateway-vpn-vps-privileged/update-transactions/active.json") {
		t.Fatal("VPS install/uninstall uses raw active.json existence instead of semantic update lifecycle inspection")
	}
	if !strings.Contains(installer, "update-lifecycle-check") {
		t.Fatal("VPS reinstall does not perform semantic update lifecycle inspection")
	}
	installedVerify := strings.Index(installer, `"$RELEASE_DIR/bin/gateway-vpnctl" vps-release-verify --release-dir "$DEST"`)
	lifecycleInspect := strings.Index(installer, `"$DEST/bin/gateway-vpn-vps-agent" update-lifecycle-check`)
	if installedVerify < 0 || lifecycleInspect < 0 || installedVerify > lifecycleInspect {
		t.Fatal("VPS reinstall executes the installed lifecycle checker before the signed source verifier authenticates that tree")
	}
	for _, required := range []string{"assert_no_vps_transaction", "CONTROL_PLANE_WAS_ACTIVE", "systemctl stop gateway-vpn-vps-agent.service"} {
		if !strings.Contains(uninstaller, required) {
			t.Errorf("VPS uninstall TOCTOU guard missing %q", required)
		}
	}
	commandGenerator := read(t, filepath.Join(root, "scripts", "generate-vps-install-command.sh"))
	for _, required := range []string{"channel-vps-install-command", "install-vps-$VERSION.command.txt", "--gateway-public-key", "--admin-public-key", "--install-dependencies", "--apply"} {
		if !strings.Contains(commandGenerator, required) {
			t.Errorf("VPS command generator missing %q", required)
		}
	}
}

func TestVPSUpdatePackagingHasIndependentLiveAndBootRecoveryBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	directory := filepath.Join(root, "packaging", "vps", "systemd")
	agentCommand := read(t, filepath.Join(root, "cmd", "gateway-vpn-vps-agent", "main.go"))
	lifecycleLock := read(t, filepath.Join(root, "cmd", "gateway-vpn-vps-agent", "lifecycle_lock.go"))
	update := read(t, filepath.Join(directory, "gateway-vpn-vps-update.service"))
	recovery := read(t, filepath.Join(directory, "gateway-vpn-vps-update-recovery.service"))
	finalize := read(t, filepath.Join(directory, "gateway-vpn-vps-update-finalize.service"))
	pathUnit := read(t, filepath.Join(directory, "gateway-vpn-vps-update.path"))
	timer := read(t, filepath.Join(directory, "gateway-vpn-vps-update-finalize.timer"))
	agent := read(t, filepath.Join(directory, "gateway-vpn-vps-agent.service"))
	installRecovery := read(t, filepath.Join(directory, "gateway-vpn-vps-install-recovery.service"))

	for _, required := range []string{
		"GATEWAY_VPN_VPS_UPDATE_UNIT=1",
		"ExecStart=/opt/gateway-vpn-vps/recovery/bin/gateway-vpn-vps-agent update-apply",
		"ExecStopPost=/usr/bin/rm -f /run/gateway-vpn-vps-update-live /var/lib/gateway-vpn-vps/agent/update.trigger",
		"OnFailure=gateway-vpn-vps-update-recovery.service",
		"Conflicts=gateway-vpn-vps-restore.service gateway-vpn-vps-fabric.service gateway-vpn-vps-update-finalize.service",
		"ReadWritePaths=/opt/gateway-vpn-vps /var/lib/gateway-vpn-vps/agent /var/lib/gateway-vpn-vps-privileged /run/systemd",
		"RestrictAddressFamilies=AF_UNIX",
	} {
		if !strings.Contains(update, required) {
			t.Errorf("VPS update unit missing %q", required)
		}
	}
	for _, required := range []string{
		"ConditionPathExists=!/run/gateway-vpn-vps-update-live",
		"ConditionPathIsSymbolicLink=!/run/gateway-vpn-vps-update-live",
		"ExecStart=/opt/gateway-vpn-vps/recovery/bin/gateway-vpn-vps-agent update-recover",
		"Before=network.target",
	} {
		if !strings.Contains(recovery, required) {
			t.Errorf("VPS update recovery unit missing %q", required)
		}
	}
	if strings.Contains(recovery, "ConditionPathExists=/var/lib/gateway-vpn-vps-privileged/update-transactions/active.json") {
		t.Fatal("VPS boot recovery can be skipped after active.json is lost between redundant journal writes")
	}
	for _, required := range []string{"GATEWAY_VPN_VPS_UPDATE_FINALIZE_UNIT=1", "/run/gateway-vpn-vps-update-live", "update-finalize", "OnFailure=gateway-vpn-vps-update-recovery.service"} {
		if !strings.Contains(finalize, required) {
			t.Errorf("VPS update finalize unit missing %q", required)
		}
	}
	if !strings.Contains(finalize, "Conflicts=gateway-vpn-vps-update.service gateway-vpn-vps-restore.service gateway-vpn-vps-fabric.service") {
		t.Fatal("VPS update finalizer can overlap another root data-plane transaction")
	}
	if strings.Contains(update, "ExecStartPre=") || strings.Contains(finalize, "ExecStartPre=") {
		t.Fatal("VPS update units mutate root state before the shared lifecycle lock is acquired")
	}
	for _, required := range []string{"acquireVPSUpdateRootLifecycle(false)", "acquireVPSUpdateRootLifecycle(true)", "createVPSUpdateLiveMarker()"} {
		if !strings.Contains(agentCommand, required) {
			t.Errorf("VPS root update command is missing lifecycle boundary %q", required)
		}
	}
	for _, required := range []string{"/run/lock/gateway-vpn-vps-install.lock", "/var/lib/gateway-vpn-vps/install-transactions/active", "/run/gateway-vpn-vps-install-authorized"} {
		if !strings.Contains(lifecycleLock, required) {
			t.Errorf("VPS update lifecycle lock is missing fixed boundary %q", required)
		}
	}
	if !strings.Contains(pathUnit, "PathExists=/var/lib/gateway-vpn-vps/agent/update.trigger") || !strings.Contains(pathUnit, "Unit=gateway-vpn-vps-update.service") || !strings.Contains(timer, "OnUnitActiveSec=15min") || !strings.Contains(timer, "Persistent=true") {
		t.Fatal("VPS update path/finalize timer contract is incomplete")
	}
	if !strings.Contains(agent, "Requires=gateway-vpn-vps-update-recovery.service") || !strings.Contains(agent, "After=network-online.target gateway-vpn-vps-install-recovery.service gateway-vpn-vps-update-recovery.service") {
		t.Fatal("VPS Agent is not ordered behind boot update recovery")
	}
	if !strings.Contains(installRecovery, "Before=network-pre.target") || !strings.Contains(installRecovery, "gateway-vpn-vps-update-recovery.service") || !strings.Contains(installRecovery, "gateway-vpn-vps-update.path") {
		t.Fatal("first-install recovery is not ordered before VPS update units")
	}
	for name, content := range map[string]string{"update": update, "recovery": recovery, "finalize": finalize, "path": pathUnit, "timer": timer} {
		lower := strings.ToLower(content)
		for _, forbidden := range []string{"amnezia", "docker", "ufw", "firewalld", "nft flush ruleset", "systemctl reboot"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("VPS %s unit crosses ownership boundary with %q", name, forbidden)
			}
		}
	}
}

func TestSafeApplyPrivilegesAreIsolatedBehindSocketAndIndependentTimer(t *testing.T) {
	root := repositoryRoot(t)
	socket := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.socket"))
	for _, required := range []string{"ListenStream=/run/gateway-vpn/network-broker.sock", "SocketUser=gateway-vpn", "SocketGroup=gateway-vpn", "SocketMode=0660"} {
		if !strings.Contains(socket, required) {
			t.Errorf("broker socket missing %q", required)
		}
	}
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	for _, required := range []string{"network-broker", "User=" /* root is intentionally implicit */, "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_BOOT", "NoNewPrivileges=yes", "/var/lib/gateway-vpn-privileged/network-transactions"} {
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
	for _, required := range []string{
		"d /var/lib/gateway-vpn/secrets/management 0700 root root",
		"d /var/lib/gateway-vpn-privileged/backup-exports 0700 root root",
		"d /var/lib/gateway-vpn-privileged/management-fabric 0700 root root",
		"/var/lib/gateway-vpn-privileged/backup-exports",
		"/var/lib/gateway-vpn-privileged/management-fabric",
	} {
		if !strings.Contains(tmpfiles+broker, required) {
			t.Errorf("Gateway Management Fabric packaging missing %q", required)
		}
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
	if !strings.Contains(recovery, "StartLimitIntervalSec=0") {
		t.Fatal("idempotent network recovery can hit systemd start limiting while several dependents start sequentially")
	}
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
	for _, required := range []string{"ID_VENDOR_ID=12d1", "DHCP=ipv4", "UseRoutes=no", "UseGateway=no", "IPv6AcceptRA=no", "RequiredForOnline=no"} {
		if !strings.Contains(networkd, required) {
			t.Errorf("HiLink networkd policy missing %q", required)
		}
	}
	lanNetwork := read(t, filepath.Join(root, "packaging", "systemd-networkd", "05-gateway-vpn-lan.network.in"))
	for _, required := range []string{"Name=__LAN_INTERFACE__", "Address=__LAN_ADDRESS__", "DHCP=no", "IPv6AcceptRA=no", "LinkLocalAddressing=no", "ConfigureWithoutCarrier=yes", "RequiredForOnline=no"} {
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
	waitOnline := read(t, filepath.Join(root, "packaging", "systemd-wait-online", "gateway-vpn.conf"))
	for _, required := range []string{"ExecStart=", "ExecStart=/usr/bin/true"} {
		if !strings.Contains(waitOnline, required) {
			t.Errorf("bounded wait-online policy missing %q", required)
		}
	}
	grubPolicies := map[string][]string{
		"90-gateway-vpn-automatic.cfg": {"GRUB_DEFAULT=0", "GRUB_TIMEOUT_STYLE=hidden", "GRUB_TIMEOUT=1", "GRUB_RECORDFAIL_TIMEOUT=0"},
		"90-gateway-vpn-menu.cfg":      {"GRUB_DEFAULT=0", "GRUB_TIMEOUT_STYLE=menu", "GRUB_TIMEOUT=5", "GRUB_RECORDFAIL_TIMEOUT=5"},
	}
	for filename, requirements := range grubPolicies {
		policy := read(t, filepath.Join(root, "packaging", "grub", filename))
		for _, required := range requirements {
			if !strings.Contains(policy, required) {
				t.Errorf("%s missing %q", filename, required)
			}
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
	for _, required := range []string{"/run/lock/gateway-vpn-install.lock", "flock -n 9", "Gateway recovery marker field count is invalid", `"$MARKER_FIELD_COUNT" == 14 || "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 || "$MARKER_FIELD_COUNT" == 21`, "boot_network_policy", "grub_policy", "old_ipv4_forward", "old_ipv4_src_valid_mark", "SOURCE_MARK_STATE_KNOWN", `net.ipv4.conf.all.src_valid_mark=$OLD_IPV4_SRC_VALID_MARK`, "preserve_state_root", "preserve_lan_address", "lan_members", "lan_member_was_up", "ssh_was_enabled", "ssh_was_active", "restore_systemd_unit_state ssh.service", "systemd-networkd-wait-online.service.d/gateway-vpn.conf", "update-grub", "grub-script-check", "ip link set dev \"$member\" nomaster", "ip link delete dev \"$LAN_INTERFACE\" type bridge", "nft delete table inet gateway_vpn", "ip link delete dev wg-mgmt", "ip link delete dev wg-ingress", "active marker retained for retry", "if ((FAILED))", "rolled-back-"} {
		if !strings.Contains(recovery, required) {
			t.Errorf("Gateway recovery missing %q", required)
		}
	}
	if strings.Contains(recovery, "flush ruleset") || strings.Index(recovery, "if ((FAILED))") > strings.Index(recovery, "mv -f \"$MARKER\"") {
		t.Fatal("Gateway recovery can discard its marker before verified owned-state cleanup")
	}
	if !strings.Contains(recovery, "restore_systemd_unit_state()") || !strings.Contains(recovery, "only record_failure controls recovery failure") || !strings.Contains(recovery, "  return 0\n}") {
		t.Fatal("Gateway recovery systemd-state helper can leak an expected negative probe through set -e")
	}
	grubRollbackStart := strings.Index(recovery, `if [[ "$GRUB_POLICY" != keep ]]; then`)
	grubRollbackEnd := strings.Index(recovery, "rm -f /etc/systemd/journald@gateway-vpn.conf.d/retention.conf")
	if grubRollbackStart < 0 || grubRollbackEnd <= grubRollbackStart {
		t.Fatal("Gateway recovery GRUB rollback block is unavailable")
	}
	grubRollback := recovery[grubRollbackStart:grubRollbackEnd]
	for _, required := range []string{
		"rm -f /etc/default/grub.d/90-gateway-vpn.cfg",
		"update-grub >/dev/null",
		"grub-script-check /boot/grub/grub.cfg",
	} {
		if !strings.Contains(grubRollback, required) {
			t.Errorf("Gateway recovery cannot durably finish GRUB rollback after an interrupted retry: missing %q", required)
		}
	}
	if strings.Contains(grubRollback, "[[ -e /etc/default/grub.d/90-gateway-vpn.cfg") || strings.Contains(grubRollback, "[[ -f /etc/default/grub.d/90-gateway-vpn.cfg") {
		t.Fatal("Gateway recovery incorrectly skips GRUB regeneration after an earlier retry already removed the owned drop-in")
	}
	installRecovery := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-install-recovery.service"))
	for _, required := range []string{"gateway-vpn-update-recovery.service", "gateway-vpn-database-restore-boot.service", "gateway-vpn-network-recovery.service", "gateway-vpn-network-broker.socket", "gateway-vpn-network-broker.service"} {
		if !strings.Contains(installRecovery, required) {
			t.Errorf("first-install boot recovery is not ordered before %q", required)
		}
	}
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	for _, required := range []string{"/run/lock/gateway-vpn-install.lock", "Recover the interrupted Gateway install", `"$MARKER_FIELD_COUNT" == 14 || "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 || "$MARKER_FIELD_COUNT" == 21`, "old_ipv4_src_valid_mark", "SOURCE_MARK_STATE_KNOWN", `net.ipv4.conf.all.src_valid_mark=$OLD_IPV4_SRC_VALID_MARK`, "05-gateway-vpn-lan.network", "05-gateway-vpn-lan.netdev", "lan_members", "systemd-networkd-wait-online.service.d/gateway-vpn.conf", "90-gateway-vpn.cfg", "update-grub", "grub-script-check", "ip link set dev \"$member\" nomaster", "ip link delete dev \"$LAN_INTERFACE\" type bridge", "restore_systemd_unit_state ssh.service", "nft delete table inet gateway_vpn", "ip link delete dev wg-mgmt", "ip link delete dev wg-ingress"} {
		if !strings.Contains(uninstaller, required) {
			t.Errorf("Gateway uninstall missing %q", required)
		}
	}
}

func TestGatewayInstallMarkerLifecycleGateCoversCurrentAndLegacySchemas(t *testing.T) {
	root := repositoryRoot(t)
	harness := read(t, filepath.Join(root, "test", "release-gate", "validate_gateway_install_marker_lifecycle.sh"))
	for _, required := range []string{
		"GATEWAY_VPN_RELEASE_GATE",
		"--release-gate-only",
		"14 || $1 == 16 || $1 == 18 || $1 == 20 || $1 == 21",
		"old_ipv4_src_valid_mark",
		"ssh_socket_was_enabled|ssh_socket_was_active",
		"log_reader_user|log_reader_was_member",
		"boot_network_policy|grub_policy",
		"GATEWAY_INSTALL_MARKER_ACTIVATE_PASS",
		"GATEWAY_INSTALL_MARKER_CLEANUP_PASS",
		"net.ipv4.conf.all.src_valid_mark = 1",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("Gateway install-marker lifecycle gate missing %q", required)
		}
	}
	if strings.Contains(harness, "rm -rf /var/lib/gateway-vpn-privileged") {
		t.Fatal("release-gate marker helper can destroy the transaction evidence root")
	}
}

func TestGatewayOpenSSHSocketAndLogAccessAreTransactionallyRestored(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	recovery := read(t, filepath.Join(root, "scripts", "recover-gateway-install.sh"))
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))

	for _, required := range []string{
		"SSH_SOCKET_UNIT_ENABLED=0",
		"SSH_SOCKET_UNIT_ACTIVE=0",
		"elif ((SSH_SOCKET_UNIT_ACTIVE)); then",
		"SSH_SOCKET_WAS_ENABLED=0",
		"SSH_SOCKET_WAS_ACTIVE=0",
		"ssh_socket_was_enabled=%s",
		"ssh_socket_was_active=%s",
		"log_reader_was_member=%s",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer does not snapshot OpenSSH/log access transaction state: missing %q", required)
		}
	}
	for name, script := range map[string]string{"recovery": recovery, "uninstaller": uninstaller} {
		for _, required := range []string{
			`"$MARKER_FIELD_COUNT" == 14 || "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 || "$MARKER_FIELD_COUNT" == 21`,
			"SSH_SOCKET_STATE_KNOWN=0",
			`if [[ "$MARKER_FIELD_COUNT" == 20 || "$MARKER_FIELD_COUNT" == 21 ]]; then`,
			`if [[ "$load_state" == not-found ]]; then`,
			`((desired_enabled == 0 && desired_active == 0)) && return 0`,
			`restore_systemd_unit_state ssh.socket "$SSH_SOCKET_WAS_ENABLED" "$SSH_SOCKET_WAS_ACTIVE" "OpenSSH socket"`,
			`restore_systemd_unit_state ssh.service "$SSH_WAS_ENABLED" "$SSH_WAS_ACTIVE" "OpenSSH service"`,
			`id -nG "$LOG_READER_USER" 2>/dev/null | tr ' ' '\n' | grep -Fxq gateway-vpn-log-readers`,
			`gpasswd -d "$LOG_READER_USER" gateway-vpn-log-readers`,
		} {
			if !strings.Contains(script, required) {
				t.Errorf("Gateway %s does not restore compatible OpenSSH/log access state: missing %q", name, required)
			}
		}
	}
}

func TestGatewayWebUIUninstallIsDurableTypedAndBootRecoverable(t *testing.T) {
	root := repositoryRoot(t)
	helper := read(t, filepath.Join(root, "scripts", "run-gateway-uninstall-job.sh"))
	unit := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-uninstall.service"))
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	uninstaller := read(t, filepath.Join(root, "scripts", "uninstall.sh"))
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	web := read(t, filepath.Join(root, "internal", "webapi", "static", "uninstall.js"))

	for _, required := range []string{
		"GATEWAY_VPN_UNINSTALL_UNIT", "ROOT=/var/lib/gateway-vpn-uninstall", "ACTIVE=$ROOT/active", "uninstall-[a-f0-9]{32}",
		"release-verify", "tooling-ready", "gateway-vpn_sha256", "sha256sum --binary", "gateway-vpn PATH_BLOCKED",
		`"$TOOLING/gateway-vpn" firewall-boot --config /etc/gateway-vpn/config.yaml --apply`,
		"GATEWAY_VPN_UNINSTALL_GUARDIAN=1", "completed-$OPERATION_ID", "sync -f \"$RECEIPT_TMP\"",
		"/var/lib/gateway-vpn/update-staging/pending-update.json", `"$TOOLING/gateway-vpn" update-lifecycle-check`,
		"/var/lib/gateway-vpn-privileged/update-rollback/pending.json", "/var/lib/gateway-vpn/recovery/pending-restore.json",
	} {
		if !strings.Contains(helper, required) {
			t.Errorf("uninstall guardian helper missing %q", required)
		}
	}
	receipt := strings.Index(helper, `mv -T "$RECEIPT_TMP" "$RECEIPT"`)
	removeActive := -1
	if receipt >= 0 {
		removeActive = strings.Index(helper[receipt:], `rm -f "$ACTIVE"`)
	}
	if receipt < 0 || removeActive < 0 {
		t.Fatal("uninstall guardian can remove active marker before durable terminal receipt")
	}
	for _, required := range []string{
		"DefaultDependencies=no", "ConditionPathExists=/var/lib/gateway-vpn-uninstall/active",
		"ExecStart=/usr/libexec/gateway-vpn-uninstall-job", "Before=network-pre.target",
		"ReadWritePaths=/etc -/boot/grub /usr/libexec", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, required) {
			t.Errorf("uninstall guardian unit missing %q", required)
		}
	}
	for _, required := range []string{"run-gateway-uninstall-job.sh", "gateway-vpn-uninstall.service", "systemctl enable gateway-vpn-install-recovery.service gateway-vpn-host-upgrade-recovery.service gateway-vpn-uninstall.service"} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer does not install boot-recoverable uninstall asset %q", required)
		}
	}
	if !strings.Contains(tmpfiles, "d /var/lib/gateway-vpn-uninstall 0700 root root") || !strings.Contains(broker, "/var/lib/gateway-vpn-uninstall") {
		t.Fatal("uninstall marker root is not provisioned for the fixed root broker")
	}
	for _, required := range []string{"УДАЛИТЬ GATEWAY VPN", "PRESERVE_DATA", "PURGE_DATA", "acknowledge_session_loss", "acknowledge_not_factory_reset"} {
		if !strings.Contains(web, required) {
			t.Errorf("WebUI uninstall confirmation flow missing %q", required)
		}
	}
	if !strings.Contains(uninstaller, "Gateway did not enter PATH_BLOCKED before uninstall") || !strings.Contains(uninstaller, "rm -rf /var/log/gateway-vpn") || !strings.Contains(uninstaller, "/var/lib/gateway-vpn-privileged/update-rollback/pending.json") || strings.Contains(uninstaller, "gateway-vpn-state-$(date") {
		t.Fatal("CLI uninstall does not match fail-closed preserve/purge contract")
	}
	if !strings.Contains(uninstaller, `"$UPDATE_LIFECYCLE_CHECKER" firewall-boot --config /etc/gateway-vpn/config.yaml --apply`) || strings.Contains(uninstaller, `/usr/sbin/nft --file /etc/gateway-vpn/nftables/boot.nft`) {
		t.Fatal("CLI uninstall does not atomically replace the owned fail-closed table")
	}
	for _, required := range []string{"assert_no_update_restore_transaction", "CONTROL_PLANE_WAS_ACTIVE", "update-lifecycle-check"} {
		if !strings.Contains(uninstaller, required) {
			t.Errorf("CLI uninstall lifecycle recheck missing %q", required)
		}
	}
	upgrader := read(t, filepath.Join(root, "scripts", "upgrade-gateway-host.sh"))
	for name, content := range map[string]string{"uninstall helper": helper, "uninstaller": uninstaller, "host upgrader": upgrader} {
		if strings.Contains(content, "/var/lib/gateway-vpn-privileged/update-transactions/active.json") {
			t.Errorf("%s still treats durable terminal active.json as an active transaction", name)
		}
	}
}

func TestGatewayCleanupReloadsNetworkdOnlyWhenAlreadyActive(t *testing.T) {
	root := repositoryRoot(t)
	scripts := map[string]string{
		"first-install recovery": read(t, filepath.Join(root, "scripts", "recover-gateway-install.sh")),
		"uninstall":              read(t, filepath.Join(root, "scripts", "uninstall.sh")),
	}

	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			functionStart := strings.Index(script, "reload_networkd_policy_if_active() {")
			if functionStart < 0 {
				t.Fatal("networkd cleanup helper is missing")
			}
			functionEnd := strings.Index(script[functionStart:], "\n}")
			if functionEnd < 0 {
				t.Fatal("networkd cleanup helper is incomplete")
			}
			function := script[functionStart : functionStart+functionEnd]
			activeCheck := strings.Index(function, "systemctl is-active --quiet systemd-networkd.service")
			reload := strings.Index(function, "networkctl reload")
			if activeCheck < 0 || reload <= activeCheck {
				t.Fatal("networkd reload is not gated on the daemon already being active")
			}
			if strings.Count(script, "networkctl reload") != 1 {
				t.Fatal("cleanup contains an unconditional or duplicate networkd reload")
			}
			if strings.Count(script, "reload_networkd_policy_if_active") != 2 {
				t.Fatal("networkd cleanup helper must have exactly one definition and one call")
			}
		})
	}
}

func TestGatewayInstallerAcceptsOnlyAuthenticatedTerminalUninstallRemnants(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))

	for _, required := range []string{
		"UNINSTALL_TERMINAL_REMNANTS=0",
		`if [[ ! -e /opt/gateway-vpn/current && ! -L /opt/gateway-vpn/current ]] &&`,
		"Previous Gateway uninstall receipt root is unsafe",
		"completed-uninstall-*",
		"Previous Gateway uninstall terminal receipt is unavailable or unsafe",
		`$(wc -l <"$LATEST_UNINSTALL_RECEIPT") == 6`,
		`grep -Ec '^(format|operation_id|mode|result|completed_at|packages_removed)='`,
		`grep -c "^${receipt_key}="`,
		`grep -Fxq 'format=1'`,
		`$RECEIPT_OPERATION_ID =~ ^uninstall-[a-f0-9]{32}$`,
		`$(basename "$LATEST_UNINSTALL_RECEIPT") == completed-$RECEIPT_OPERATION_ID`,
		`grep -Eq '^mode=(PRESERVE_DATA|PURGE_DATA)$'`,
		`grep -Fxq 'result=SUCCEEDED'`,
		`grep -Eq '^completed_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'`,
		`grep -Fxq 'packages_removed=0'`,
		"Previous Gateway uninstall terminal receipt values are invalid",
		"Previous Gateway uninstall guardian remnant is unsafe",
		"UNINSTALL_TERMINAL_REMNANTS=1",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer terminal uninstall receipt validation is incomplete: missing %q", required)
		}
	}

	remnantException := `if ((UNINSTALL_TERMINAL_REMNANTS)) && [[ "$conflict" == /etc/systemd/system/gateway-vpn-uninstall.service || "$conflict" == /usr/libexec/gateway-vpn-uninstall-job ]]; then`
	if !strings.Contains(installer, remnantException) {
		t.Fatal("Gateway installer cannot safely replace the two authenticated terminal guardian remnants")
	}
	if strings.Contains(installer, "if ((UNINSTALL_TERMINAL_REMNANTS)); then\n      continue") {
		t.Fatal("Gateway installer terminal receipt exception is broad enough to bypass unrelated managed-path conflicts")
	}
}

func TestGatewayInstallerClassifiesInstalledAndPartialPointersBeforeTerminalRemnants(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	upgrader := read(t, filepath.Join(root, "scripts", "upgrade-gateway-host.sh"))

	guard := `if [[ ! -e /opt/gateway-vpn/current && ! -L /opt/gateway-vpn/current ]] &&
   [[ -e /etc/systemd/system/gateway-vpn-uninstall.service || -L /etc/systemd/system/gateway-vpn-uninstall.service || -e /usr/libexec/gateway-vpn-uninstall-job || -L /usr/libexec/gateway-vpn-uninstall-job ]]; then`
	if strings.Count(installer, guard) != 1 {
		t.Fatal("terminal uninstall remnants are not gated on complete absence of the current install pointer")
	}
	for _, required := range []string{
		`if [[ -e "$DEST" || -L /opt/gateway-vpn/current || -L /opt/gateway-vpn/recovery || -e /var/lib/gateway-vpn/install-report.json ]]; then`,
		`[[ -d "$DEST" && ! -L "$DEST" && -L /opt/gateway-vpn/current && $(readlink /opt/gateway-vpn/current) == "releases/v$RELEASE_VERSION"`,
		`/opt/gateway-vpn/current /opt/gateway-vpn/recovery`,
		`[[ ! -e "$conflict" && ! -L "$conflict" ]] || { echo "Conflicting Gateway managed path exists: $conflict"`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer can bypass partial current-pointer validation: missing %q", required)
		}
	}
	for _, required := range []string{
		`[[ -L /opt/gateway-vpn/current && -L /opt/gateway-vpn/recovery ]]`,
		`[[ -d $OLD_RELEASE && ! -L $OLD_RELEASE`,
	} {
		if !strings.Contains(upgrader, required) {
			t.Errorf("Gateway host upgrade can accept a dangling or incomplete current pointer: missing %q", required)
		}
	}
}

func TestWireGuardIngressSecretsHaveNarrowRootWriteBoundary(t *testing.T) {
	root := repositoryRoot(t)
	tmpfiles := read(t, filepath.Join(root, "packaging", "tmpfiles.d", "gateway-vpn.conf"))
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))

	if !strings.Contains(tmpfiles, "d /var/lib/gateway-vpn/secrets/wireguard-ingress 0700 root root") {
		t.Fatal("WireGuard ingress secret root is not created as a root-only directory")
	}
	for _, required := range []string{
		"ReadOnlyPaths=/opt/gateway-vpn /var/lib/gateway-vpn/secrets",
		"ReadWritePaths=/etc/gateway-vpn /etc/systemd/journald@gateway-vpn.conf.d /var/lib/gateway-vpn /var/lib/gateway-vpn/secrets/wireguard-ingress",
	} {
		if !strings.Contains(broker, required) {
			t.Errorf("network broker lacks the narrow WireGuard ingress secret override: missing %q", required)
		}
	}
	if strings.Count(broker, "/var/lib/gateway-vpn/secrets/wireguard-ingress") != 1 {
		t.Fatal("WireGuard ingress secret write override must appear exactly once")
	}
	if !strings.Contains(installer, `$(stat -c '%U:%G:%a' /var/lib/gateway-vpn/secrets/wireguard-ingress) == "root:root:700"`) {
		t.Fatal("installer does not verify the root-only WireGuard ingress secret directory")
	}
}

func TestGatewayInstallerUsesLiteralFileComparisonsForOwnedPolicies(t *testing.T) {
	root := repositoryRoot(t)
	installer := read(t, filepath.Join(root, "scripts", "install-gateway.sh"))
	for _, required := range []string{
		"cp cmp",
		"cmp -s -- /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf",
		"cmp -s -- /etc/systemd/network/05-gateway-vpn-lan.netdev",
		"cmp -s -- /etc/default/grub.d/90-gateway-vpn.cfg",
		"cmp -s -- /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf",
		"cmp -s -- /etc/sysctl.d/90-gateway-vpn-ipv6.conf",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Gateway installer lacks literal owned-policy comparison %q", required)
		}
	}
	if strings.Contains(installer, `== $(cat`) {
		t.Fatal("Gateway installer compares file content as a Bash glob pattern")
	}
}

func TestSystemdReleaseGateUsesCanonicalGenericUplinkState(t *testing.T) {
	root := repositoryRoot(t)
	gate := read(t, filepath.Join(root, "test", "release-gate", "validate_gateway_systemd.sh"))
	if !strings.Contains(gate, `"GatewayState":"ALL_UPLINKS_OFFLINE"`) || strings.Contains(gate, `"GatewayState":"ALL_MODEMS_OFFLINE"`) {
		t.Fatal("systemd release gate still asserts the retired modem-only runtime state")
	}
}

func TestCriticalBashNegativeAssertionsCannotBeMaskedByErrexit(t *testing.T) {
	root := repositoryRoot(t)
	files := map[string][]string{
		filepath.Join(root, "scripts", "uninstall.sh"): {
			`! systemctl is-enabled --quiet "$unit"`,
			`! systemctl is-active --quiet "$unit"`,
		},
		filepath.Join(root, "test", "release-gate", "validate_gateway_systemd.sh"): {
			"! systemctl is-active --quiet gateway-vpn-mihomo.service",
			"! nft list set inet gateway_vpn active_tun_interfaces",
			"! nft list set inet gateway_vpn active_direct_interfaces",
			"! nft list set inet gateway_vpn active_path_generation",
		},
		filepath.Join(root, "test", "release-gate", "validate_gateway_install_marker_lifecycle.sh"): {
			"! grep -q '^old_ipv4_src_valid_mark='",
			"! find /opt/gateway-vpn/releases",
			"! nft list table inet gateway_vpn",
		},
		filepath.Join(root, "test", "release-gate", "validate_gateway_restore_point_systemd.sh"): {
			"! grep -Fq '# restore-point-gate: newer'",
		},
	}
	for filename, forbidden := range files {
		contents := read(t, filename)
		for _, fragment := range forbidden {
			if strings.Contains(contents, fragment) {
				t.Errorf("%s contains a standalone negated assertion that Bash errexit can mask: %q", filepath.Base(filename), fragment)
			}
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
		`\[[[:space:]]*8[[:space:]]*\]`,
		"mss 1240",
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
		"nft list set inet gateway_vpn local_management_interfaces",
		`iifname @local_management_interfaces tcp dport 22 accept`,
		"/dev/tcp/192.168.200.1/22",
		"/dev/tcp/192.168.8.2/22",
		"TCP/22 was exposed through the non-LAN uplink",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("LAN bridge SSH netns harness missing %q", required)
		}
	}
}

func TestWireGuardIngressHarnessCoversKernelHandshakeAndFailClosedLifecycle(t *testing.T) {
	root := repositoryRoot(t)
	harness := read(t, filepath.Join(root, "test", "netns", "wireguard_ingress.sh"))
	workflow := read(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	dockerfile := read(t, filepath.Join(root, "test", "netns", "Dockerfile.ubuntu24"))
	for _, required := range []string{
		"GATEWAY_VPN_WG_INGRESS_INTEGRATION=1",
		"TestBackendAgainstKernelWireGuardNamespace",
		"gateway-vpn-wgingress-test",
		"wireguard-tools",
		"useradd --system --no-create-home --shell /usr/sbin/nologin",
		"ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
	} {
		if !strings.Contains(harness+workflow+dockerfile, required) {
			t.Errorf("WireGuard ingress kernel gate missing %q", required)
		}
	}
}

func TestWebUIContextualHelpDecoratesLegacyAndDynamicControls(t *testing.T) {
	root := repositoryRoot(t)
	index := read(t, filepath.Join(root, "internal", "webapi", "static", "index.html"))
	script := read(t, filepath.Join(root, "internal", "webapi", "static", "contextual-help.js"))
	for _, required := range []string{
		`src="/contextual-help.js"`, "MutationObserver", "querySelectorAll('label')",
		"control.title", "label.title", "aria-label",
	} {
		if !strings.Contains(index+script, required) {
			t.Errorf("contextual help layer missing %q", required)
		}
	}
	if strings.Index(index, `src="/contextual-help.js"`) < strings.Index(index, `src="/wireguard-ingress.js"`) {
		t.Fatal("contextual help must load after dynamic WebUI modules")
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
	rollback := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-update-rollback.service"))
	for _, required := range []string{
		"ConditionPathExists=/var/lib/gateway-vpn-privileged/update-rollback/pending.json",
		"GATEWAY_VPN_UPDATE_ROLLBACK_UNIT=1",
		"GATEWAY_VPN_UPDATE_UNIT=1",
		"ExecStart=/opt/gateway-vpn/recovery/bin/gateway-vpn update-rollback --config /etc/gateway-vpn/config.yaml --apply",
		"Requires=gateway-vpn-update-recovery.service",
		"OnFailure=gateway-vpn-update-resume.service",
		"ReadWritePaths=/opt/gateway-vpn /etc/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged /run",
	} {
		if !strings.Contains(rollback, required) {
			t.Errorf("restore point rollback unit missing %q", required)
		}
	}
	if strings.Contains(update, "ExecStartPre=") || strings.Contains(rollback, "ExecStartPre=") {
		t.Fatal("update units can mutate PATH_BLOCKED before acquiring the common lifecycle lock")
	}
	commands := read(t, filepath.Join(root, "cmd", "gateway-vpn", "update_commands.go"))
	lock := read(t, filepath.Join(root, "cmd", "gateway-vpn", "lifecycle_lock.go")) + read(t, filepath.Join(root, "cmd", "gateway-vpn", "lifecycle_lock_linux.go"))
	for _, required := range []string{
		"acquireUpdateRootLifecycle(false)",
		"acquireUpdateRootLifecycle(true)",
		"gateway-vpn-install.lock",
		"O_NOFOLLOW",
		"LOCK_EX|unix.LOCK_NB",
		"gateway-vpn-install-authorized",
	} {
		if !strings.Contains(commands+lock, required) {
			t.Errorf("common update lifecycle lock contract missing %q", required)
		}
	}
	broker := read(t, filepath.Join(root, "packaging", "systemd", "gateway-vpn-network-broker.service"))
	for _, required := range []string{
		"/var/lib/gateway-vpn-privileged/update-transactions",
		"/var/lib/gateway-vpn-privileged/update-restore-points",
		"/var/lib/gateway-vpn-privileged/update-rollback",
	} {
		if !strings.Contains(broker, required) {
			t.Errorf("network broker sandbox missing restore point path %q", required)
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
		"ReadWritePaths=/opt/gateway-vpn /etc/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged /run",
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
	if !strings.Contains(resume, "systemctl restart gateway-vpn-update-recovery.service") || !strings.Contains(resume, "systemctl start gateway-vpn-network-broker.socket") || !strings.Contains(resume, "systemctl start gateway-vpn.service") || !strings.Contains(resume, "systemctl reset-failed gateway-vpn-update.service gateway-vpn-update-rollback.service gateway-vpn-update-finalize.service") {
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
		"d /var/lib/gateway-vpn-privileged/update-restore-points 0700 root root",
		"d /var/lib/gateway-vpn-privileged/update-rollback 0700 root root",
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
	for _, unit := range []string{"gateway-vpn-update.service", "gateway-vpn-update-rollback.service", "gateway-vpn-update-recovery.service", "gateway-vpn-update-resume.service", "gateway-vpn-update-finalize.service", "gateway-vpn-update-finalize.timer"} {
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
