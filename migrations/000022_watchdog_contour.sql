-- Preserve the operator's existing bounded recovery choices while extending
-- the policy with fixed, typed thresholds and per-component recovery modes.
UPDATE settings
SET value_json=json_set(
        value_json,
        '$.schema_version', 2,
        '$.worker_stale_seconds', 120,
        '$.wireguard_handshake_stale_seconds', 180,
        '$.backup_max_age_hours', 36,
        '$.database_wal_max_bytes', 268435456,
        '$.minimum_disk_free_bytes', 536870912,
        '$.minimum_disk_free_percent', 5,
        '$.minimum_memory_available_bytes', 134217728,
        '$.minimum_memory_available_percent', 5,
        '$.component_recovery_modes', json('{"control_plane":"RESTART","sqlite":"RESTART","firewall_guard":"RESTART","firewall_ruleset":"RESTART","network_broker":"RESTART","systemd_networkd":"RESTART","dnsmasq":"RESTART","openssh_sftp":"RESTART","mihomo":"RESTART","wireguard_management":"RESTART","wireguard_ingress":"RESTART","policy_routing":"RESTART","worker_runtime":"RESTART","configuration_convergence":"RESTART","database_backup":"RESTART","resources":"MONITOR_ONLY"}')
    ),
    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE key='watchdog';
