INSERT INTO settings(key, value_json, updated_at)
VALUES (
    'watchdog',
    '{"schema_version":1,"enabled":true,"check_interval_seconds":15,"failure_threshold":3,"success_threshold":2,"reconcile_enabled":true,"component_restart_enabled":true,"restart_cooldown_seconds":30,"max_restarts_per_component":5,"restart_window_seconds":900,"host_reboot_enabled":false,"reboot_after_critical_seconds":900,"max_reboots_per_24h":1,"reboot_grace_seconds":60,"updated_at":""}',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
)
ON CONFLICT(key) DO NOTHING;
