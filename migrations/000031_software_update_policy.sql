INSERT INTO settings(key, value_json, updated_at)
VALUES (
    'software_update_policy',
    '{"schema_version":1,"channel":"stable","automatic_check_enabled":false,"automatic_download_enabled":false,"automatic_apply_enabled":false,"check_interval_hours":24,"jitter_minutes":30,"maintenance_window_enabled":false,"maintenance_start_minute_utc":180,"maintenance_duration_minutes":120,"retention_maximum_points":4,"retention_maximum_bytes":8589934592,"retention_maximum_age_days":365,"retention_minimum_old_points":2}',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);
