INSERT INTO settings(key, value_json, updated_at)
VALUES (
    'logging',
    '{"schema_version":1,"global_level":"info","component_levels":{},"debug_components":[],"debug_until":"","retention_days":14,"max_disk_usage_bytes":268435456,"diagnostic_excerpt_bytes":1048576,"health_error_aggregation_seconds":60,"updated_at":""}',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
)
ON CONFLICT(key) DO NOTHING;
