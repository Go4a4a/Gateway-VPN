UPDATE settings
SET value_json=json_set(
        value_json,
        '$.component_recovery_modes.logging_pipeline', 'RESTART'
    ),
    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE key='watchdog'
  AND json_type(value_json, '$.component_recovery_modes.logging_pipeline') IS NULL;
