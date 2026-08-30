-- Extend the fixed watchdog contour without overwriting an administrator's
-- existing per-component recovery choices.

UPDATE settings
SET value_json=json_set(
    value_json,
    '$.component_recovery_modes.management_fabric_routes', 'RESTART',
    '$.component_recovery_modes.wireguard_admin', 'RESTART'
)
WHERE key='watchdog'
  AND json_type(value_json, '$.component_recovery_modes.management_fabric_routes') IS NULL
  AND json_type(value_json, '$.component_recovery_modes.wireguard_admin') IS NULL;

UPDATE settings
SET value_json=json_set(
    value_json,
    '$.component_recovery_modes.management_fabric_routes', 'RESTART'
)
WHERE key='watchdog'
  AND json_type(value_json, '$.component_recovery_modes.management_fabric_routes') IS NULL;

UPDATE settings
SET value_json=json_set(
    value_json,
    '$.component_recovery_modes.wireguard_admin', 'RESTART'
)
WHERE key='watchdog'
  AND json_type(value_json, '$.component_recovery_modes.wireguard_admin') IS NULL;
