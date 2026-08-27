ALTER TABLE runtime_state ADD COLUMN active_direct_path_id TEXT
    REFERENCES direct_modem_paths(id) ON DELETE SET NULL;

-- Migration 14 introduced the unified method columns after existing VPN
-- runtime tuples had already been created. Backfill a coherent method
-- identity so an in-place upgrade can still validate and recover that tuple.
UPDATE runtime_state
SET active_method_id=(
        SELECT a.id
        FROM access_methods AS a
        WHERE a.kind='SUBSCRIPTION'
          AND a.subscription_id=runtime_state.active_subscription_id
    ),
    active_method_kind='SUBSCRIPTION',
    active_quality_class=COALESCE((
        SELECT p.quality_class
        FROM subscription_modem_paths AS p
        WHERE p.id=runtime_state.active_path_id
    ), 'UNKNOWN')
WHERE active_path_id IS NOT NULL
  AND active_subscription_id IS NOT NULL
  AND active_node_id IS NOT NULL
  AND active_method_id IS NULL;
