DROP TRIGGER runtime_state_policy_transition_validate_insert;
DROP TRIGGER runtime_state_policy_transition_validate_update;
DROP TRIGGER runtime_state_generic_update;

ALTER TABLE runtime_state RENAME TO runtime_state_legacy_v17;

CREATE TABLE runtime_state (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    gateway_state TEXT NOT NULL,
    path_state TEXT NOT NULL,
    active_uplink_id TEXT,
    active_path_id TEXT,
    active_direct_path_id TEXT,
    management_uplink_id TEXT,
    active_subscription_id TEXT,
    active_node_id TEXT,
    active_method_id TEXT,
    active_method_kind TEXT,
    active_quality_class TEXT,
    config_generation INTEGER NOT NULL DEFAULT 0,
    policy_transition_generation INTEGER,
    policy_transition_started_at TEXT,
    policy_transition_deadline TEXT,
    updated_at TEXT NOT NULL,

    -- Read-only compatibility projection during the successor migration.
    -- Generic runtime code never uses these columns as authority.
    active_modem_id TEXT,
    management_modem_id TEXT,

    FOREIGN KEY(active_uplink_id) REFERENCES uplinks(id) ON DELETE SET NULL,
    FOREIGN KEY(active_path_id) REFERENCES subscription_uplink_paths(id) ON DELETE SET NULL,
    FOREIGN KEY(active_direct_path_id) REFERENCES direct_uplink_paths(id) ON DELETE SET NULL,
    FOREIGN KEY(management_uplink_id) REFERENCES uplinks(id) ON DELETE SET NULL,
    FOREIGN KEY(active_subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL,
    FOREIGN KEY(active_node_id) REFERENCES nodes(id) ON DELETE SET NULL,
    CHECK(
        (active_method_kind IS NULL AND active_method_id IS NULL
         AND active_path_id IS NULL AND active_direct_path_id IS NULL)
        OR
        (active_method_kind='SUBSCRIPTION' AND active_method_id IS NOT NULL
         AND active_uplink_id IS NOT NULL AND active_path_id IS NOT NULL
         AND active_direct_path_id IS NULL AND active_subscription_id IS NOT NULL
         AND active_node_id IS NOT NULL)
        OR
        (active_method_kind='DIRECT' AND active_method_id IS NOT NULL
         AND active_uplink_id IS NOT NULL AND active_path_id IS NULL
         AND active_direct_path_id IS NOT NULL AND active_subscription_id IS NULL
         AND active_node_id IS NULL)
    )
);

INSERT INTO runtime_state (
    singleton_id, gateway_state, path_state, active_uplink_id, active_path_id,
    active_direct_path_id, management_uplink_id, active_subscription_id,
    active_node_id, active_method_id, active_method_kind, active_quality_class,
    config_generation, policy_transition_generation,
    policy_transition_started_at, policy_transition_deadline, updated_at,
    active_modem_id, management_modem_id
)
SELECT
    singleton_id, gateway_state, path_state,
    COALESCE(active_uplink_id, active_modem_id), active_path_id,
    active_direct_path_id, COALESCE(management_uplink_id, management_modem_id),
    active_subscription_id, active_node_id, active_method_id, active_method_kind,
    active_quality_class, config_generation, policy_transition_generation,
    policy_transition_started_at, policy_transition_deadline, updated_at,
    active_modem_id, management_modem_id
FROM runtime_state_legacy_v17;

DROP TABLE runtime_state_legacy_v17;

-- Periodic health scheduling follows the canonical VPN path as well. Without
-- rebuilding this foreign key an Ethernet path could be activated but could
-- not be scheduled for startup requalification.
ALTER TABLE path_health_runtime RENAME TO path_health_runtime_legacy_v17;

CREATE TABLE path_health_runtime (
    path_id TEXT PRIMARY KEY,
    probe_class TEXT NOT NULL,
    next_probe_at TEXT NOT NULL,
    last_probe_at TEXT,
    last_result TEXT NOT NULL DEFAULT 'UNKNOWN',
    consecutive_successes INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_successes >= 0),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures >= 0),
    deferred_reason TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(path_id) REFERENCES subscription_uplink_paths(id) ON DELETE CASCADE,
    CHECK(probe_class IN ('ACTIVE', 'STANDBY')),
    CHECK(last_result IN ('UNKNOWN', 'PASSED', 'FAILED', 'DEFERRED_BUDGET')),
    CHECK(NOT (consecutive_successes > 0 AND consecutive_failures > 0)),
    CHECK((last_result = 'DEFERRED_BUDGET') = (deferred_reason IS NOT NULL))
);

INSERT INTO path_health_runtime
SELECT h.*
FROM path_health_runtime_legacy_v17 AS h
JOIN subscription_uplink_paths AS p ON p.id=h.path_id;

DROP TABLE path_health_runtime_legacy_v17;

CREATE INDEX path_health_runtime_due
ON path_health_runtime(probe_class, next_probe_at, path_id);

CREATE TRIGGER runtime_state_policy_transition_validate_insert
BEFORE INSERT ON runtime_state
WHEN NOT (
    (NEW.policy_transition_generation IS NULL
     AND NEW.policy_transition_started_at IS NULL
     AND NEW.policy_transition_deadline IS NULL)
    OR
    (NEW.policy_transition_generation IS NOT NULL
     AND NEW.policy_transition_generation > 0
     AND NEW.policy_transition_started_at IS NOT NULL
     AND NEW.policy_transition_deadline IS NOT NULL
     AND NEW.policy_transition_started_at < NEW.policy_transition_deadline
     AND NEW.gateway_state='VERIFYING_POLICY'
     AND NEW.path_state='PATH_ACTIVE'
     AND NEW.active_uplink_id IS NOT NULL
     AND NEW.active_path_id IS NOT NULL
     AND NEW.active_subscription_id IS NOT NULL
     AND NEW.active_node_id IS NOT NULL
     AND NEW.active_method_kind='SUBSCRIPTION')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid generic runtime policy transition');
END;

CREATE TRIGGER runtime_state_policy_transition_validate_update
BEFORE UPDATE ON runtime_state
WHEN NOT (
    (NEW.policy_transition_generation IS NULL
     AND NEW.policy_transition_started_at IS NULL
     AND NEW.policy_transition_deadline IS NULL)
    OR
    (NEW.policy_transition_generation IS NOT NULL
     AND NEW.policy_transition_generation > 0
     AND NEW.policy_transition_started_at IS NOT NULL
     AND NEW.policy_transition_deadline IS NOT NULL
     AND NEW.policy_transition_started_at < NEW.policy_transition_deadline
     AND NEW.gateway_state='VERIFYING_POLICY'
     AND NEW.path_state='PATH_ACTIVE'
     AND NEW.active_uplink_id IS NOT NULL
     AND NEW.active_path_id IS NOT NULL
     AND NEW.active_subscription_id IS NOT NULL
     AND NEW.active_node_id IS NOT NULL
     AND NEW.active_method_kind='SUBSCRIPTION')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid generic runtime policy transition');
END;

ALTER TABLE events ADD COLUMN uplink_id TEXT;
UPDATE events SET uplink_id=modem_id WHERE modem_id IS NOT NULL;
CREATE INDEX events_uplink_occurred_at ON events(uplink_id, occurred_at DESC);
