ALTER TABLE runtime_state ADD COLUMN policy_transition_generation INTEGER;
ALTER TABLE runtime_state ADD COLUMN policy_transition_started_at TEXT;
ALTER TABLE runtime_state ADD COLUMN policy_transition_deadline TEXT;

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
     AND NEW.gateway_state = 'VERIFYING_POLICY'
     AND NEW.path_state = 'PATH_ACTIVE'
     AND NEW.active_modem_id IS NOT NULL
     AND NEW.active_path_id IS NOT NULL
     AND NEW.active_subscription_id IS NOT NULL
     AND NEW.active_node_id IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid runtime policy transition');
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
     AND NEW.gateway_state = 'VERIFYING_POLICY'
     AND NEW.path_state = 'PATH_ACTIVE'
     AND NEW.active_modem_id IS NOT NULL
     AND NEW.active_path_id IS NOT NULL
     AND NEW.active_subscription_id IS NOT NULL
     AND NEW.active_node_id IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid runtime policy transition');
END;
