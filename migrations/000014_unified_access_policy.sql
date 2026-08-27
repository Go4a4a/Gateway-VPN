CREATE TABLE access_methods (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('DIRECT', 'SUBSCRIPTION')),
    subscription_id TEXT UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    priority INTEGER NOT NULL CHECK(priority > 0),
    immutable INTEGER NOT NULL DEFAULT 0 CHECK(immutable IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    CHECK(
        (kind='DIRECT' AND subscription_id IS NULL AND immutable=1)
        OR
        (kind='SUBSCRIPTION' AND subscription_id IS NOT NULL AND immutable=0)
    )
);

CREATE UNIQUE INDEX access_methods_enabled_priority
ON access_methods(priority) WHERE enabled=1;

CREATE UNIQUE INDEX access_methods_single_direct
ON access_methods(kind) WHERE kind='DIRECT';

INSERT INTO access_methods (
    id, kind, subscription_id, enabled, priority, immutable, created_at, updated_at
) VALUES (
    'access:direct', 'DIRECT', NULL, 1, 10, 1,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

INSERT INTO access_methods (
    id, kind, subscription_id, enabled, priority, immutable, created_at, updated_at
)
SELECT
    'access:subscription:' || id,
    'SUBSCRIPTION',
    id,
    enabled,
    priority + 10,
    0,
    created_at,
    updated_at
FROM subscriptions;

CREATE TABLE access_policy (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    startup_block_until_qualified INTEGER NOT NULL DEFAULT 1 CHECK(startup_block_until_qualified IN (0, 1)),
    direct_service_refresh_enabled INTEGER NOT NULL DEFAULT 1 CHECK(direct_service_refresh_enabled IN (0, 1)),
    failure_hold_seconds INTEGER NOT NULL DEFAULT 30 CHECK(failure_hold_seconds BETWEEN 0 AND 300),
    recovery_stable_seconds INTEGER NOT NULL DEFAULT 120 CHECK(recovery_stable_seconds BETWEEN 0 AND 3600),
    switch_cooldown_seconds INTEGER NOT NULL DEFAULT 60 CHECK(switch_cooldown_seconds BETWEEN 0 AND 3600),
    ranking_generation INTEGER NOT NULL DEFAULT 1 CHECK(ranking_generation > 0),
    updated_at TEXT NOT NULL
);

INSERT INTO access_policy(singleton_id, updated_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

ALTER TABLE modems ADD COLUMN route_generation INTEGER NOT NULL DEFAULT 0
    CHECK(route_generation >= 0);

ALTER TABLE subscription_modem_paths ADD COLUMN quality_class TEXT NOT NULL DEFAULT 'UNKNOWN'
    CHECK(quality_class IN ('UNKNOWN', 'FULL', 'LIMITED', 'FAILED'));
ALTER TABLE subscription_modem_paths ADD COLUMN functional_score INTEGER NOT NULL DEFAULT 0
    CHECK(functional_score >= 0);
ALTER TABLE subscription_modem_paths ADD COLUMN optional_targets_passed INTEGER NOT NULL DEFAULT 0
    CHECK(optional_targets_passed >= 0);
ALTER TABLE subscription_modem_paths ADD COLUMN optional_targets_total INTEGER NOT NULL DEFAULT 0
    CHECK(optional_targets_total >= 0);

CREATE TABLE direct_modem_paths (
    id TEXT PRIMARY KEY,
    modem_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'UNTESTED',
    transport_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    quality_class TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(quality_class IN ('UNKNOWN', 'FULL', 'LIMITED', 'FAILED')),
    functional_score INTEGER NOT NULL DEFAULT 0 CHECK(functional_score >= 0),
    required_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(required_targets_passed >= 0),
    required_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(required_targets_total >= 0),
    optional_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(optional_targets_passed >= 0),
    optional_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(optional_targets_total >= 0),
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    policy_generation INTEGER NOT NULL DEFAULT 0 CHECK(policy_generation >= 0),
    route_generation INTEGER NOT NULL DEFAULT 0 CHECK(route_generation >= 0),
    last_checked_at TEXT,
    expires_at TEXT,
    failure_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(modem_id) REFERENCES modems(id) ON DELETE CASCADE,
    CHECK(required_targets_passed <= required_targets_total),
    CHECK(optional_targets_passed <= optional_targets_total)
);

CREATE INDEX direct_modem_paths_ranking
ON direct_modem_paths(quality_class, functional_score DESC, modem_id);

CREATE TABLE direct_path_target_results (
    path_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    state TEXT NOT NULL,
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    http_status INTEGER,
    error_code TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_generation INTEGER NOT NULL CHECK(policy_generation >= 0),
    route_generation INTEGER NOT NULL CHECK(route_generation >= 0),
    PRIMARY KEY(path_id, target_id),
    FOREIGN KEY(path_id) REFERENCES direct_modem_paths(id) ON DELETE CASCADE,
    FOREIGN KEY(target_id) REFERENCES bypass_probe_targets(id) ON DELETE CASCADE
);

CREATE INDEX direct_path_target_results_freshness
ON direct_path_target_results(path_id, policy_generation, route_generation, expires_at);

CREATE TABLE subscription_node_preferences (
    subscription_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    selection_override TEXT NOT NULL DEFAULT 'auto'
        CHECK(selection_override IN ('auto', 'include', 'exclude')),
    preferred_rank INTEGER CHECK(preferred_rank IS NULL OR preferred_rank > 0),
    user_label TEXT NOT NULL DEFAULT '' CHECK(length(user_label) <= 128),
    last_seen_version_id TEXT NOT NULL DEFAULT '',
    missing_since TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(subscription_id, fingerprint),
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX subscription_node_preferences_rank
ON subscription_node_preferences(subscription_id, preferred_rank)
WHERE preferred_rank IS NOT NULL;

INSERT INTO subscription_node_preferences (
    subscription_id, fingerprint, selection_override, last_seen_version_id,
    created_at, updated_at
)
SELECT
    s.id, n.fingerprint, n.selection_override, n.version_id,
    s.updated_at, s.updated_at
FROM subscriptions AS s
JOIN nodes AS n ON n.version_id=s.active_version_id;

CREATE TABLE access_selection_runtime (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    pending_candidate_key TEXT,
    pending_candidate_since TEXT,
    last_switch_at TEXT,
    last_switch_reason TEXT,
    temporary_direct_only INTEGER NOT NULL DEFAULT 0 CHECK(temporary_direct_only IN (0, 1)),
    temporary_direct_boot_id TEXT,
    updated_at TEXT NOT NULL,
    CHECK(
        (temporary_direct_only=0 AND temporary_direct_boot_id IS NULL)
        OR
        (temporary_direct_only=1 AND temporary_direct_boot_id IS NOT NULL)
    )
);

INSERT INTO access_selection_runtime(singleton_id, updated_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    requested_by TEXT NOT NULL DEFAULT 'SYSTEM',
    summary_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL,
    CHECK((status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')) = (finished_at IS NOT NULL))
);

CREATE INDEX operations_recent
ON operations(created_at DESC, id DESC);

CREATE INDEX operations_active
ON operations(status, updated_at) WHERE status IN ('QUEUED', 'RUNNING');

CREATE TABLE operation_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    occurred_at TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR')),
    stage TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL CHECK(length(message) <= 512),
    details_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(operation_id, sequence),
    FOREIGN KEY(operation_id) REFERENCES operations(id) ON DELETE CASCADE
);

CREATE INDEX operation_steps_operation_sequence
ON operation_steps(operation_id, sequence);

ALTER TABLE runtime_state ADD COLUMN active_method_id TEXT;
ALTER TABLE runtime_state ADD COLUMN active_method_kind TEXT;
ALTER TABLE runtime_state ADD COLUMN active_quality_class TEXT;
