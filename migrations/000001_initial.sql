CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_secret_ref TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    auto_refresh INTEGER NOT NULL DEFAULT 1,
    refresh_interval_seconds INTEGER NOT NULL DEFAULT 3600,
    fallback_when_named_candidates_fail INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'UNKNOWN',
    active_version_id TEXT,
    last_refresh_at TEXT,
    last_success_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX subscriptions_priority_enabled
ON subscriptions(priority) WHERE enabled = 1;

CREATE TABLE modems (
    id TEXT PRIMARY KEY,
    display_number INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    operator_label TEXT,
    observed_operator TEXT,
    identity_kind TEXT NOT NULL,
    identity_hash TEXT NOT NULL,
    masked_serial TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    interface_name TEXT,
    management_cidr TEXT,
    gateway TEXT,
    dns_json TEXT,
    mtu INTEGER,
    routing_table_id INTEGER NOT NULL UNIQUE,
    fwmark INTEGER NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'MODEM_CONFIGURED_OFFLINE',
    telemetry_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    management_reachability_state TEXT NOT NULL DEFAULT 'UNTESTED',
    last_seen_at TEXT,
    stable_since TEXT,
    api_secret_ref TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX modems_identity
ON modems(identity_kind, identity_hash);

CREATE UNIQUE INDEX modems_priority_enabled
ON modems(priority) WHERE enabled = 1;

CREATE TABLE subscription_versions (
    id TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    nodes_total INTEGER NOT NULL,
    state TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE INDEX subscription_versions_subscription_created
ON subscription_versions(subscription_id, created_at DESC);

CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    version_id TEXT NOT NULL,
    external_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    proxy_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    selection_override TEXT NOT NULL DEFAULT 'auto',
    candidate_source TEXT NOT NULL DEFAULT 'UNCLASSIFIED',
    FOREIGN KEY(version_id) REFERENCES subscription_versions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX nodes_version_fingerprint
ON nodes(version_id, fingerprint);

CREATE UNIQUE INDEX nodes_version_normalized_name
ON nodes(version_id, normalized_name);

CREATE TABLE node_matchers (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    match_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX node_matchers_priority_enabled
ON node_matchers(priority) WHERE enabled = 1;

CREATE TABLE bypass_probe_targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_value TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    required INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 8,
    success_mode TEXT NOT NULL DEFAULT 'any_http_response',
    expected_status TEXT,
    expected_body_substring TEXT,
    state TEXT NOT NULL DEFAULT 'UNKNOWN',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX bypass_probe_targets_priority_enabled
ON bypass_probe_targets(priority) WHERE enabled = 1;

CREATE TABLE subscription_modem_paths (
    id TEXT PRIMARY KEY,
    modem_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'UNTESTED',
    transport_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    selected_node_id TEXT,
    candidate_nodes INTEGER NOT NULL DEFAULT 0,
    qualified_nodes INTEGER NOT NULL DEFAULT 0,
    required_targets_passed INTEGER NOT NULL DEFAULT 0,
    required_targets_total INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    policy_generation INTEGER NOT NULL DEFAULT 0,
    route_generation INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(modem_id, subscription_id),
    FOREIGN KEY(modem_id) REFERENCES modems(id) ON DELETE CASCADE,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    FOREIGN KEY(selected_node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

CREATE INDEX subscription_modem_paths_ranking
ON subscription_modem_paths(modem_id, subscription_id, state);

CREATE TABLE path_nodes (
    path_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    qualification_state TEXT NOT NULL DEFAULT 'UNTESTED',
    qualification_generation INTEGER NOT NULL DEFAULT 0,
    route_generation INTEGER NOT NULL DEFAULT 0,
    qualification_expires_at TEXT,
    latency_ms INTEGER,
    last_success_at TEXT,
    last_failure_at TEXT,
    failure_code TEXT,
    PRIMARY KEY(path_id, node_id),
    FOREIGN KEY(path_id) REFERENCES subscription_modem_paths(id) ON DELETE CASCADE,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE path_node_target_results (
    path_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    state TEXT NOT NULL,
    latency_ms INTEGER,
    http_status INTEGER,
    error_code TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_generation INTEGER NOT NULL,
    route_generation INTEGER NOT NULL,
    PRIMARY KEY(path_id, node_id, target_id),
    FOREIGN KEY(path_id, node_id) REFERENCES path_nodes(path_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(target_id) REFERENCES bypass_probe_targets(id) ON DELETE CASCADE
);

CREATE INDEX path_node_target_results_freshness
ON path_node_target_results(path_id, policy_generation, route_generation, expires_at);

CREATE TABLE runtime_state (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
    gateway_state TEXT NOT NULL,
    path_state TEXT NOT NULL,
    active_modem_id TEXT,
    active_path_id TEXT,
    management_modem_id TEXT,
    active_subscription_id TEXT,
    active_node_id TEXT,
    config_generation INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(active_modem_id) REFERENCES modems(id) ON DELETE SET NULL,
    FOREIGN KEY(active_path_id) REFERENCES subscription_modem_paths(id) ON DELETE SET NULL,
    FOREIGN KEY(management_modem_id) REFERENCES modems(id) ON DELETE SET NULL,
    FOREIGN KEY(active_subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL,
    FOREIGN KEY(active_node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

INSERT INTO runtime_state (
    singleton_id,
    gateway_state,
    path_state,
    config_generation,
    updated_at
) VALUES (
    1,
    'BOOTING',
    'PATH_BLOCKED',
    0,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    modem_id TEXT,
    subscription_id TEXT,
    path_id TEXT,
    details_json TEXT NOT NULL
);

CREATE INDEX events_occurred_at
ON events(occurred_at DESC);

CREATE TABLE health_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    measured_at TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT,
    state TEXT NOT NULL,
    latency_ms INTEGER,
    error_code TEXT
);

CREATE INDEX health_samples_scope_measured
ON health_samples(scope_type, scope_id, measured_at DESC);

CREATE TABLE traffic_daily_totals (
    date TEXT PRIMARY KEY,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    upload_bytes INTEGER NOT NULL DEFAULT 0,
    mihomo_download_bytes INTEGER NOT NULL DEFAULT 0,
    mihomo_upload_bytes INTEGER NOT NULL DEFAULT 0,
    checkpointed_at TEXT NOT NULL
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
