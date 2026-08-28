ALTER TABLE bypass_probe_targets ADD COLUMN target_class TEXT NOT NULL DEFAULT 'GLOBAL_REQUIRED'
    CHECK(target_class IN ('GLOBAL_REQUIRED', 'GLOBAL_OPTIONAL', 'WHITELIST_INDICATOR', 'SERVICE_ENDPOINT'));

UPDATE bypass_probe_targets
SET target_class=CASE WHEN required=1 THEN 'GLOBAL_REQUIRED' ELSE 'GLOBAL_OPTIONAL' END;

CREATE TABLE network_interfaces (
    id TEXT PRIMARY KEY,
    stable_identity_kind TEXT NOT NULL,
    stable_identity_hash TEXT NOT NULL,
    permanent_mac TEXT,
    topology_path TEXT,
    current_ifname TEXT,
    driver TEXT,
    vendor TEXT,
    model TEXT,
    carrier_state TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(carrier_state IN ('UNKNOWN', 'UP', 'DOWN', 'ABSENT')),
    addresses_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT,
    replacement_for_interface_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(stable_identity_kind, stable_identity_hash),
    FOREIGN KEY(replacement_for_interface_id) REFERENCES network_interfaces(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX network_interfaces_current_ifname
ON network_interfaces(current_ifname) WHERE current_ifname IS NOT NULL;

INSERT INTO network_interfaces (
    id, stable_identity_kind, stable_identity_hash, current_ifname,
    carrier_state, observed_at, created_at, updated_at
)
SELECT
    'netif:legacy:' || id,
    'HILINK_' || identity_kind,
    identity_hash,
    interface_name,
    CASE
        WHEN state='MODEM_READY' THEN 'UP'
        WHEN state='MODEM_CONFIGURED_OFFLINE' THEN 'ABSENT'
        ELSE 'UNKNOWN'
    END,
    last_seen_at,
    created_at,
    updated_at
FROM modems;

CREATE TABLE uplinks (
    id TEXT PRIMARY KEY,
    display_number INTEGER NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK(type IN ('HILINK', 'ETHERNET')),
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    priority INTEGER NOT NULL CHECK(priority <> 0),
    network_interface_id TEXT,
    address_mode TEXT NOT NULL DEFAULT 'DHCP' CHECK(address_mode IN ('DHCP', 'STATIC')),
    ipv4_cidr TEXT,
    gateway TEXT,
    dns_json TEXT NOT NULL DEFAULT '[]',
    mtu INTEGER CHECK(mtu IS NULL OR mtu BETWEEN 576 AND 9216),
    routing_table_id INTEGER NOT NULL UNIQUE,
    fwmark INTEGER NOT NULL UNIQUE,
    route_generation INTEGER NOT NULL DEFAULT 0 CHECK(route_generation >= 0),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    observed_generation INTEGER NOT NULL DEFAULT 0 CHECK(observed_generation >= 0),
    state TEXT NOT NULL DEFAULT 'UPLINK_CONFIGURED_OFFLINE',
    last_seen_at TEXT,
    stable_since TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(network_interface_id) REFERENCES network_interfaces(id) ON DELETE SET NULL,
    CHECK(address_mode='DHCP' OR (ipv4_cidr IS NOT NULL AND gateway IS NOT NULL))
);

CREATE UNIQUE INDEX uplinks_priority_enabled
ON uplinks(priority) WHERE enabled=1;

CREATE INDEX uplinks_type_state
ON uplinks(type, state, priority);

INSERT INTO uplinks (
    id, display_number, type, name, enabled, priority, network_interface_id,
    address_mode, ipv4_cidr, gateway, dns_json, mtu, routing_table_id, fwmark,
    route_generation, state, last_seen_at, stable_since, created_at, updated_at
)
SELECT
    id,
    display_number,
    'HILINK',
    name,
    enabled,
    priority,
    'netif:legacy:' || id,
    'DHCP',
    management_cidr,
    gateway,
    COALESCE(dns_json, '[]'),
    mtu,
    routing_table_id,
    fwmark,
    route_generation,
    CASE
        WHEN state LIKE 'MODEM_%' THEN 'UPLINK_' || substr(state, 7)
        ELSE state
    END,
    last_seen_at,
    stable_since,
    created_at,
    updated_at
FROM modems;

INSERT OR IGNORE INTO settings(key, value_json, updated_at)
SELECT 'next_uplink_display_number', CAST(COALESCE(MAX(display_number), 0) + 1 AS TEXT),
       strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM uplinks;

INSERT OR IGNORE INTO settings(key, value_json, updated_at)
SELECT 'next_uplink_routing_table', CAST(MAX(COALESCE((SELECT MAX(routing_table_id) FROM uplinks), 1100) + 1, 1101) AS TEXT),
       strftime('%Y-%m-%dT%H:%M:%fZ', 'now');

INSERT OR IGNORE INTO settings(key, value_json, updated_at)
SELECT 'next_uplink_fwmark', CAST(MAX(COALESCE((SELECT MAX(fwmark) FROM uplinks), 4352) + 1, 4353) AS TEXT),
       strftime('%Y-%m-%dT%H:%M:%fZ', 'now');

CREATE TABLE hilink_modems (
    uplink_id TEXT PRIMARY KEY,
    operator_label TEXT,
    observed_operator TEXT,
    identity_kind TEXT NOT NULL,
    identity_hash TEXT NOT NULL,
    masked_serial TEXT,
    modem_state TEXT NOT NULL DEFAULT 'MODEM_CONFIGURED_OFFLINE',
    telemetry_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    management_reachability_state TEXT NOT NULL DEFAULT 'UNTESTED',
    api_secret_ref TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(identity_kind, identity_hash),
    FOREIGN KEY(uplink_id) REFERENCES uplinks(id) ON DELETE CASCADE
);

INSERT INTO hilink_modems (
    uplink_id, operator_label, observed_operator, identity_kind, identity_hash,
    masked_serial, modem_state, telemetry_state, management_reachability_state,
    api_secret_ref, created_at, updated_at
)
SELECT
    id, operator_label, observed_operator, identity_kind, identity_hash,
    masked_serial, state, telemetry_state, management_reachability_state,
    api_secret_ref, created_at, updated_at
FROM modems;

CREATE TABLE legacy_modem_uplink_map (
    modem_id TEXT PRIMARY KEY,
    uplink_id TEXT NOT NULL UNIQUE,
    migrated_at TEXT NOT NULL,
    FOREIGN KEY(modem_id) REFERENCES modems(id) ON DELETE RESTRICT,
    FOREIGN KEY(uplink_id) REFERENCES uplinks(id) ON DELETE CASCADE
);

INSERT INTO legacy_modem_uplink_map(modem_id, uplink_id, migrated_at)
SELECT id, id, strftime('%Y-%m-%dT%H:%M:%fZ', 'now') FROM modems;

CREATE TABLE interface_role_assignments (
    id TEXT PRIMARY KEY,
    network_interface_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN (
        'LAN_MEMBER', 'MANAGEMENT', 'ETHERNET_UPLINK', 'HILINK_UPLINK',
        'WG_ENDPOINT', 'SHARED_ONE_ARM', 'UNUSED'
    )),
    uplink_id TEXT,
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    observed_generation INTEGER NOT NULL DEFAULT 0 CHECK(observed_generation >= 0),
    state TEXT NOT NULL DEFAULT 'CONFIGURED',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(network_interface_id, role),
    FOREIGN KEY(network_interface_id) REFERENCES network_interfaces(id) ON DELETE CASCADE,
    FOREIGN KEY(uplink_id) REFERENCES uplinks(id) ON DELETE CASCADE,
    CHECK(
        (role IN ('ETHERNET_UPLINK', 'HILINK_UPLINK') AND uplink_id IS NOT NULL)
        OR
        (role NOT IN ('ETHERNET_UPLINK', 'HILINK_UPLINK') AND uplink_id IS NULL)
    )
);

INSERT INTO interface_role_assignments (
    id, network_interface_id, role, uplink_id, created_at, updated_at
)
SELECT
    'role:hilink:' || id,
    'netif:legacy:' || id,
    'HILINK_UPLINK',
    id,
    created_at,
    updated_at
FROM modems;

CREATE TABLE subscription_uplink_paths (
    id TEXT PRIMARY KEY,
    uplink_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'UNTESTED',
    transport_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    selected_node_id TEXT,
    candidate_nodes INTEGER NOT NULL DEFAULT 0 CHECK(candidate_nodes >= 0),
    qualified_nodes INTEGER NOT NULL DEFAULT 0 CHECK(qualified_nodes >= 0),
    required_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(required_targets_passed >= 0),
    required_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(required_targets_total >= 0),
    optional_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(optional_targets_passed >= 0),
    optional_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(optional_targets_total >= 0),
    quality_class TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(quality_class IN ('UNKNOWN', 'FULL', 'LIMITED', 'WHITELIST_ONLY', 'FAILED')),
    functional_score INTEGER NOT NULL DEFAULT 0 CHECK(functional_score >= 0),
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    policy_generation INTEGER NOT NULL DEFAULT 0 CHECK(policy_generation >= 0),
    route_generation INTEGER NOT NULL DEFAULT 0 CHECK(route_generation >= 0),
    last_checked_at TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(uplink_id, subscription_id),
    FOREIGN KEY(uplink_id) REFERENCES uplinks(id) ON DELETE CASCADE,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    FOREIGN KEY(selected_node_id) REFERENCES nodes(id) ON DELETE SET NULL,
    CHECK(qualified_nodes <= candidate_nodes),
    CHECK(required_targets_passed <= required_targets_total),
    CHECK(optional_targets_passed <= optional_targets_total)
);

CREATE INDEX subscription_uplink_paths_ranking
ON subscription_uplink_paths(quality_class, functional_score DESC, uplink_id, subscription_id);

INSERT INTO subscription_uplink_paths (
    id, uplink_id, subscription_id, state, transport_state, selected_node_id,
    candidate_nodes, qualified_nodes, required_targets_passed, required_targets_total,
    optional_targets_passed, optional_targets_total, quality_class, functional_score,
    latency_ms, policy_generation, route_generation, last_checked_at, expires_at,
    created_at, updated_at
)
SELECT
    id,
    modem_id,
    subscription_id,
    CASE
        WHEN state='MODEM_OFFLINE' THEN 'UPLINK_OFFLINE'
        WHEN state='MODEM_DISABLED' THEN 'UPLINK_DISABLED'
        ELSE state
    END,
    transport_state,
    selected_node_id,
    candidate_nodes,
    qualified_nodes,
    required_targets_passed,
    required_targets_total,
    optional_targets_passed,
    optional_targets_total,
    quality_class,
    functional_score,
    latency_ms,
    policy_generation,
    route_generation,
    last_checked_at,
    expires_at,
    created_at,
    updated_at
FROM subscription_modem_paths;

CREATE TABLE uplink_path_nodes (
    path_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    qualification_state TEXT NOT NULL DEFAULT 'UNTESTED',
    qualification_generation INTEGER NOT NULL DEFAULT 0 CHECK(qualification_generation >= 0),
    route_generation INTEGER NOT NULL DEFAULT 0 CHECK(route_generation >= 0),
    qualification_expires_at TEXT,
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    last_success_at TEXT,
    last_failure_at TEXT,
    failure_code TEXT,
    PRIMARY KEY(path_id, node_id),
    FOREIGN KEY(path_id) REFERENCES subscription_uplink_paths(id) ON DELETE CASCADE,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

INSERT INTO uplink_path_nodes
SELECT * FROM path_nodes;

CREATE TABLE uplink_path_node_target_results (
    path_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    state TEXT NOT NULL,
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    http_status INTEGER,
    error_code TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_generation INTEGER NOT NULL CHECK(policy_generation >= 0),
    route_generation INTEGER NOT NULL CHECK(route_generation >= 0),
    PRIMARY KEY(path_id, node_id, target_id),
    FOREIGN KEY(path_id, node_id) REFERENCES uplink_path_nodes(path_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(target_id) REFERENCES bypass_probe_targets(id) ON DELETE CASCADE
);

CREATE INDEX uplink_path_node_target_results_freshness
ON uplink_path_node_target_results(path_id, policy_generation, route_generation, expires_at);

INSERT INTO uplink_path_node_target_results
SELECT * FROM path_node_target_results;

CREATE TABLE direct_uplink_paths (
    id TEXT PRIMARY KEY,
    uplink_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'UNTESTED',
    transport_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    quality_class TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(quality_class IN ('UNKNOWN', 'FULL', 'LIMITED', 'WHITELIST_ONLY', 'FAILED')),
    functional_score INTEGER NOT NULL DEFAULT 0 CHECK(functional_score >= 0),
    required_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(required_targets_passed >= 0),
    required_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(required_targets_total >= 0),
    optional_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(optional_targets_passed >= 0),
    optional_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(optional_targets_total >= 0),
    whitelist_targets_passed INTEGER NOT NULL DEFAULT 0 CHECK(whitelist_targets_passed >= 0),
    whitelist_targets_total INTEGER NOT NULL DEFAULT 0 CHECK(whitelist_targets_total >= 0),
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    policy_generation INTEGER NOT NULL DEFAULT 0 CHECK(policy_generation >= 0),
    route_generation INTEGER NOT NULL DEFAULT 0 CHECK(route_generation >= 0),
    last_checked_at TEXT,
    expires_at TEXT,
    failure_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(uplink_id) REFERENCES uplinks(id) ON DELETE CASCADE,
    CHECK(required_targets_passed <= required_targets_total),
    CHECK(optional_targets_passed <= optional_targets_total),
    CHECK(whitelist_targets_passed <= whitelist_targets_total)
);

CREATE INDEX direct_uplink_paths_ranking
ON direct_uplink_paths(quality_class, functional_score DESC, uplink_id);

INSERT INTO direct_uplink_paths (
    id, uplink_id, state, transport_state, quality_class, functional_score,
    required_targets_passed, required_targets_total, optional_targets_passed,
    optional_targets_total, latency_ms, policy_generation, route_generation,
    last_checked_at, expires_at, failure_code, created_at, updated_at
)
SELECT
    id, modem_id, state, transport_state, quality_class, functional_score,
    required_targets_passed, required_targets_total, optional_targets_passed,
    optional_targets_total, latency_ms, policy_generation, route_generation,
    last_checked_at, expires_at, failure_code, created_at, updated_at
FROM direct_modem_paths;

CREATE TABLE direct_uplink_path_target_results (
    path_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_class TEXT NOT NULL
        CHECK(target_class IN ('GLOBAL_REQUIRED', 'GLOBAL_OPTIONAL', 'WHITELIST_INDICATOR')),
    state TEXT NOT NULL,
    latency_ms INTEGER CHECK(latency_ms IS NULL OR latency_ms >= 0),
    http_status INTEGER,
    error_code TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_generation INTEGER NOT NULL CHECK(policy_generation >= 0),
    route_generation INTEGER NOT NULL CHECK(route_generation >= 0),
    PRIMARY KEY(path_id, target_id),
    FOREIGN KEY(path_id) REFERENCES direct_uplink_paths(id) ON DELETE CASCADE,
    FOREIGN KEY(target_id) REFERENCES bypass_probe_targets(id) ON DELETE CASCADE
);

CREATE INDEX direct_uplink_path_target_results_freshness
ON direct_uplink_path_target_results(path_id, target_class, policy_generation, route_generation, expires_at);

INSERT INTO direct_uplink_path_target_results (
    path_id, target_id, target_class, state, latency_ms, http_status, error_code,
    checked_at, expires_at, policy_generation, route_generation
)
SELECT
    r.path_id, r.target_id, t.target_class, r.state, r.latency_ms, r.http_status,
    r.error_code, r.checked_at, r.expires_at, r.policy_generation, r.route_generation
FROM direct_path_target_results AS r
JOIN bypass_probe_targets AS t ON t.id=r.target_id;

ALTER TABLE runtime_state ADD COLUMN active_uplink_id TEXT
    REFERENCES uplinks(id) ON DELETE SET NULL;
ALTER TABLE runtime_state ADD COLUMN management_uplink_id TEXT
    REFERENCES uplinks(id) ON DELETE SET NULL;

UPDATE runtime_state
SET active_uplink_id=active_modem_id,
    management_uplink_id=management_modem_id;

CREATE TABLE wireguard_ingress_servers (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    name TEXT NOT NULL,
    interface_name TEXT NOT NULL DEFAULT 'wg-ingress' UNIQUE,
    subnet_cidr TEXT NOT NULL,
    listen_port INTEGER NOT NULL CHECK(listen_port BETWEEN 1 AND 65535),
    endpoint_host TEXT NOT NULL DEFAULT '',
    mtu INTEGER CHECK(mtu IS NULL OR mtu BETWEEN 576 AND 9000),
    private_key_secret_ref TEXT NOT NULL,
    topology_mode TEXT NOT NULL DEFAULT 'ROUTED'
        CHECK(topology_mode IN ('ROUTED', 'ONE_ARM')),
    network_interface_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(network_interface_id) REFERENCES network_interfaces(id) ON DELETE SET NULL
);

CREATE TABLE wireguard_ingress_peers (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    display_number INTEGER NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    peer_kind TEXT NOT NULL CHECK(peer_kind IN ('DEVICE', 'ROUTER_NAT', 'ROUTER_ROUTED')),
    key_mode TEXT NOT NULL CHECK(key_mode IN ('MANAGED', 'EXTERNAL')),
    public_key TEXT NOT NULL UNIQUE,
    private_key_secret_ref TEXT,
    preshared_key_secret_ref TEXT,
    assigned_address TEXT NOT NULL,
    endpoint_override TEXT NOT NULL DEFAULT '',
    persistent_keepalive INTEGER NOT NULL DEFAULT 25 CHECK(persistent_keepalive BETWEEN 0 AND 65535),
    access_policy_mode TEXT NOT NULL DEFAULT 'AUTO'
        CHECK(access_policy_mode IN ('AUTO', 'DIRECT_ONLY', 'VPN_ONLY')),
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(server_id, display_number),
    UNIQUE(server_id, assigned_address),
    FOREIGN KEY(server_id) REFERENCES wireguard_ingress_servers(id) ON DELETE CASCADE,
    CHECK(
        (key_mode='MANAGED' AND private_key_secret_ref IS NOT NULL)
        OR
        (key_mode='EXTERNAL' AND private_key_secret_ref IS NULL)
    )
);

CREATE TABLE wireguard_ingress_peer_routes (
    peer_id TEXT NOT NULL,
    cidr TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'INGRESS' CHECK(direction IN ('INGRESS', 'RETURN')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(peer_id, cidr, direction),
    FOREIGN KEY(peer_id) REFERENCES wireguard_ingress_peers(id) ON DELETE CASCADE
);

CREATE TABLE wireguard_ingress_runtime (
    server_id TEXT PRIMARY KEY,
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    state TEXT NOT NULL DEFAULT 'DISABLED',
    last_error_code TEXT NOT NULL DEFAULT '',
    last_applied_at TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(server_id) REFERENCES wireguard_ingress_servers(id) ON DELETE CASCADE
);

CREATE TABLE wireguard_ingress_peer_runtime (
    peer_id TEXT PRIMARY KEY,
    last_handshake_at TEXT,
    rx_bytes INTEGER NOT NULL DEFAULT 0 CHECK(rx_bytes >= 0),
    tx_bytes INTEGER NOT NULL DEFAULT 0 CHECK(tx_bytes >= 0),
    observed_endpoint TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'NEVER_CONNECTED',
    updated_at TEXT NOT NULL,
    FOREIGN KEY(peer_id) REFERENCES wireguard_ingress_peers(id) ON DELETE CASCADE
);

CREATE TABLE modem_recovery_policy (
    uplink_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    dhcp_retry_after_seconds INTEGER NOT NULL DEFAULT 30 CHECK(dhcp_retry_after_seconds BETWEEN 5 AND 3600),
    api_retry_after_seconds INTEGER NOT NULL DEFAULT 60 CHECK(api_retry_after_seconds BETWEEN 5 AND 3600),
    mobile_session_restart_after_seconds INTEGER NOT NULL DEFAULT 120 CHECK(mobile_session_restart_after_seconds BETWEEN 10 AND 7200),
    usb_rebind_after_seconds INTEGER NOT NULL DEFAULT 300 CHECK(usb_rebind_after_seconds BETWEEN 30 AND 86400),
    usb_reset_after_seconds INTEGER NOT NULL DEFAULT 600 CHECK(usb_reset_after_seconds BETWEEN 60 AND 86400),
    usb_reset_cooldown_seconds INTEGER NOT NULL DEFAULT 900 CHECK(usb_reset_cooldown_seconds BETWEEN 60 AND 86400),
    max_usb_resets_per_window INTEGER NOT NULL DEFAULT 3 CHECK(max_usb_resets_per_window BETWEEN 0 AND 20),
    usb_reset_window_seconds INTEGER NOT NULL DEFAULT 3600 CHECK(usb_reset_window_seconds BETWEEN 300 AND 86400),
    allow_hub_port_power_cycle INTEGER NOT NULL DEFAULT 0 CHECK(allow_hub_port_power_cycle IN (0, 1)),
    policy_generation INTEGER NOT NULL DEFAULT 1 CHECK(policy_generation > 0),
    updated_at TEXT NOT NULL,
    FOREIGN KEY(uplink_id) REFERENCES hilink_modems(uplink_id) ON DELETE CASCADE
);

INSERT INTO modem_recovery_policy(uplink_id, updated_at)
SELECT uplink_id, updated_at FROM hilink_modems;

CREATE TABLE modem_recovery_runtime (
    uplink_id TEXT PRIMARY KEY,
    policy_generation INTEGER NOT NULL CHECK(policy_generation > 0),
    state TEXT NOT NULL DEFAULT 'IDLE',
    failure_started_at TEXT,
    cooldown_until TEXT,
    budget_window_started_at TEXT,
    usb_resets_in_window INTEGER NOT NULL DEFAULT 0 CHECK(usb_resets_in_window >= 0),
    active_attempt_id TEXT,
    last_outcome_code TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    FOREIGN KEY(uplink_id) REFERENCES hilink_modems(uplink_id) ON DELETE CASCADE
);

INSERT INTO modem_recovery_runtime(uplink_id, policy_generation, updated_at)
SELECT uplink_id, 1, updated_at FROM hilink_modems;

CREATE TABLE modem_recovery_attempts (
    id TEXT PRIMARY KEY,
    uplink_id TEXT NOT NULL,
    policy_generation INTEGER NOT NULL CHECK(policy_generation > 0),
    action TEXT NOT NULL CHECK(action IN (
        'DHCP_RENEW', 'HILINK_API_RECONNECT', 'MOBILE_SESSION_RESTART',
        'USB_DRIVER_REBIND', 'USB_DEVICE_RESET', 'USB_PORT_POWER_CYCLE'
    )),
    requested_by TEXT NOT NULL DEFAULT 'SYSTEM' CHECK(requested_by IN ('SYSTEM', 'USER')),
    status TEXT NOT NULL CHECK(status IN ('RUNNING', 'SUCCEEDED', 'FAILED', 'DEVICE_REMOVED', 'SUPPRESSED')),
    reason_code TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(uplink_id) REFERENCES hilink_modems(uplink_id) ON DELETE CASCADE,
    CHECK((status='RUNNING') = (finished_at IS NULL))
);

CREATE INDEX modem_recovery_attempts_recent
ON modem_recovery_attempts(uplink_id, started_at DESC);

CREATE TABLE log_export_policy (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    max_file_bytes INTEGER NOT NULL DEFAULT 10485760 CHECK(max_file_bytes BETWEEN 1048576 AND 1073741824),
    max_archive_files INTEGER NOT NULL DEFAULT 14 CHECK(max_archive_files BETWEEN 1 AND 365),
    max_total_bytes INTEGER NOT NULL DEFAULT 268435456 CHECK(max_total_bytes BETWEEN 10485760 AND 10737418240),
    retention_days INTEGER NOT NULL DEFAULT 14 CHECK(retention_days BETWEEN 1 AND 365),
    categories_json TEXT NOT NULL DEFAULT '["all","modems","subscriptions","access","vpn-mihomo","network","wireguard-vps","watchdog","updates","security-audit"]',
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    state TEXT NOT NULL DEFAULT 'PENDING',
    updated_at TEXT NOT NULL
);

INSERT INTO log_export_policy(singleton_id, updated_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Compatibility bridge for the bounded successor migration window. Legacy
-- code paths may still write modem-specific tables, but every such write is
-- projected into the generic source in the same SQLite transaction. New
-- Ethernet/WireGuard code writes only generic tables. These triggers are
-- removed together with the legacy schema after all readers are migrated.
CREATE TRIGGER modems_generic_insert
AFTER INSERT ON modems
BEGIN
    INSERT INTO network_interfaces (
        id, stable_identity_kind, stable_identity_hash, current_ifname,
        carrier_state, observed_at, created_at, updated_at
    ) VALUES (
        'netif:legacy:' || NEW.id, 'HILINK_' || NEW.identity_kind,
        NEW.identity_hash, NEW.interface_name,
        CASE WHEN NEW.state='MODEM_READY' THEN 'UP'
             WHEN NEW.state='MODEM_CONFIGURED_OFFLINE' THEN 'ABSENT'
             ELSE 'UNKNOWN' END,
        NEW.last_seen_at, NEW.created_at, NEW.updated_at
    );

    INSERT INTO uplinks (
        id, display_number, type, name, enabled, priority, network_interface_id,
        address_mode, ipv4_cidr, gateway, dns_json, mtu, routing_table_id, fwmark,
        route_generation, state, last_seen_at, stable_since, created_at, updated_at
    ) VALUES (
        NEW.id, NEW.display_number, 'HILINK', NEW.name, NEW.enabled, NEW.priority,
        'netif:legacy:' || NEW.id, 'DHCP', NEW.management_cidr, NEW.gateway,
        COALESCE(NEW.dns_json, '[]'), NEW.mtu, NEW.routing_table_id, NEW.fwmark,
        NEW.route_generation,
        CASE WHEN NEW.state LIKE 'MODEM_%' THEN 'UPLINK_' || substr(NEW.state, 7) ELSE NEW.state END,
        NEW.last_seen_at, NEW.stable_since, NEW.created_at, NEW.updated_at
    );

    INSERT INTO hilink_modems (
        uplink_id, operator_label, observed_operator, identity_kind, identity_hash,
        masked_serial, modem_state, telemetry_state, management_reachability_state,
        api_secret_ref, created_at, updated_at
    ) VALUES (
        NEW.id, NEW.operator_label, NEW.observed_operator, NEW.identity_kind,
        NEW.identity_hash, NEW.masked_serial, NEW.state, NEW.telemetry_state,
        NEW.management_reachability_state, NEW.api_secret_ref, NEW.created_at, NEW.updated_at
    );

    INSERT INTO legacy_modem_uplink_map(modem_id, uplink_id, migrated_at)
    VALUES (NEW.id, NEW.id, NEW.created_at);

    INSERT INTO interface_role_assignments (
        id, network_interface_id, role, uplink_id, created_at, updated_at
    ) VALUES (
        'role:hilink:' || NEW.id, 'netif:legacy:' || NEW.id,
        'HILINK_UPLINK', NEW.id, NEW.created_at, NEW.updated_at
    );

    INSERT INTO modem_recovery_policy(uplink_id, updated_at)
    VALUES (NEW.id, NEW.updated_at);
    INSERT INTO modem_recovery_runtime(uplink_id, policy_generation, updated_at)
    VALUES (NEW.id, 1, NEW.updated_at);

    INSERT INTO settings(key, value_json, updated_at)
    VALUES ('next_uplink_display_number', CAST(NEW.display_number + 1 AS TEXT), NEW.updated_at)
    ON CONFLICT(key) DO UPDATE SET
        value_json=CAST(MAX(CAST(settings.value_json AS INTEGER), NEW.display_number + 1) AS TEXT),
        updated_at=excluded.updated_at;
    INSERT INTO settings(key, value_json, updated_at)
    VALUES ('next_uplink_routing_table', CAST(NEW.routing_table_id + 1 AS TEXT), NEW.updated_at)
    ON CONFLICT(key) DO UPDATE SET
        value_json=CAST(MAX(CAST(settings.value_json AS INTEGER), NEW.routing_table_id + 1) AS TEXT),
        updated_at=excluded.updated_at;
    INSERT INTO settings(key, value_json, updated_at)
    VALUES ('next_uplink_fwmark', CAST(NEW.fwmark + 1 AS TEXT), NEW.updated_at)
    ON CONFLICT(key) DO UPDATE SET
        value_json=CAST(MAX(CAST(settings.value_json AS INTEGER), NEW.fwmark + 1) AS TEXT),
        updated_at=excluded.updated_at;
END;

CREATE TRIGGER modems_generic_update
AFTER UPDATE ON modems
BEGIN
    UPDATE network_interfaces
    SET stable_identity_kind='HILINK_' || NEW.identity_kind,
        stable_identity_hash=NEW.identity_hash,
        current_ifname=NEW.interface_name,
        carrier_state=CASE WHEN NEW.state='MODEM_READY' THEN 'UP'
                           WHEN NEW.state='MODEM_CONFIGURED_OFFLINE' THEN 'ABSENT'
                           ELSE carrier_state END,
        observed_at=NEW.last_seen_at,
        updated_at=NEW.updated_at
    WHERE id='netif:legacy:' || NEW.id;

    UPDATE uplinks
    SET display_number=NEW.display_number, name=NEW.name, enabled=NEW.enabled,
        priority=NEW.priority, ipv4_cidr=NEW.management_cidr, gateway=NEW.gateway,
        dns_json=COALESCE(NEW.dns_json, '[]'), mtu=NEW.mtu,
        routing_table_id=NEW.routing_table_id, fwmark=NEW.fwmark,
        route_generation=NEW.route_generation,
        state=CASE WHEN NEW.state LIKE 'MODEM_%' THEN 'UPLINK_' || substr(NEW.state, 7) ELSE NEW.state END,
        last_seen_at=NEW.last_seen_at, stable_since=NEW.stable_since,
        updated_at=NEW.updated_at
    WHERE id=NEW.id;

    UPDATE hilink_modems
    SET operator_label=NEW.operator_label, observed_operator=NEW.observed_operator,
        identity_kind=NEW.identity_kind, identity_hash=NEW.identity_hash,
        masked_serial=NEW.masked_serial, modem_state=NEW.state,
        telemetry_state=NEW.telemetry_state,
        management_reachability_state=NEW.management_reachability_state,
        api_secret_ref=NEW.api_secret_ref, updated_at=NEW.updated_at
    WHERE uplink_id=NEW.id;
END;

CREATE TRIGGER modems_generic_delete
BEFORE DELETE ON modems
BEGIN
    DELETE FROM uplinks WHERE id=OLD.id;
    DELETE FROM network_interfaces WHERE id='netif:legacy:' || OLD.id;
END;

CREATE TRIGGER subscription_modem_paths_generic_insert
AFTER INSERT ON subscription_modem_paths
BEGIN
    INSERT INTO subscription_uplink_paths (
        id, uplink_id, subscription_id, state, transport_state, selected_node_id,
        candidate_nodes, qualified_nodes, required_targets_passed, required_targets_total,
        optional_targets_passed, optional_targets_total, quality_class, functional_score,
        latency_ms, policy_generation, route_generation, last_checked_at, expires_at,
        created_at, updated_at
    ) VALUES (
        NEW.id, NEW.modem_id, NEW.subscription_id,
        CASE WHEN NEW.state='MODEM_OFFLINE' THEN 'UPLINK_OFFLINE'
             WHEN NEW.state='MODEM_DISABLED' THEN 'UPLINK_DISABLED' ELSE NEW.state END,
        NEW.transport_state, NEW.selected_node_id, NEW.candidate_nodes, NEW.qualified_nodes,
        NEW.required_targets_passed, NEW.required_targets_total,
        NEW.optional_targets_passed, NEW.optional_targets_total,
        NEW.quality_class, NEW.functional_score, NEW.latency_ms,
        NEW.policy_generation, NEW.route_generation, NEW.last_checked_at,
        NEW.expires_at, NEW.created_at, NEW.updated_at
    );
END;

CREATE TRIGGER subscription_modem_paths_generic_update
AFTER UPDATE ON subscription_modem_paths
BEGIN
    UPDATE subscription_uplink_paths
    SET uplink_id=NEW.modem_id, subscription_id=NEW.subscription_id,
        state=CASE WHEN NEW.state='MODEM_OFFLINE' THEN 'UPLINK_OFFLINE'
                   WHEN NEW.state='MODEM_DISABLED' THEN 'UPLINK_DISABLED' ELSE NEW.state END,
        transport_state=NEW.transport_state, selected_node_id=NEW.selected_node_id,
        candidate_nodes=NEW.candidate_nodes, qualified_nodes=NEW.qualified_nodes,
        required_targets_passed=NEW.required_targets_passed,
        required_targets_total=NEW.required_targets_total,
        optional_targets_passed=NEW.optional_targets_passed,
        optional_targets_total=NEW.optional_targets_total,
        quality_class=NEW.quality_class, functional_score=NEW.functional_score,
        latency_ms=NEW.latency_ms, policy_generation=NEW.policy_generation,
        route_generation=NEW.route_generation, last_checked_at=NEW.last_checked_at,
        expires_at=NEW.expires_at, updated_at=NEW.updated_at
    WHERE id=OLD.id;
END;

CREATE TRIGGER subscription_modem_paths_generic_delete
AFTER DELETE ON subscription_modem_paths
BEGIN
    DELETE FROM subscription_uplink_paths WHERE id=OLD.id;
END;

CREATE TRIGGER path_nodes_generic_insert
AFTER INSERT ON path_nodes
BEGIN
    INSERT INTO uplink_path_nodes (
        path_id, node_id, qualification_state, qualification_generation,
        route_generation, qualification_expires_at, latency_ms,
        last_success_at, last_failure_at, failure_code
    ) VALUES (
        NEW.path_id, NEW.node_id, NEW.qualification_state, NEW.qualification_generation,
        NEW.route_generation, NEW.qualification_expires_at, NEW.latency_ms,
        NEW.last_success_at, NEW.last_failure_at, NEW.failure_code
    );
END;

CREATE TRIGGER path_nodes_generic_update
AFTER UPDATE ON path_nodes
BEGIN
    UPDATE uplink_path_nodes
    SET qualification_state=NEW.qualification_state,
        qualification_generation=NEW.qualification_generation,
        route_generation=NEW.route_generation,
        qualification_expires_at=NEW.qualification_expires_at,
        latency_ms=NEW.latency_ms, last_success_at=NEW.last_success_at,
        last_failure_at=NEW.last_failure_at, failure_code=NEW.failure_code
    WHERE path_id=OLD.path_id AND node_id=OLD.node_id;
END;

CREATE TRIGGER path_nodes_generic_delete
AFTER DELETE ON path_nodes
BEGIN
    DELETE FROM uplink_path_nodes WHERE path_id=OLD.path_id AND node_id=OLD.node_id;
END;

CREATE TRIGGER path_node_target_results_generic_insert
AFTER INSERT ON path_node_target_results
BEGIN
    INSERT INTO uplink_path_node_target_results (
        path_id, node_id, target_id, state, latency_ms, http_status, error_code,
        checked_at, expires_at, policy_generation, route_generation
    ) VALUES (
        NEW.path_id, NEW.node_id, NEW.target_id, NEW.state, NEW.latency_ms,
        NEW.http_status, NEW.error_code, NEW.checked_at, NEW.expires_at,
        NEW.policy_generation, NEW.route_generation
    );
END;

CREATE TRIGGER path_node_target_results_generic_update
AFTER UPDATE ON path_node_target_results
BEGIN
    UPDATE uplink_path_node_target_results
    SET state=NEW.state, latency_ms=NEW.latency_ms, http_status=NEW.http_status,
        error_code=NEW.error_code, checked_at=NEW.checked_at,
        expires_at=NEW.expires_at, policy_generation=NEW.policy_generation,
        route_generation=NEW.route_generation
    WHERE path_id=OLD.path_id AND node_id=OLD.node_id AND target_id=OLD.target_id;
END;

CREATE TRIGGER path_node_target_results_generic_delete
AFTER DELETE ON path_node_target_results
BEGIN
    DELETE FROM uplink_path_node_target_results
    WHERE path_id=OLD.path_id AND node_id=OLD.node_id AND target_id=OLD.target_id;
END;

CREATE TRIGGER direct_modem_paths_generic_insert
AFTER INSERT ON direct_modem_paths
BEGIN
    INSERT INTO direct_uplink_paths (
        id, uplink_id, state, transport_state, quality_class, functional_score,
        required_targets_passed, required_targets_total, optional_targets_passed,
        optional_targets_total, latency_ms, policy_generation, route_generation,
        last_checked_at, expires_at, failure_code, created_at, updated_at
    ) VALUES (
        NEW.id, NEW.modem_id, NEW.state, NEW.transport_state, NEW.quality_class,
        NEW.functional_score, NEW.required_targets_passed, NEW.required_targets_total,
        NEW.optional_targets_passed, NEW.optional_targets_total, NEW.latency_ms,
        NEW.policy_generation, NEW.route_generation, NEW.last_checked_at,
        NEW.expires_at, NEW.failure_code, NEW.created_at, NEW.updated_at
    );
END;

CREATE TRIGGER direct_modem_paths_generic_update
AFTER UPDATE ON direct_modem_paths
BEGIN
    UPDATE direct_uplink_paths
    SET uplink_id=NEW.modem_id, state=NEW.state, transport_state=NEW.transport_state,
        quality_class=NEW.quality_class, functional_score=NEW.functional_score,
        required_targets_passed=NEW.required_targets_passed,
        required_targets_total=NEW.required_targets_total,
        optional_targets_passed=NEW.optional_targets_passed,
        optional_targets_total=NEW.optional_targets_total,
        latency_ms=NEW.latency_ms, policy_generation=NEW.policy_generation,
        route_generation=NEW.route_generation, last_checked_at=NEW.last_checked_at,
        expires_at=NEW.expires_at, failure_code=NEW.failure_code,
        updated_at=NEW.updated_at
    WHERE id=OLD.id;
END;

CREATE TRIGGER direct_modem_paths_generic_delete
AFTER DELETE ON direct_modem_paths
BEGIN
    DELETE FROM direct_uplink_paths WHERE id=OLD.id;
END;

CREATE TRIGGER direct_path_target_results_generic_insert
AFTER INSERT ON direct_path_target_results
BEGIN
    INSERT INTO direct_uplink_path_target_results (
        path_id, target_id, target_class, state, latency_ms, http_status,
        error_code, checked_at, expires_at, policy_generation, route_generation
    ) VALUES (
        NEW.path_id, NEW.target_id,
        (SELECT target_class FROM bypass_probe_targets WHERE id=NEW.target_id),
        NEW.state, NEW.latency_ms, NEW.http_status, NEW.error_code,
        NEW.checked_at, NEW.expires_at, NEW.policy_generation, NEW.route_generation
    );
END;

CREATE TRIGGER direct_path_target_results_generic_update
AFTER UPDATE ON direct_path_target_results
BEGIN
    UPDATE direct_uplink_path_target_results
    SET target_class=(SELECT target_class FROM bypass_probe_targets WHERE id=NEW.target_id),
        state=NEW.state, latency_ms=NEW.latency_ms, http_status=NEW.http_status,
        error_code=NEW.error_code, checked_at=NEW.checked_at,
        expires_at=NEW.expires_at, policy_generation=NEW.policy_generation,
        route_generation=NEW.route_generation
    WHERE path_id=OLD.path_id AND target_id=OLD.target_id;
END;

CREATE TRIGGER direct_path_target_results_generic_delete
AFTER DELETE ON direct_path_target_results
BEGIN
    DELETE FROM direct_uplink_path_target_results
    WHERE path_id=OLD.path_id AND target_id=OLD.target_id;
END;

CREATE TRIGGER runtime_state_generic_update
AFTER UPDATE OF active_modem_id, management_modem_id ON runtime_state
BEGIN
    UPDATE runtime_state
    SET active_uplink_id=NEW.active_modem_id,
        management_uplink_id=NEW.management_modem_id
    WHERE singleton_id=NEW.singleton_id;
END;

CREATE TRIGGER bypass_targets_generic_class_update
AFTER UPDATE OF required ON bypass_probe_targets
WHEN NEW.target_class IN ('GLOBAL_REQUIRED', 'GLOBAL_OPTIONAL')
BEGIN
    UPDATE bypass_probe_targets
    SET target_class=CASE WHEN NEW.required=1 THEN 'GLOBAL_REQUIRED' ELSE 'GLOBAL_OPTIONAL' END
    WHERE id=NEW.id;
END;
