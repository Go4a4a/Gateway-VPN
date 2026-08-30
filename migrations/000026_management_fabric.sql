-- Durable, mutation-free Management Fabric model.  Private key material and
-- raw pairing tokens are deliberately excluded from SQLite; only fixed secret
-- references and token digests may be stored here.

CREATE TABLE management_sites (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    is_local INTEGER NOT NULL DEFAULT 0 CHECK(is_local IN (0, 1)),
    identity_state TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK(identity_state IN ('ACTIVE', 'QUARANTINED', 'REVOKED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX management_sites_one_local
ON management_sites(is_local) WHERE is_local=1;

-- Monotonic allocation prevents a removed VPS number or WireGuard interface
-- slot from silently acquiring a different identity after restore/reboot.
CREATE TABLE management_fabric_counters (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    next_vps_number INTEGER NOT NULL CHECK(next_vps_number > 0),
    next_link_slot INTEGER NOT NULL CHECK(next_link_slot BETWEEN 1 AND 4096)
);

INSERT INTO management_fabric_counters(singleton_id, next_vps_number, next_link_slot)
VALUES (1, 1, 1);

CREATE TABLE vps_nodes (
    id TEXT PRIMARY KEY,
    display_number INTEGER NOT NULL UNIQUE CHECK(display_number > 0),
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    priority INTEGER NOT NULL CHECK(priority > 0),
    verified_fingerprint TEXT NOT NULL UNIQUE
        CHECK(length(verified_fingerprint)=64
          AND verified_fingerprint=lower(verified_fingerprint)
          AND verified_fingerprint NOT GLOB '*[^0-9a-f]*'),
    public_key TEXT NOT NULL UNIQUE,
    admin_address_pool TEXT NOT NULL CHECK(admin_address_pool!='0.0.0.0/0'),
    resource_alias_pool TEXT NOT NULL CHECK(resource_alias_pool!='0.0.0.0/0'),
    state TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK(state IN ('CONFIGURED', 'PAIRING', 'REACHABLE', 'DEGRADED', 'OFFLINE', 'REVOKED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX vps_nodes_enabled_priority
ON vps_nodes(priority) WHERE enabled=1;

CREATE TABLE management_links (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    vps_id TEXT NOT NULL,
    slot INTEGER NOT NULL UNIQUE CHECK(slot >= 0 AND slot <= 4095),
    interface_name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    management_subnet TEXT NOT NULL UNIQUE CHECK(management_subnet!='0.0.0.0/0'),
    local_address TEXT NOT NULL UNIQUE,
    remote_address TEXT NOT NULL UNIQUE,
    local_private_key_secret_ref TEXT NOT NULL
        CHECK(local_private_key_secret_ref LIKE '/var/lib/gateway-vpn/secrets/%.key'
          AND instr(local_private_key_secret_ref, '..')=0),
    local_public_key TEXT NOT NULL UNIQUE,
    remote_public_key TEXT NOT NULL,
    uplink_policy TEXT NOT NULL DEFAULT 'AUTO'
        CHECK(uplink_policy IN ('AUTO', 'PINNED_WITH_FALLBACK', 'PINNED_ONLY')),
    pinned_uplink_id TEXT,
    selected_uplink_id TEXT,
    persistent_keepalive INTEGER NOT NULL DEFAULT 25
        CHECK(persistent_keepalive BETWEEN 10 AND 60),
    desired_route_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_route_generation > 0),
    applied_route_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_route_generation >= 0),
    desired_acl_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_acl_generation > 0),
    applied_acl_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_acl_generation >= 0),
    state TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK(state IN (
            'DISABLED', 'CONFIGURED', 'CONNECTING', 'REACHABLE', 'DEGRADED',
            'ENDPOINT_UNREACHABLE', 'AUTH_FAILED', 'ROUTE_CONFLICT', 'STALE', 'REVOKED'
        )),
    last_error_code TEXT NOT NULL DEFAULT '',
    last_handshake_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(site_id, vps_id),
    FOREIGN KEY(site_id) REFERENCES management_sites(id) ON DELETE RESTRICT,
    FOREIGN KEY(vps_id) REFERENCES vps_nodes(id) ON DELETE RESTRICT,
    FOREIGN KEY(pinned_uplink_id) REFERENCES uplinks(id) ON DELETE RESTRICT,
    FOREIGN KEY(selected_uplink_id) REFERENCES uplinks(id) ON DELETE SET NULL,
    CHECK(
        (uplink_policy='AUTO' AND pinned_uplink_id IS NULL)
        OR
        (uplink_policy IN ('PINNED_WITH_FALLBACK', 'PINNED_ONLY') AND pinned_uplink_id IS NOT NULL)
    )
);

CREATE INDEX management_links_vps_state
ON management_links(vps_id, enabled, state, slot);

CREATE TABLE management_link_endpoints (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK(priority > 0),
    endpoint_host TEXT NOT NULL,
    endpoint_port INTEGER NOT NULL CHECK(endpoint_port BETWEEN 1 AND 65535),
    resolved_address TEXT,
    resolved_expires_at TEXT,
    state TEXT NOT NULL DEFAULT 'UNRESOLVED'
        CHECK(state IN ('UNRESOLVED', 'RESOLVED', 'FAILED', 'EXPIRED')),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(link_id, priority),
    UNIQUE(link_id, endpoint_host, endpoint_port),
    FOREIGN KEY(link_id) REFERENCES management_links(id) ON DELETE CASCADE
);

CREATE TABLE management_pairing_invitations (
    id TEXT PRIMARY KEY,
    vps_id TEXT NOT NULL,
    token_sha256 TEXT NOT NULL UNIQUE
        CHECK(length(token_sha256)=64
          AND token_sha256=lower(token_sha256)
          AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    expected_fingerprint TEXT NOT NULL,
    expected_public_key TEXT NOT NULL,
    endpoint_host TEXT NOT NULL,
    endpoint_port INTEGER NOT NULL CHECK(endpoint_port BETWEEN 1 AND 65535),
    assigned_subnet TEXT NOT NULL CHECK(assigned_subnet!='0.0.0.0/0'),
    assigned_local_address TEXT NOT NULL,
    assigned_remote_address TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'IMPORTED'
        CHECK(state IN ('IMPORTED', 'CONFIRMED', 'CONSUMED', 'EXPIRED', 'REJECTED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(vps_id) REFERENCES vps_nodes(id) ON DELETE CASCADE,
    CHECK((state='CONSUMED' AND consumed_at IS NOT NULL) OR (state!='CONSUMED' AND consumed_at IS NULL))
);

CREATE UNIQUE INDEX management_pairing_one_open_per_vps
ON management_pairing_invitations(vps_id)
WHERE state IN ('IMPORTED', 'CONFIRMED');

CREATE TABLE management_link_key_rotations (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    new_local_private_key_secret_ref TEXT NOT NULL
        CHECK(new_local_private_key_secret_ref LIKE '/var/lib/gateway-vpn/secrets/%.key'
          AND instr(new_local_private_key_secret_ref, '..')=0),
    new_local_public_key TEXT NOT NULL,
    new_remote_public_key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'PREPARED'
        CHECK(state IN ('PREPARED', 'WAITING_HANDSHAKE', 'VERIFIED', 'COMMITTED', 'ROLLED_BACK')),
    verified_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(link_id) REFERENCES management_links(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX management_link_one_active_rotation
ON management_link_key_rotations(link_id)
WHERE state IN ('PREPARED', 'WAITING_HANDSHAKE', 'VERIFIED');

CREATE TABLE management_admins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    identity_kind TEXT NOT NULL CHECK(identity_kind IN ('ADMIN', 'GROUP')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    state TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK(state IN ('ACTIVE', 'REVOKED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE management_admin_vps_peers (
    id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL,
    vps_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key_secret_ref TEXT
        CHECK(private_key_secret_ref IS NULL
          OR (private_key_secret_ref LIKE '/var/lib/gateway-vpn/secrets/%.key'
              AND instr(private_key_secret_ref, '..')=0)),
    assigned_address TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK(state IN ('CONFIGURED', 'ACTIVE', 'REVOKED')),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(admin_id, vps_id),
    UNIQUE(vps_id, public_key),
    UNIQUE(vps_id, assigned_address),
    FOREIGN KEY(admin_id) REFERENCES management_admins(id) ON DELETE CASCADE,
    FOREIGN KEY(vps_id) REFERENCES vps_nodes(id) ON DELETE CASCADE
);

CREATE TABLE management_resources (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    name TEXT NOT NULL,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN (
        'GATEWAY_SERVICE', 'KEENETIC_SERVICE', 'LOCAL_HOST', 'LOCAL_SUBNET', 'CUSTOM_SERVICE'
    )),
    access_profile TEXT NOT NULL CHECK(access_profile IN (
        'GATEWAY_ONLY', 'KEENETIC_WAN', 'VIA_KEENETIC_WAN_ROUTED',
        'VIA_WG_ROUTER', 'VIA_DEDICATED_LAN'
    )),
    local_destination TEXT NOT NULL CHECK(local_destination NOT IN ('0.0.0.0', '0.0.0.0/0')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    advanced_scope_acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(advanced_scope_acknowledged IN (0, 1)),
    desired_route_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_route_generation > 0),
    applied_route_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_route_generation >= 0),
    health_state TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(health_state IN ('UNKNOWN', 'WAITING_EXTERNAL_CONFIGURATION', 'HEALTHY', 'DEGRADED', 'FAILED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(site_id) REFERENCES management_sites(id) ON DELETE RESTRICT,
    CHECK(resource_kind!='LOCAL_SUBNET' OR advanced_scope_acknowledged=1)
);

CREATE TABLE management_resource_ports (
    resource_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP', 'ICMP')),
    port_start INTEGER NOT NULL DEFAULT 0 CHECK(port_start BETWEEN 0 AND 65535),
    port_end INTEGER NOT NULL DEFAULT 0 CHECK(port_end BETWEEN 0 AND 65535),
    PRIMARY KEY(resource_id, protocol, port_start, port_end),
    FOREIGN KEY(resource_id) REFERENCES management_resources(id) ON DELETE CASCADE,
    CHECK(port_end >= port_start),
    CHECK((protocol='ICMP' AND port_start=0 AND port_end=0) OR (protocol!='ICMP' AND port_start > 0))
);

CREATE TABLE management_resource_publications (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    link_id TEXT NOT NULL,
    published_alias TEXT NOT NULL CHECK(published_alias!='0.0.0.0/0'),
    desired_route_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_route_generation > 0),
    applied_route_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_route_generation >= 0),
    desired_acl_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_acl_generation > 0),
    applied_acl_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_acl_generation >= 0),
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(state IN ('PENDING', 'APPLIED', 'PARTIAL', 'PENDING_RETRY', 'ROLLED_BACK', 'DISABLED', 'CONFLICT')),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(resource_id, link_id),
    UNIQUE(link_id, published_alias),
    FOREIGN KEY(resource_id) REFERENCES management_resources(id) ON DELETE CASCADE,
    FOREIGN KEY(link_id) REFERENCES management_links(id) ON DELETE CASCADE
);

CREATE TABLE management_resource_acl (
    id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP', 'ICMP')),
    port_start INTEGER NOT NULL DEFAULT 0 CHECK(port_start BETWEEN 0 AND 65535),
    port_end INTEGER NOT NULL DEFAULT 0 CHECK(port_end BETWEEN 0 AND 65535),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    generation INTEGER NOT NULL CHECK(generation > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(admin_id, resource_id, protocol, port_start, port_end),
    FOREIGN KEY(admin_id) REFERENCES management_admins(id) ON DELETE CASCADE,
    FOREIGN KEY(resource_id) REFERENCES management_resources(id) ON DELETE CASCADE,
    CHECK(port_end >= port_start),
    CHECK((protocol='ICMP' AND port_start=0 AND port_end=0) OR (protocol!='ICMP' AND port_start > 0))
);

CREATE TABLE management_fabric_generations (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    desired_generation INTEGER NOT NULL CHECK(desired_generation > 0),
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(state IN ('PENDING', 'APPLIED', 'PARTIAL', 'PENDING_RETRY', 'ROLLED_BACK')),
    updated_at TEXT NOT NULL
);

INSERT INTO management_fabric_generations(singleton_id, desired_generation, state, updated_at)
VALUES (1, 1, 'PENDING', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE management_fabric_operations (
    id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK(operation_kind IN (
        'PAIR', 'ROTATE', 'REVOKE', 'APPLY_ROUTES', 'APPLY_ACL', 'PUBLISH_RESOURCE', 'REMOVE_RESOURCE'
    )),
    scope_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    state TEXT NOT NULL CHECK(state IN (
        'QUEUED', 'PREPARING', 'APPLYING', 'VERIFYING', 'WAITING_ACK',
        'SUCCEEDED', 'FAILED', 'ROLLED_BACK'
    )),
    stage TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX management_fabric_operations_state
ON management_fabric_operations(state, updated_at);
