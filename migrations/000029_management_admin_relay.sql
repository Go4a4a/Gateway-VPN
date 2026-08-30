-- Gateway-terminated administrator contour.  The VPS relay stores and
-- forwards only encrypted UDP datagrams; inner private key material remains a
-- root-owned Gateway file and administrator private keys are never persisted
-- in SQLite.

ALTER TABLE management_admin_vps_peers
ADD COLUMN trust_mode TEXT NOT NULL DEFAULT 'ROUTED_HUB'
    CHECK(trust_mode IN ('ROUTED_HUB', 'END_TO_END_RELAY'));

CREATE TABLE management_admin_contour (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    interface_name TEXT NOT NULL DEFAULT 'wg-admin' CHECK(interface_name='wg-admin'),
    private_key_secret_ref TEXT NOT NULL
        CHECK(private_key_secret_ref LIKE '/var/lib/gateway-vpn/secrets/management/%.key'
          AND instr(private_key_secret_ref, '..')=0),
    public_key TEXT NOT NULL UNIQUE,
    subnet TEXT NOT NULL UNIQUE CHECK(subnet!='0.0.0.0/0'),
    gateway_address TEXT NOT NULL UNIQUE,
    listen_port INTEGER NOT NULL CHECK(listen_port BETWEEN 1 AND 65535),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    state TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK(state IN ('DISABLED', 'CONFIGURED', 'ACTIVE', 'DEGRADED', 'FAILED')),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK((enabled=1 AND state!='DISABLED') OR (enabled=0 AND state='DISABLED'))
);

CREATE TABLE management_admin_relays (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    public_endpoint_host TEXT NOT NULL,
    public_bind_address TEXT NOT NULL,
    public_udp_port INTEGER NOT NULL CHECK(public_udp_port BETWEEN 1 AND 65535),
    destination_port INTEGER NOT NULL CHECK(destination_port BETWEEN 1 AND 65535),
    rate_limit_per_second INTEGER NOT NULL DEFAULT 100 CHECK(rate_limit_per_second BETWEEN 1 AND 10000),
    burst_packets INTEGER NOT NULL DEFAULT 200 CHECK(burst_packets BETWEEN 1 AND 10000),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    state TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK(state IN ('DISABLED', 'CONFIGURED', 'ACTIVE', 'DEGRADED', 'CONFLICT', 'FAILED')),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(link_id) REFERENCES management_links(id) ON DELETE CASCADE,
    UNIQUE(public_bind_address, public_udp_port),
    CHECK((enabled=1 AND state!='DISABLED') OR (enabled=0 AND state='DISABLED'))
);

CREATE TABLE management_admin_tunnels (
    id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL,
    relay_id TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    assigned_address TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK(state IN ('CONFIGURED', 'ACTIVE', 'REVOKED')),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    latest_handshake_at TEXT,
    rx_bytes INTEGER NOT NULL DEFAULT 0 CHECK(rx_bytes >= 0),
    tx_bytes INTEGER NOT NULL DEFAULT 0 CHECK(tx_bytes >= 0),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(admin_id, relay_id),
    FOREIGN KEY(admin_id) REFERENCES management_admins(id) ON DELETE CASCADE,
    FOREIGN KEY(relay_id) REFERENCES management_admin_relays(id) ON DELETE CASCADE
);

CREATE INDEX management_admin_relays_state
ON management_admin_relays(enabled, state, link_id);

CREATE INDEX management_admin_tunnels_state
ON management_admin_tunnels(relay_id, state, admin_id);
