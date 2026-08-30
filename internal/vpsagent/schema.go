package vpsagent

const schemaV1 = `
CREATE TABLE vps_identity(
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    vps_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    identity_fingerprint TEXT NOT NULL UNIQUE
        CHECK(length(identity_fingerprint)=64 AND identity_fingerprint=lower(identity_fingerprint)
          AND identity_fingerprint NOT GLOB '*[^0-9a-f]*'),
    public_key TEXT NOT NULL UNIQUE,
    private_key_secret_ref TEXT NOT NULL CHECK(private_key_secret_ref LIKE '/var/lib/gateway-vpn-vps/agent/secrets/%'),
    update_identity_ref TEXT NOT NULL CHECK(update_identity_ref LIKE '/var/lib/gateway-vpn-vps/agent/secrets/%'),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE vps_settings(
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    updated_at TEXT NOT NULL
);

INSERT INTO vps_settings(key,value_json,updated_at) VALUES
('watchdog','{"enabled":true,"check_interval_seconds":30,"recovery_mode":"OWNED_ONLY","host_reboot_enabled":false}',strftime('%Y-%m-%dT%H:%M:%fZ','now')),
('logging','{"level":"INFO","retention_days":14,"max_disk_bytes":268435456}',strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- Keep the proven Gateway auth table contract so the lightweight VPS Hub can
-- reuse Argon2id, bounded sessions, CSRF and reauthentication without sharing
-- either database or credentials with any Gateway.
CREATE TABLE users(
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK(must_change_password IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions(
    id_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    csrf_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT,
    client_key_hash TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX sessions_user_expiry ON sessions(user_id,expires_at);

CREATE TABLE login_attempts(
    key_hash TEXT PRIMARY KEY,
    failures INTEGER NOT NULL CHECK(failures>=0),
    first_failure_at TEXT NOT NULL,
    last_failure_at TEXT NOT NULL,
    blocked_until TEXT
);

CREATE TABLE events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    modem_id TEXT,
    subscription_id TEXT,
    path_id TEXT,
    details_json TEXT NOT NULL CHECK(json_valid(details_json))
);

CREATE INDEX events_occurred_at ON events(occurred_at DESC);

CREATE TABLE gateway_peers(
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    assigned_subnet TEXT NOT NULL UNIQUE CHECK(assigned_subnet!='0.0.0.0/0'),
    assigned_address TEXT NOT NULL UNIQUE,
    remote_address TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('PAIRING','ACTIVE','DEGRADED','OFFLINE','QUARANTINED','REVOKED')),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation>0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation>=0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE admin_peers(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    private_key_secret_ref TEXT CHECK(private_key_secret_ref IS NULL OR private_key_secret_ref LIKE '/var/lib/gateway-vpn-vps/agent/secrets/%'),
    assigned_address TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('CONFIGURED','ACTIVE','REVOKED')),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation>0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation>=0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE prefix_allocations(
    id TEXT PRIMARY KEY,
    owner_kind TEXT NOT NULL CHECK(owner_kind IN ('GATEWAY_LINK','ADMIN_PEER','RESOURCE_ALIAS','WG_ADMIN_RELAY')),
    owner_id TEXT NOT NULL,
    prefix TEXT NOT NULL UNIQUE CHECK(prefix!='0.0.0.0/0'),
    state TEXT NOT NULL CHECK(state IN ('ALLOCATED','ACTIVE','QUARANTINED','RELEASED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(owner_kind,owner_id)
);

CREATE TABLE resource_publications(
    id TEXT PRIMARY KEY,
    gateway_peer_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('GATEWAY_SERVICE','KEENETIC_SERVICE','LOCAL_HOST','LOCAL_SUBNET','CUSTOM_SERVICE')),
    local_destination TEXT NOT NULL CHECK(local_destination NOT IN ('0.0.0.0','0.0.0.0/0')),
    published_alias TEXT NOT NULL UNIQUE CHECK(published_alias!='0.0.0.0/0'),
    state TEXT NOT NULL CHECK(state IN ('PENDING','APPLIED','PENDING_RETRY','ROLLED_BACK','DISABLED')),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation>0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation>=0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(gateway_peer_id,resource_id),
    FOREIGN KEY(gateway_peer_id) REFERENCES gateway_peers(id) ON DELETE CASCADE
);

CREATE TABLE acl_grants(
    id TEXT PRIMARY KEY,
    admin_peer_id TEXT NOT NULL,
    publication_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('TCP','UDP','ICMP')),
    port_start INTEGER NOT NULL CHECK(port_start BETWEEN 0 AND 65535),
    port_end INTEGER NOT NULL CHECK(port_end BETWEEN 0 AND 65535),
    generation INTEGER NOT NULL CHECK(generation>0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(admin_peer_id,publication_id,protocol,port_start,port_end),
    FOREIGN KEY(admin_peer_id) REFERENCES admin_peers(id) ON DELETE CASCADE,
    FOREIGN KEY(publication_id) REFERENCES resource_publications(id) ON DELETE CASCADE,
    CHECK(port_end>=port_start),
    CHECK((protocol='ICMP' AND port_start=0 AND port_end=0) OR (protocol!='ICMP' AND port_start>0))
);

-- Ephemeral/security-runtime tables exist in the live DB but are emptied and
-- VACUUMed from portable backups.
CREATE TABLE pairing_invitations(
    id TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL UNIQUE CHECK(length(token_sha256)=64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK(state IN ('OPEN','CONSUMED','EXPIRED','REJECTED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE audit_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details_json TEXT NOT NULL CHECK(json_valid(details_json))
);

CREATE TABLE operations(
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    stage TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
`
