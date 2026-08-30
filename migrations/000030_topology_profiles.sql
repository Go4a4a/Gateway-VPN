ALTER TABLE network_apply_transactions RENAME TO network_apply_transactions_v2;

CREATE TABLE network_apply_transactions (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    confirm_token_sha256 TEXT NOT NULL,
    interface_name TEXT NOT NULL,
    old_lan_cidr TEXT NOT NULL,
    new_lan_cidr TEXT NOT NULL,
    old_url TEXT NOT NULL,
    new_url TEXT NOT NULL,
    new_destination_ip TEXT NOT NULL,
    rollback_deadline TEXT NOT NULL,
    transaction_dir TEXT NOT NULL,
    error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    confirmed_at TEXT,
    rolled_back_at TEXT,
    manifest_schema INTEGER NOT NULL DEFAULT 1
        CHECK(manifest_schema IN (1, 2, 3)),
    operation_kind TEXT NOT NULL DEFAULT 'LAN_ADDRESS'
        CHECK(operation_kind IN ('LAN_ADDRESS', 'ETHERNET_UPLINK', 'TOPOLOGY_PROFILE')),
    candidate_json TEXT NOT NULL DEFAULT '{}'
);

INSERT INTO network_apply_transactions (
    id, state, confirm_token_sha256, interface_name, old_lan_cidr,
    new_lan_cidr, old_url, new_url, new_destination_ip,
    rollback_deadline, transaction_dir, error_code, created_at, updated_at,
    confirmed_at, rolled_back_at, manifest_schema, operation_kind, candidate_json
)
SELECT
    id, state, confirm_token_sha256, interface_name, old_lan_cidr,
    new_lan_cidr, old_url, new_url, new_destination_ip,
    rollback_deadline, transaction_dir, error_code, created_at, updated_at,
    confirmed_at, rolled_back_at, manifest_schema, operation_kind, candidate_json
FROM network_apply_transactions_v2;

DROP TABLE network_apply_transactions_v2;

CREATE INDEX network_apply_unfinished
ON network_apply_transactions(state, rollback_deadline);

CREATE INDEX network_apply_operation_history
ON network_apply_transactions(operation_kind, created_at DESC);

CREATE TABLE topology_profile_state (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
    active_profile TEXT NOT NULL CHECK(active_profile IN (
        'ETHERNET_HILINK', 'ETHERNET_ETHERNET', 'ONE_ARM_WIREGUARD', 'MIXED'
    )),
    desired_generation INTEGER NOT NULL DEFAULT 1 CHECK(desired_generation > 0),
    applied_generation INTEGER NOT NULL DEFAULT 1 CHECK(applied_generation >= 0),
    state TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(state IN (
        'ACTIVE', 'PENDING', 'APPLYING', 'ROLLING_BACK', 'FAILED'
    )),
    last_error_code TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

INSERT INTO topology_profile_state(
    singleton_id, active_profile, desired_generation, applied_generation,
    state, last_error_code, updated_at
)
SELECT
    1,
    CASE
        WHEN EXISTS(
            SELECT 1 FROM interface_role_assignments
            WHERE role='SHARED_ONE_ARM'
        ) THEN 'ONE_ARM_WIREGUARD'
        WHEN EXISTS(
            SELECT 1 FROM interface_role_assignments WHERE role='LAN_MEMBER'
        ) AND EXISTS(
            SELECT 1 FROM uplinks WHERE enabled=1 AND type='HILINK'
        ) AND EXISTS(
            SELECT 1 FROM uplinks WHERE enabled=1 AND type='ETHERNET'
        ) THEN 'MIXED'
        WHEN EXISTS(
            SELECT 1 FROM interface_role_assignments WHERE role='LAN_MEMBER'
        ) AND EXISTS(
            SELECT 1 FROM uplinks WHERE enabled=1 AND type='ETHERNET'
        ) THEN 'ETHERNET_ETHERNET'
        ELSE 'ETHERNET_HILINK'
    END,
    1, 1, 'ACTIVE', '', strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
