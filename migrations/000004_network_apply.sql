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
    rolled_back_at TEXT
);

CREATE INDEX network_apply_unfinished
ON network_apply_transactions(state, rollback_deadline);
