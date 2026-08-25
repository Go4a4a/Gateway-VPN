CREATE TABLE subscription_refresh_state (
    subscription_id TEXT PRIMARY KEY,
    etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures >= 0),
    next_attempt_at TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error_code TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE INDEX subscription_refresh_due
ON subscription_refresh_state(next_attempt_at);
