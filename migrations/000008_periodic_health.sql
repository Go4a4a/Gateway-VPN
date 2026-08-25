CREATE TABLE path_health_runtime (
    path_id TEXT PRIMARY KEY,
    probe_class TEXT NOT NULL,
    next_probe_at TEXT NOT NULL,
    last_probe_at TEXT,
    last_result TEXT NOT NULL DEFAULT 'UNKNOWN',
    consecutive_successes INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_successes >= 0),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures >= 0),
    deferred_reason TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(path_id) REFERENCES subscription_modem_paths(id) ON DELETE CASCADE,
    CHECK(probe_class IN ('ACTIVE', 'STANDBY')),
    CHECK(last_result IN ('UNKNOWN', 'PASSED', 'FAILED', 'DEFERRED_BUDGET')),
    CHECK(NOT (consecutive_successes > 0 AND consecutive_failures > 0)),
    CHECK((last_result = 'DEFERRED_BUDGET') = (deferred_reason IS NOT NULL))
);

CREATE INDEX path_health_runtime_due
ON path_health_runtime(probe_class, next_probe_at, path_id);
