CREATE TABLE logging_runtime (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
    desired_sha256 TEXT NOT NULL DEFAULT '',
    applied_sha256 TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(state IN ('UNKNOWN', 'PENDING', 'APPLYING', 'APPLIED', 'FAILED')),
    applied_at TEXT,
    last_error_code TEXT,
    updated_at TEXT NOT NULL
);

INSERT INTO logging_runtime(singleton_id, state, updated_at)
VALUES (1, 'UNKNOWN', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
