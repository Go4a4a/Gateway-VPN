CREATE TABLE software_update_scheduler (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
    phase TEXT NOT NULL CHECK(phase IN (
        'IDLE', 'DISABLED', 'CHECKING', 'CANDIDATE', 'DOWNLOADING',
        'STAGED', 'WAITING_WINDOW', 'APPLY_INTENT', 'APPLY_DISPATCHED',
        'SUCCEEDED', 'FAILED', 'SUPPRESSED', 'MANUAL_PENDING', 'OUTCOME_UNKNOWN'
    )),
    policy_updated_at TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL CHECK(channel IN ('stable', 'testing')),
    jitter_offset_minutes INTEGER NOT NULL DEFAULT 0
        CHECK(jitter_offset_minutes BETWEEN 0 AND 360),
    next_check_at TEXT,
    next_apply_at TEXT,
    last_attempt_at TEXT,
    last_completed_at TEXT,
    last_result_code TEXT NOT NULL DEFAULT '' CHECK(length(last_result_code) <= 64),
    last_error_code TEXT NOT NULL DEFAULT '' CHECK(length(last_error_code) <= 64),
    consecutive_failures INTEGER NOT NULL DEFAULT 0
        CHECK(consecutive_failures BETWEEN 0 AND 100),
    candidate_version TEXT NOT NULL DEFAULT '' CHECK(length(candidate_version) <= 128),
    candidate_reference TEXT NOT NULL DEFAULT '' CHECK(length(candidate_reference) <= 256),
    candidate_published_at TEXT,
    staged_update_id TEXT NOT NULL DEFAULT '' CHECK(length(staged_update_id) <= 128),
    staged_version TEXT NOT NULL DEFAULT '' CHECK(length(staged_version) <= 128),
    apply_intent_at TEXT,
    apply_observed_at TEXT,
    lease_owner TEXT NOT NULL DEFAULT '' CHECK(length(lease_owner) <= 64),
    lease_expires_at TEXT,
    updated_at TEXT NOT NULL,
    CHECK((lease_owner = '') = (lease_expires_at IS NULL)),
    CHECK(staged_update_id = '' OR staged_version <> ''),
    CHECK(candidate_version = '' OR candidate_reference <> '')
);

INSERT INTO software_update_scheduler(
    singleton_id, phase, channel, updated_at
) VALUES (
    1, 'IDLE', 'stable', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);
