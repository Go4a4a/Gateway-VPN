UPDATE settings
SET value_json=json_set(
        value_json,
        '$.schema_version', 2,
        '$.maximum_apply_delay_hours', 72
    )
WHERE key='software_update_policy';

CREATE TABLE software_update_scheduler_v33 (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
    phase TEXT NOT NULL CHECK(phase IN (
        'IDLE', 'DISABLED', 'CHECKING', 'CANDIDATE', 'DOWNLOADING',
        'STAGED', 'WAITING_WINDOW', 'APPLY_INTENT', 'APPLY_DISPATCHED',
        'SUCCEEDED', 'FAILED', 'SUPPRESSED', 'MANUAL_PENDING',
        'MANUAL_ATTENTION', 'OUTCOME_UNKNOWN'
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
    staged_at TEXT,
    apply_deadline_at TEXT,
    apply_intent_at TEXT,
    apply_observed_at TEXT,
    lease_owner TEXT NOT NULL DEFAULT '' CHECK(length(lease_owner) <= 64),
    lease_expires_at TEXT,
    updated_at TEXT NOT NULL,
    CHECK((lease_owner = '') = (lease_expires_at IS NULL)),
    CHECK(
        (staged_update_id = '' AND staged_version = '' AND staged_at IS NULL AND apply_deadline_at IS NULL)
        OR
        (staged_update_id <> '' AND staged_version <> '' AND staged_at IS NOT NULL AND apply_deadline_at IS NOT NULL)
    ),
    CHECK(candidate_version = '' OR candidate_reference <> '')
);

INSERT INTO software_update_scheduler_v33 (
    singleton_id, phase, policy_updated_at, channel, jitter_offset_minutes,
    next_check_at, next_apply_at, last_attempt_at, last_completed_at,
    last_result_code, last_error_code, consecutive_failures,
    candidate_version, candidate_reference, candidate_published_at,
    staged_update_id, staged_version, staged_at, apply_deadline_at,
    apply_intent_at, apply_observed_at, lease_owner, lease_expires_at, updated_at
)
SELECT
    singleton_id, phase, policy_updated_at, channel, jitter_offset_minutes,
    next_check_at, next_apply_at, last_attempt_at, last_completed_at,
    last_result_code, last_error_code, consecutive_failures,
    candidate_version, candidate_reference, candidate_published_at,
    staged_update_id, staged_version,
    CASE WHEN staged_update_id='' THEN NULL ELSE
        strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(apply_intent_at, last_completed_at, updated_at)) END,
    CASE WHEN staged_update_id='' THEN NULL ELSE
        strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(apply_intent_at, last_completed_at, updated_at), '+72 hours') END,
    apply_intent_at, apply_observed_at, lease_owner, lease_expires_at, updated_at
FROM software_update_scheduler;

DROP TABLE software_update_scheduler;
ALTER TABLE software_update_scheduler_v33 RENAME TO software_update_scheduler;
