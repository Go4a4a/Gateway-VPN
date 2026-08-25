ALTER TABLE subscriptions ADD COLUMN display_number INTEGER;

UPDATE subscriptions
SET display_number = (
    SELECT COUNT(*)
    FROM subscriptions AS earlier
    WHERE earlier.rowid <= subscriptions.rowid
);

CREATE UNIQUE INDEX subscriptions_display_number
ON subscriptions(display_number);

CREATE TRIGGER subscriptions_display_number_required_insert
BEFORE INSERT ON subscriptions
WHEN NEW.display_number IS NULL
BEGIN
    SELECT RAISE(ABORT, 'subscription display_number is required');
END;

CREATE TRIGGER subscriptions_display_number_required_update
BEFORE UPDATE OF display_number ON subscriptions
WHEN NEW.display_number IS NULL
BEGIN
    SELECT RAISE(ABORT, 'subscription display_number is required');
END;

INSERT INTO settings(key, value_json, updated_at)
VALUES (
    'next_subscription_display_number',
    CAST((SELECT COALESCE(MAX(display_number), 0) + 1 FROM subscriptions) AS TEXT),
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
)
ON CONFLICT(key) DO NOTHING;
