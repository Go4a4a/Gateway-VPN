package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// AllocateCounter returns the current monotonic value and atomically persists
// the next one inside the caller's transaction.
func AllocateCounter(ctx context.Context, transaction *sql.Tx, key string, initial int64, updatedAt string) (int64, error) {
	var raw string
	err := transaction.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", key).Scan(&raw)
	value := initial
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return 0, fmt.Errorf("read counter %s: %w", key, err)
	default:
		value, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || value < initial {
			return 0, fmt.Errorf("invalid counter %s value %q", key, raw)
		}
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at`,
		key,
		strconv.FormatInt(value+1, 10),
		updatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("advance counter %s: %w", key, err)
	}
	return value, nil
}
