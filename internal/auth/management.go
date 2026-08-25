package auth

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

var (
	ErrInvalidUsername    = errors.New("invalid username")
	ErrUsernameExists     = errors.New("username already exists")
	ErrNoUserChanges      = errors.New("no user changes requested")
	ErrSelfUserMutation   = errors.New("current user cannot be disabled or deleted")
	ErrLastEnabledUser    = errors.New("last enabled user cannot be disabled")
	ErrUserMustBeDisabled = errors.New("user must be disabled before deletion")
	ErrPasswordUnchanged  = errors.New("new password must differ from current password")
	ErrCredentialsChanged = errors.New("credentials changed concurrently")
	ErrSelfPasswordReset  = errors.New("use current-password flow for own account")
	ErrInvalidSessionID   = errors.New("invalid session id")
)

// User is the secret-free local administrator read model. Full RBAC is outside
// the MVP: every enabled local user has the same administrative permissions.
type User struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	Enabled            bool      `json:"enabled"`
	MustChangePassword bool      `json:"must_change_password"`
	ActiveSessions     int       `json:"active_sessions"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type SessionInfo struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type UpdateUserInput struct {
	Username *string
	Enabled  *bool
}

func ValidateUsername(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 64 || !asciiAlphaNumeric(value[0]) {
		return "", ErrInvalidUsername
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return "", ErrInvalidUsername
		}
	}
	return value, nil
}

func (service Service) ListUsers(ctx context.Context) ([]User, error) {
	if service.Database == nil {
		return nil, errors.New("auth database is required")
	}
	rows, err := service.Database.QueryContext(ctx, `
SELECT u.id, u.username, u.enabled, u.must_change_password, u.created_at, u.updated_at,
       (SELECT COUNT(*) FROM sessions AS s
        WHERE s.user_id=u.id AND s.revoked_at IS NULL AND s.expires_at>?)
FROM users AS u
ORDER BY u.username COLLATE NOCASE, u.id`, service.now().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("list auth users: %w", err)
	}
	defer rows.Close()
	result := make([]User, 0)
	for rows.Next() {
		item, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate auth users: %w", err)
	}
	return result, nil
}

func (service Service) CreateUser(ctx context.Context, actor Principal, username, password string) (User, error) {
	if service.Database == nil || actor.UserID == "" {
		return User{}, errors.New("authenticated auth database is required")
	}
	username, err := ValidateUsername(username)
	if err != nil {
		return User{}, err
	}
	passwordHash, err := HashPassword(password, service.parameters())
	if err != nil {
		return User{}, err
	}
	randomID, err := randomToken(18)
	if err != nil {
		return User{}, err
	}
	userID := "user-" + randomID
	now := service.now()
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin auth user create: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `
INSERT INTO users(id, username, password_hash, enabled, must_change_password, created_at, updated_at)
VALUES (?, ?, ?, 1, 1, ?, ?)`, userID, username, passwordHash, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		if isUniqueConstraint(err) {
			return User{}, ErrUsernameExists
		}
		return User{}, fmt.Errorf("insert auth user: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, now, "AUTH_USER_CREATED", map[string]any{"actor_user_id": actor.UserID, "user_id": userID, "username": username}); err != nil {
		return User{}, err
	}
	if err := transaction.Commit(); err != nil {
		return User{}, fmt.Errorf("commit auth user create: %w", err)
	}
	return User{ID: userID, Username: username, Enabled: true, MustChangePassword: true, CreatedAt: now, UpdatedAt: now}, nil
}

func (service Service) UpdateUser(ctx context.Context, actor Principal, userID string, input UpdateUserInput) (User, error) {
	if service.Database == nil || actor.UserID == "" {
		return User{}, errors.New("authenticated auth database is required")
	}
	if input.Username == nil && input.Enabled == nil {
		return User{}, ErrNoUserChanges
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin auth user update: %w", err)
	}
	defer transaction.Rollback()
	current, passwordHash, err := readUserForUpdate(ctx, transaction, userID, service.now())
	if err != nil {
		return User{}, err
	}
	username := current.Username
	if input.Username != nil {
		username, err = ValidateUsername(*input.Username)
		if err != nil {
			return User{}, err
		}
	}
	enabled := current.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if !enabled && current.Enabled {
		if userID == actor.UserID {
			return User{}, ErrSelfUserMutation
		}
		var enabledUsers int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE enabled=1").Scan(&enabledUsers); err != nil {
			return User{}, fmt.Errorf("count enabled auth users: %w", err)
		}
		if enabledUsers <= 1 {
			return User{}, ErrLastEnabledUser
		}
	}
	now := service.now()
	result, err := transaction.ExecContext(ctx, "UPDATE users SET username=?, enabled=?, updated_at=? WHERE id=? AND password_hash=?", username, boolInt(enabled), now.Format(time.RFC3339Nano), userID, passwordHash)
	if err != nil {
		if isUniqueConstraint(err) {
			return User{}, ErrUsernameExists
		}
		return User{}, fmt.Errorf("update auth user: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("read auth user update count: %w", err)
	}
	if changed != 1 {
		return User{}, ErrCredentialsChanged
	}
	if current.Enabled && !enabled {
		if _, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", now.Format(time.RFC3339Nano), userID); err != nil {
			return User{}, fmt.Errorf("revoke disabled user sessions: %w", err)
		}
	}
	eventType := "AUTH_USER_UPDATED"
	if current.Enabled != enabled {
		if enabled {
			eventType = "AUTH_USER_ENABLED"
		} else {
			eventType = "AUTH_USER_DISABLED"
		}
	}
	if err := appendAuthEvent(ctx, transaction, now, eventType, map[string]any{"actor_user_id": actor.UserID, "user_id": userID, "username": username, "enabled": enabled}); err != nil {
		return User{}, err
	}
	if err := transaction.Commit(); err != nil {
		return User{}, fmt.Errorf("commit auth user update: %w", err)
	}
	current.Username = username
	current.Enabled = enabled
	current.UpdatedAt = now
	if !enabled {
		current.ActiveSessions = 0
	}
	return current, nil
}

func (service Service) DeleteUser(ctx context.Context, actor Principal, userID string) error {
	if service.Database == nil || actor.UserID == "" {
		return errors.New("authenticated auth database is required")
	}
	if userID == actor.UserID {
		return ErrSelfUserMutation
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin auth user delete: %w", err)
	}
	defer transaction.Rollback()
	current, _, err := readUserForUpdate(ctx, transaction, userID, service.now())
	if err != nil {
		return err
	}
	if current.Enabled {
		return ErrUserMustBeDisabled
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM users WHERE id=?", userID); err != nil {
		return fmt.Errorf("delete auth user: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, service.now(), "AUTH_USER_DELETED", map[string]any{"actor_user_id": actor.UserID, "user_id": userID, "username": current.Username}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit auth user delete: %w", err)
	}
	return nil
}

func (service Service) ChangePassword(ctx context.Context, principal Principal, currentPassword, newPassword string) error {
	if service.Database == nil || principal.UserID == "" || principal.SessionHash == "" {
		return ErrInvalidSession
	}
	var currentHash string
	if err := service.Database.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id=? AND enabled=1", principal.UserID).Scan(&currentHash); errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidSession
	} else if err != nil {
		return fmt.Errorf("read current password hash: %w", err)
	}
	verified, err := VerifyPassword(currentPassword, currentHash)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}
	if !verified {
		return ErrInvalidCredentials
	}
	unchanged, err := VerifyPassword(newPassword, currentHash)
	if err != nil {
		return fmt.Errorf("compare new password: %w", err)
	}
	if unchanged {
		return ErrPasswordUnchanged
	}
	newHash, err := HashPassword(newPassword, service.parameters())
	if err != nil {
		return err
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin own password change: %w", err)
	}
	defer transaction.Rollback()
	now := service.now()
	result, err := transaction.ExecContext(ctx, "UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=? AND password_hash=? AND enabled=1", newHash, now.Format(time.RFC3339Nano), principal.UserID, currentHash)
	if err != nil {
		return fmt.Errorf("change own password: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read own password change count: %w", err)
	}
	if changed != 1 {
		return ErrCredentialsChanged
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND id_hash<>? AND revoked_at IS NULL", now.Format(time.RFC3339Nano), principal.UserID, principal.SessionHash); err != nil {
		return fmt.Errorf("revoke other sessions after password change: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, now, "AUTH_PASSWORD_CHANGED", map[string]any{"user_id": principal.UserID, "other_sessions_revoked": true}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit own password change: %w", err)
	}
	return nil
}

func (service Service) ResetPassword(ctx context.Context, actor Principal, userID, newPassword string) error {
	if service.Database == nil || actor.UserID == "" {
		return errors.New("authenticated auth database is required")
	}
	if userID == actor.UserID {
		return ErrSelfPasswordReset
	}
	newHash, err := HashPassword(newPassword, service.parameters())
	if err != nil {
		return err
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin auth password reset: %w", err)
	}
	defer transaction.Rollback()
	current, _, err := readUserForUpdate(ctx, transaction, userID, service.now())
	if err != nil {
		return err
	}
	now := service.now()
	if _, err := transaction.ExecContext(ctx, "UPDATE users SET password_hash=?, must_change_password=1, updated_at=? WHERE id=?", newHash, now.Format(time.RFC3339Nano), userID); err != nil {
		return fmt.Errorf("reset auth user password: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", now.Format(time.RFC3339Nano), userID); err != nil {
		return fmt.Errorf("revoke reset user sessions: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, now, "AUTH_PASSWORD_RESET", map[string]any{"actor_user_id": actor.UserID, "user_id": userID, "username": current.Username, "must_change_password": true}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit auth password reset: %w", err)
	}
	return nil
}

func (service Service) ListSessions(ctx context.Context) ([]SessionInfo, error) {
	if service.Database == nil {
		return nil, errors.New("auth database is required")
	}
	rows, err := service.Database.QueryContext(ctx, `
SELECT s.id_hash, s.user_id, u.username, s.created_at, s.expires_at, s.last_seen_at
FROM sessions AS s JOIN users AS u ON u.id=s.user_id
WHERE s.revoked_at IS NULL AND s.expires_at>?
ORDER BY s.last_seen_at DESC, s.id_hash`, service.now().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("list auth sessions: %w", err)
	}
	defer rows.Close()
	result := make([]SessionInfo, 0)
	for rows.Next() {
		var item SessionInfo
		var createdAt, expiresAt, lastSeenAt string
		if err := rows.Scan(&item.ID, &item.UserID, &item.Username, &createdAt, &expiresAt, &lastSeenAt); err != nil {
			return nil, fmt.Errorf("scan auth session: %w", err)
		}
		item.CreatedAt, err = parseAuthTime(createdAt)
		if err != nil {
			return nil, err
		}
		item.ExpiresAt, err = parseAuthTime(expiresAt)
		if err != nil {
			return nil, err
		}
		item.LastSeenAt, err = parseAuthTime(lastSeenAt)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate auth sessions: %w", err)
	}
	return result, nil
}

func (service Service) RevokeSession(ctx context.Context, actor Principal, sessionID string) error {
	if service.Database == nil || actor.UserID == "" {
		return errors.New("authenticated auth database is required")
	}
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrative session revoke: %w", err)
	}
	defer transaction.Rollback()
	var targetUserID, targetUsername string
	err = transaction.QueryRowContext(ctx, `
SELECT s.user_id, u.username
FROM sessions AS s JOIN users AS u ON u.id=s.user_id
WHERE s.id_hash=? AND s.revoked_at IS NULL`, sessionID).Scan(&targetUserID, &targetUsername)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read administrative session revoke target: %w", err)
	}
	now := service.now()
	if _, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE id_hash=? AND revoked_at IS NULL", now.Format(time.RFC3339Nano), sessionID); err != nil {
		return fmt.Errorf("revoke administrative session: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, now, "AUTH_SESSION_REVOKED", map[string]any{"actor_user_id": actor.UserID, "target_user_id": targetUserID, "target_username": targetUsername, "current_session": sessionID == actor.SessionHash}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit administrative session revoke: %w", err)
	}
	return nil
}

func readUserForUpdate(ctx context.Context, transaction *sql.Tx, userID string, now time.Time) (User, string, error) {
	var item User
	var passwordHash, createdAt, updatedAt string
	var enabled, mustChange int
	err := transaction.QueryRowContext(ctx, `
SELECT id, username, password_hash, enabled, must_change_password, created_at, updated_at,
       (SELECT COUNT(*) FROM sessions AS s WHERE s.user_id=users.id AND s.revoked_at IS NULL AND s.expires_at>?)
FROM users WHERE id=?`, now.UTC().Format(time.RFC3339Nano), userID).Scan(&item.ID, &item.Username, &passwordHash, &enabled, &mustChange, &createdAt, &updatedAt, &item.ActiveSessions)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", store.ErrNotFound
	}
	if err != nil {
		return User{}, "", fmt.Errorf("read auth user: %w", err)
	}
	item.Enabled = enabled != 0
	item.MustChangePassword = mustChange != 0
	item.CreatedAt, err = parseAuthTime(createdAt)
	if err != nil {
		return User{}, "", err
	}
	item.UpdatedAt, err = parseAuthTime(updatedAt)
	if err != nil {
		return User{}, "", err
	}
	return item, passwordHash, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanUser(row rowScanner) (User, error) {
	var item User
	var enabled, mustChange int
	var createdAt, updatedAt string
	if err := row.Scan(&item.ID, &item.Username, &enabled, &mustChange, &createdAt, &updatedAt, &item.ActiveSessions); err != nil {
		return User{}, fmt.Errorf("scan auth user: %w", err)
	}
	item.Enabled = enabled != 0
	item.MustChangePassword = mustChange != 0
	var err error
	item.CreatedAt, err = parseAuthTime(createdAt)
	if err != nil {
		return User{}, err
	}
	item.UpdatedAt, err = parseAuthTime(updatedAt)
	if err != nil {
		return User{}, err
	}
	return item, nil
}

func parseAuthTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse auth timestamp: %w", err)
	}
	return parsed.UTC(), nil
}

func validateSessionID(value string) error {
	if len(value) != sha256HexLength {
		return ErrInvalidSessionID
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256HexLength/2 || value != strings.ToLower(value) {
		return ErrInvalidSessionID
	}
	return nil
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}

const sha256HexLength = 64
