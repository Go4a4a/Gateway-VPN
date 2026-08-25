package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrRateLimited        = errors.New("login rate limited")
	ErrInvalidSession     = errors.New("invalid or expired session")
	ErrInvalidCSRF        = errors.New("invalid CSRF token")
)

type Service struct {
	Database        *sql.DB
	Parameters      Argon2Parameters
	SessionLifetime time.Duration
	Now             func() time.Time
}

type Session struct {
	ID                 string
	Token              string
	CSRFToken          string
	UserID             string
	Username           string
	MustChangePassword bool
	ExpiresAt          time.Time
}

type Principal struct {
	UserID             string
	Username           string
	MustChangePassword bool
	ExpiresAt          time.Time
	CSRFHash           string
	SessionHash        string
}

func (service Service) HasUsers(ctx context.Context) (bool, error) {
	if service.Database == nil {
		return false, errors.New("auth database is required")
	}
	var count int
	if err := service.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return false, fmt.Errorf("count auth users: %w", err)
	}
	return count > 0, nil
}

func (service Service) CreateBootstrapAdmin(ctx context.Context, password string) (bool, error) {
	if service.Database == nil {
		return false, errors.New("auth database is required")
	}
	parameters := service.parameters()
	hash, err := HashPassword(password, parameters)
	if err != nil {
		return false, err
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin bootstrap admin create: %w", err)
	}
	defer transaction.Rollback()
	var count int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return false, fmt.Errorf("count auth users: %w", err)
	}
	if count != 0 {
		return false, nil
	}
	now := service.now().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO users(id, username, password_hash, enabled, must_change_password, created_at, updated_at)
VALUES ('admin', 'admin', ?, 1, 1, ?, ?)`, hash, now, now); err != nil {
		return false, fmt.Errorf("insert bootstrap admin: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, service.now(), "AUTH_BOOTSTRAP_ADMIN_CREATED", map[string]any{"user_id": "admin", "username": "admin"}); err != nil {
		return false, err
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit bootstrap admin: %w", err)
	}
	return true, nil
}

func (service Service) Login(ctx context.Context, username, password, clientKey string) (Session, error) {
	username = strings.TrimSpace(username)
	if service.Database == nil || username == "" || len(username) > 128 || password == "" || len(password) > 1024 {
		return Session{}, ErrInvalidCredentials
	}
	attemptKey := digestHex(strings.ToLower(username) + "\x00" + clientKey)
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin login: %w", err)
	}
	defer transaction.Rollback()
	now := service.now()
	if blocked, err := loginBlocked(ctx, transaction, attemptKey, now); err != nil {
		return Session{}, err
	} else if blocked {
		if err := appendAuthEvent(ctx, transaction, now, "AUTH_LOGIN_RATE_LIMITED", map[string]any{"username_sha256": digestHex(strings.ToLower(username))}); err != nil {
			return Session{}, err
		}
		if err := transaction.Commit(); err != nil {
			return Session{}, fmt.Errorf("commit rate-limited login audit: %w", err)
		}
		return Session{}, ErrRateLimited
	}
	var userID, canonicalUsername, storedHash string
	var enabled, mustChange int
	err = transaction.QueryRowContext(ctx, "SELECT id, username, password_hash, enabled, must_change_password FROM users WHERE username=? COLLATE NOCASE", username).Scan(&userID, &canonicalUsername, &storedHash, &enabled, &mustChange)
	userExists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Session{}, fmt.Errorf("read login user: %w", err)
	}
	if !userExists {
		storedHash, err = HashPassword("invalid-password-placeholder", service.parameters())
		if err != nil {
			return Session{}, err
		}
	}
	verified, verifyErr := VerifyPassword(password, storedHash)
	if verifyErr != nil {
		return Session{}, fmt.Errorf("verify login password: %w", verifyErr)
	}
	if !userExists || enabled == 0 || !verified {
		if err := recordLoginFailure(ctx, transaction, attemptKey, now); err != nil {
			return Session{}, err
		}
		if err := appendAuthEvent(ctx, transaction, now, "AUTH_LOGIN_FAILED", map[string]any{"username_sha256": digestHex(strings.ToLower(username))}); err != nil {
			return Session{}, err
		}
		if err := transaction.Commit(); err != nil {
			return Session{}, fmt.Errorf("commit login failure: %w", err)
		}
		return Session{}, ErrInvalidCredentials
	}
	token, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	expires := now.Add(service.sessionLifetime())
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sessions(id_hash, user_id, csrf_hash, created_at, expires_at, last_seen_at, client_key_hash)
VALUES (?, ?, ?, ?, ?, ?, ?)`, digestHex(token), userID, digestHex(csrf), now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), digestHex(clientKey)); err != nil {
		return Session{}, fmt.Errorf("insert login session: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM login_attempts WHERE key_hash=?", attemptKey); err != nil {
		return Session{}, fmt.Errorf("clear login failures: %w", err)
	}
	if err := appendAuthEvent(ctx, transaction, now, "AUTH_LOGIN_SUCCEEDED", map[string]any{"user_id": userID, "username": canonicalUsername, "must_change_password": mustChange != 0}); err != nil {
		return Session{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit login: %w", err)
	}
	return Session{ID: digestHex(token), Token: token, CSRFToken: csrf, UserID: userID, Username: canonicalUsername, MustChangePassword: mustChange != 0, ExpiresAt: expires}, nil
}

func (service Service) Authenticate(ctx context.Context, token string) (Principal, error) {
	if token == "" || service.Database == nil {
		return Principal{}, ErrInvalidSession
	}
	var principal Principal
	var expiresText string
	var mustChange int
	err := service.Database.QueryRowContext(ctx, `
SELECT u.id, u.username, u.must_change_password, s.expires_at, s.csrf_hash, s.id_hash
FROM sessions AS s
JOIN users AS u ON u.id=s.user_id
WHERE s.id_hash=? AND s.revoked_at IS NULL AND u.enabled=1`, digestHex(token)).Scan(&principal.UserID, &principal.Username, &mustChange, &expiresText, &principal.CSRFHash, &principal.SessionHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrInvalidSession
	}
	if err != nil {
		return Principal{}, fmt.Errorf("read auth session: %w", err)
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresText)
	if err != nil || !expires.After(service.now()) {
		return Principal{}, ErrInvalidSession
	}
	principal.ExpiresAt = expires
	principal.MustChangePassword = mustChange != 0
	_, _ = service.Database.ExecContext(ctx, "UPDATE sessions SET last_seen_at=? WHERE id_hash=?", service.now().Format(time.RFC3339Nano), principal.SessionHash)
	return principal, nil
}

func (service Service) ValidateCSRF(principal Principal, token string) error {
	actual := digestHex(token)
	if token == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(principal.CSRFHash)) != 1 {
		return ErrInvalidCSRF
	}
	return nil
}

func (service Service) RotateCSRF(ctx context.Context, principal Principal) (string, error) {
	if principal.SessionHash == "" {
		return "", ErrInvalidSession
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	result, err := service.Database.ExecContext(ctx, "UPDATE sessions SET csrf_hash=?, last_seen_at=? WHERE id_hash=? AND revoked_at IS NULL", digestHex(token), service.now().Format(time.RFC3339Nano), principal.SessionHash)
	if err != nil {
		return "", fmt.Errorf("rotate session CSRF token: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return "", ErrInvalidSession
	}
	return token, nil
}

func (service Service) Revoke(ctx context.Context, token string) error {
	if service.Database == nil || token == "" {
		return store.ErrNotFound
	}
	transaction, err := service.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin session revoke: %w", err)
	}
	defer transaction.Rollback()
	var userID, username string
	err = transaction.QueryRowContext(ctx, `
SELECT u.id, u.username
FROM sessions AS s JOIN users AS u ON u.id=s.user_id
WHERE s.id_hash=? AND s.revoked_at IS NULL`, digestHex(token)).Scan(&userID, &username)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read session for revoke: %w", err)
	}
	now := service.now()
	result, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE id_hash=? AND revoked_at IS NULL", now.Format(time.RFC3339Nano), digestHex(token))
	if err != nil {
		return fmt.Errorf("revoke auth session: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked session count: %w", err)
	}
	if count != 1 {
		return store.ErrNotFound
	}
	if err := appendAuthEvent(ctx, transaction, now, "AUTH_LOGOUT", map[string]any{"user_id": userID, "username": username}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit session revoke: %w", err)
	}
	return nil
}

func GenerateBootstrapPassword() (string, error) {
	return randomToken(18)
}

func (service Service) parameters() Argon2Parameters {
	if service.Parameters.MemoryKiB == 0 {
		return DefaultArgon2Parameters()
	}
	return service.Parameters
}

func (service Service) sessionLifetime() time.Duration {
	if service.SessionLifetime <= 0 {
		return 12 * time.Hour
	}
	return service.SessionLifetime
}

func (service Service) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func loginBlocked(ctx context.Context, transaction *sql.Tx, key string, now time.Time) (bool, error) {
	var blocked sql.NullString
	err := transaction.QueryRowContext(ctx, "SELECT blocked_until FROM login_attempts WHERE key_hash=?", key).Scan(&blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read login rate limit: %w", err)
	}
	if !blocked.Valid {
		return false, nil
	}
	until, err := time.Parse(time.RFC3339Nano, blocked.String)
	return err == nil && until.After(now), nil
}

func recordLoginFailure(ctx context.Context, transaction *sql.Tx, key string, now time.Time) error {
	var failures int
	var first string
	err := transaction.QueryRowContext(ctx, "SELECT failures, first_failure_at FROM login_attempts WHERE key_hash=?", key).Scan(&failures, &first)
	if errors.Is(err, sql.ErrNoRows) {
		failures, first = 0, now.Format(time.RFC3339Nano)
	} else if err != nil {
		return fmt.Errorf("read login failure count: %w", err)
	}
	failures++
	var blocked any
	if failures >= 3 {
		delay := time.Second << min(failures-3, 8)
		blocked = now.Add(delay).Format(time.RFC3339Nano)
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO login_attempts(key_hash, failures, first_failure_at, last_failure_at, blocked_until)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key_hash) DO UPDATE SET failures=excluded.failures,
    last_failure_at=excluded.last_failure_at, blocked_until=excluded.blocked_until`, key, failures, first, now.Format(time.RFC3339Nano), blocked)
	if err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

func randomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func digestHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func appendAuthEvent(ctx context.Context, transaction *sql.Tx, now time.Time, eventType string, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode auth audit event: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'INFO', ?, ?)`, now.UTC().Format(time.RFC3339Nano), eventType, string(payload)); err != nil {
		return fmt.Errorf("record auth audit event: %w", err)
	}
	return nil
}
