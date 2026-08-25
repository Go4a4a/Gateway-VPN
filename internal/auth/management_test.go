package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/store"
)

func TestLocalAdministratorAndSessionManagementLifecycle(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	service := Service{
		Database: database,
		Parameters: Argon2Parameters{
			MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32,
		},
		SessionLifetime: time.Hour,
		Now:             func() time.Time { return now },
	}
	if _, err := service.CreateBootstrapAdmin(ctx, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	adminSession, err := service.Login(ctx, "ADMIN", "correct horse battery staple", "admin-client")
	if err != nil || adminSession.Username != "admin" {
		t.Fatalf("case-insensitive canonical login = %+v, %v", adminSession, err)
	}
	admin, err := service.Authenticate(ctx, adminSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateUser(ctx, admin, "operator_1", "temporary password 123")
	if err != nil || !created.Enabled || !created.MustChangePassword || created.ID == "" {
		t.Fatalf("CreateUser() = %+v, %v", created, err)
	}
	if _, err := service.CreateUser(ctx, admin, "OPERATOR_1", "another password 123"); !errors.Is(err, ErrUsernameExists) {
		t.Fatalf("case-insensitive duplicate error = %v", err)
	}
	if _, err := service.CreateUser(ctx, admin, "bad user", "another password 123"); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("invalid username error = %v", err)
	}

	operatorSession, err := service.Login(ctx, "operator_1", "temporary password 123", "operator-client-a")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := service.Authenticate(ctx, operatorSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ResetPassword(ctx, operator, operator.UserID, "self reset bypass 123"); !errors.Is(err, ErrSelfPasswordReset) {
		t.Fatalf("self ResetPassword() error = %v", err)
	}
	if err := service.ResetPassword(ctx, admin, operator.UserID, "administrator reset 123"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, operatorSession.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("reset session Authenticate() error = %v", err)
	}
	resetSession, err := service.Login(ctx, "operator_1", "administrator reset 123", "operator-client-a")
	if err != nil || !resetSession.MustChangePassword {
		t.Fatalf("reset password Login() = %+v, %v", resetSession, err)
	}
	secondSession, err := service.Login(ctx, "operator_1", "administrator reset 123", "operator-client-b")
	if err != nil {
		t.Fatal(err)
	}
	resetPrincipal, err := service.Authenticate(ctx, resetSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword(ctx, resetPrincipal, "wrong current password", "final operator password 123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current ChangePassword() error = %v", err)
	}
	if err := service.ChangePassword(ctx, resetPrincipal, "administrator reset 123", "administrator reset 123"); !errors.Is(err, ErrPasswordUnchanged) {
		t.Fatalf("unchanged ChangePassword() error = %v", err)
	}
	if err := service.ChangePassword(ctx, resetPrincipal, "administrator reset 123", "final operator password 123"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, secondSession.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("other session after password change error = %v", err)
	}
	stillCurrent, err := service.Authenticate(ctx, resetSession.Token)
	if err != nil || stillCurrent.MustChangePassword {
		t.Fatalf("current session after password change = %+v, %v", stillCurrent, err)
	}
	if _, err := service.Login(ctx, "operator_1", "administrator reset 123", "old-password-client"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password Login() error = %v", err)
	}
	if _, err := service.Login(ctx, "operator_1", "final operator password 123", "new-password-client"); err != nil {
		t.Fatal(err)
	}

	renamed := "support-admin"
	updated, err := service.UpdateUser(ctx, admin, operator.UserID, UpdateUserInput{Username: &renamed})
	if err != nil || updated.Username != renamed {
		t.Fatalf("rename UpdateUser() = %+v, %v", updated, err)
	}
	if _, err := service.UpdateUser(ctx, admin, admin.UserID, UpdateUserInput{Enabled: boolPointer(false)}); !errors.Is(err, ErrSelfUserMutation) {
		t.Fatalf("self-disable UpdateUser() error = %v", err)
	}
	updated, err = service.UpdateUser(ctx, admin, operator.UserID, UpdateUserInput{Enabled: boolPointer(false)})
	if err != nil || updated.Enabled || updated.ActiveSessions != 0 {
		t.Fatalf("disable UpdateUser() = %+v, %v", updated, err)
	}
	if err := service.DeleteUser(ctx, admin, operator.UserID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteUser(ctx, admin, operator.UserID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteUser(missing) error = %v", err)
	}
	users, err := service.ListUsers(ctx)
	if err != nil || len(users) != 1 || users[0].ID != admin.UserID {
		t.Fatalf("ListUsers() = %+v, %v", users, err)
	}
	if _, err := service.UpdateUser(ctx, Principal{UserID: "external-auditor"}, admin.UserID, UpdateUserInput{Enabled: boolPointer(false)}); !errors.Is(err, ErrLastEnabledUser) {
		t.Fatalf("last enabled UpdateUser() error = %v", err)
	}

	sessions, err := service.ListSessions(ctx)
	if err != nil || len(sessions) != 1 || sessions[0].ID != admin.SessionHash || len(sessions[0].ID) != 64 {
		t.Fatalf("ListSessions() = %+v, %v", sessions, err)
	}
	if err := service.RevokeSession(ctx, admin, "invalid"); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("RevokeSession(invalid) error = %v", err)
	}
	if err := service.RevokeSession(ctx, admin, admin.SessionHash); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, adminSession.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("revoked admin Authenticate() error = %v", err)
	}

	var leaked int
	if err := database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM events
WHERE details_json LIKE '%temporary password%'
   OR details_json LIKE '%administrator reset%'
   OR details_json LIKE '%final operator%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("password audit leaks = %d, %v", leaked, err)
	}
	var lifecycleEvents int
	if err := database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM events
WHERE type IN ('AUTH_USER_CREATED','AUTH_PASSWORD_RESET','AUTH_PASSWORD_CHANGED',
               'AUTH_USER_UPDATED','AUTH_USER_DISABLED','AUTH_USER_DELETED','AUTH_SESSION_REVOKED')`).Scan(&lifecycleEvents); err != nil || lifecycleEvents != 7 {
		t.Fatalf("management lifecycle audit count = %d, %v", lifecycleEvents, err)
	}
}

func TestActiveUserMustBeDisabledBeforeDeletion(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	service := Service{Database: database, Parameters: Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}}
	if _, err := service.CreateBootstrapAdmin(ctx, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	session, err := service.Login(ctx, "admin", "correct horse battery staple", "client")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(ctx, principal, "second-admin", "second admin password 123")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteUser(ctx, principal, user.ID); !errors.Is(err, ErrUserMustBeDisabled) {
		t.Fatalf("DeleteUser(enabled) error = %v", err)
	}
	if err := service.DeleteUser(ctx, principal, principal.UserID); !errors.Is(err, ErrSelfUserMutation) {
		t.Fatalf("DeleteUser(self) error = %v", err)
	}
}

func boolPointer(value bool) *bool {
	return &value
}

func TestValidateUsernameUsesConservativeASCIIIdentity(t *testing.T) {
	for _, valid := range []string{"admin", "ops.user", "LTE_admin-2", strings.Repeat("a", 64)} {
		if normalized, err := ValidateUsername(valid); err != nil || normalized != valid {
			t.Errorf("ValidateUsername(%q) = %q, %v", valid, normalized, err)
		}
	}
	for _, invalid := range []string{"ab", strings.Repeat("a", 65), "_admin", "user name", "администратор", "admin/ops"} {
		if _, err := ValidateUsername(invalid); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateUsername(%q) error = %v", invalid, err)
		}
	}
}
