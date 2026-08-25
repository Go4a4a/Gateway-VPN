package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestArgon2PasswordAndSessionLifecycle(t *testing.T) {
	parameters := Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hash, err := HashPassword("correct horse battery staple", parameters)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword("correct horse battery staple", hash); err != nil || !ok {
		t.Fatalf("VerifyPassword(correct) = %v, %v", ok, err)
	}
	if ok, err := VerifyPassword("wrong password", hash); err != nil || ok {
		t.Fatalf("VerifyPassword(wrong) = %v, %v", ok, err)
	}

	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	service := Service{Database: database, Parameters: parameters, SessionLifetime: time.Hour, Now: func() time.Time { return now }}
	created, err := service.CreateBootstrapAdmin(ctx, "correct horse battery staple")
	if err != nil || !created {
		t.Fatalf("CreateBootstrapAdmin() = %v, %v", created, err)
	}
	created, err = service.CreateBootstrapAdmin(ctx, "another secure password")
	if err != nil || created {
		t.Fatalf("CreateBootstrapAdmin(second) = %v, %v", created, err)
	}
	session, err := service.Login(ctx, "admin", "correct horse battery staple", "client")
	if err != nil || session.Token == "" || session.CSRFToken == "" {
		t.Fatalf("Login() = %+v, %v", session, err)
	}
	principal, err := service.Authenticate(ctx, session.Token)
	if err != nil || principal.Username != "admin" || !principal.MustChangePassword {
		t.Fatalf("Authenticate() = %+v, %v", principal, err)
	}
	if err := service.ValidateCSRF(principal, session.CSRFToken); err != nil {
		t.Fatalf("ValidateCSRF(correct) error = %v", err)
	}
	if err := service.ValidateCSRF(principal, "wrong"); !errors.Is(err, ErrInvalidCSRF) {
		t.Fatalf("ValidateCSRF(wrong) error = %v", err)
	}
	if err := service.Revoke(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, session.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Authenticate(revoked) error = %v", err)
	}
	var lifecycleAudit int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type IN ('AUTH_BOOTSTRAP_ADMIN_CREATED','AUTH_LOGIN_SUCCEEDED','AUTH_LOGOUT')").Scan(&lifecycleAudit); err != nil || lifecycleAudit != 3 {
		t.Fatalf("auth lifecycle audit events = %d, %v", lifecycleAudit, err)
	}
}

func TestLoginRateLimitUsesProgressiveBlock(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	service := Service{Database: database, Parameters: Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}, Now: func() time.Time { return now }}
	if _, err := service.CreateBootstrapAdmin(ctx, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := service.Login(ctx, "admin", "wrong", "client"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login(wrong %d) error = %v", attempt, err)
		}
	}
	if _, err := service.Login(ctx, "admin", "correct horse battery staple", "client"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Login(blocked) error = %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := service.Login(ctx, "admin", "correct horse battery staple", "client"); err != nil {
		t.Fatalf("Login(after delay) error = %v", err)
	}
	var failed, limited, succeeded int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='AUTH_LOGIN_FAILED'").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='AUTH_LOGIN_RATE_LIMITED'").Scan(&limited); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='AUTH_LOGIN_SUCCEEDED'").Scan(&succeeded); err != nil {
		t.Fatal(err)
	}
	if failed != 3 || limited != 1 || succeeded != 1 {
		t.Fatalf("auth attempt audit counts = failed %d limited %d succeeded %d", failed, limited, succeeded)
	}
	var leaked int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE details_json LIKE '%wrong%' OR details_json LIKE '%correct horse%'").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("auth audit password leaks = %d, %v", leaked, err)
	}
}
