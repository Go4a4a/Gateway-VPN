package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gateway-vpn/internal/auth"
	databasepkg "gateway-vpn/internal/db"
)

func TestEnsureAdminCreatesOnePasswordFileAndOneUser(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(root, "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	service := auth.Service{Database: database, Parameters: auth.Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}}
	first, err := EnsureAdmin(ctx, service, root)
	if err != nil || !first.Created {
		t.Fatalf("EnsureAdmin(first) = %+v, %v", first, err)
	}
	passwordBefore, err := os.ReadFile(first.PasswordFile)
	if err != nil || len(passwordBefore) < 12 {
		t.Fatalf("password file = %q, %v", passwordBefore, err)
	}
	second, err := EnsureAdmin(ctx, service, root)
	if err != nil || second.Created {
		t.Fatalf("EnsureAdmin(second) = %+v, %v", second, err)
	}
	passwordAfter, _ := os.ReadFile(first.PasswordFile)
	if string(passwordBefore) != string(passwordAfter) {
		t.Fatal("second bootstrap changed one-time password")
	}
}
