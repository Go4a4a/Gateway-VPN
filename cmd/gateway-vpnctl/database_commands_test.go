package main

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	databasepkg "gateway-vpn/internal/db"
)

func TestDatabaseVerifyRequiresExactHealthySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database, err := databasepkg.Open(context.Background(), databasepkg.OpenOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(context.Background(), database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	schema, err := databasepkg.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"--database", path, "--expected-schema", strconv.FormatInt(schema, 10), "--json"}
	if code := runDatabaseVerify(arguments); code != 0 {
		t.Fatalf("runDatabaseVerify() code = %d, want 0", code)
	}
	arguments[3] = strconv.FormatInt(schema-1, 10)
	if code := runDatabaseVerify(arguments); code != 1 {
		t.Fatalf("runDatabaseVerify(wrong schema) code = %d, want 1", code)
	}
	if code := runDatabaseVerify([]string{"--database", path}); code != 2 {
		t.Fatalf("runDatabaseVerify(incomplete) code = %d, want 2", code)
	}
	writable, err := databasepkg.Open(context.Background(), databasepkg.OpenOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writable.Exec("UPDATE schema_migrations SET checksum_sha256=? WHERE version=?", "tampered", schema); err != nil {
		writable.Close()
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	arguments[3] = strconv.FormatInt(schema, 10)
	if code := runDatabaseVerify(arguments); code != 1 {
		t.Fatalf("runDatabaseVerify(tampered history) code = %d, want 1", code)
	}
}
