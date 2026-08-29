package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func runDatabaseVerify(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl database-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	databasePath := flags.String("database", "", "existing Gateway VPN SQLite path")
	expectedSchema := flags.Int64("expected-schema", 0, "required exact schema version")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *databasePath == "" || *expectedSchema < 1 || !*jsonOutput {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := databasepkg.OpenReadOnly(ctx, *databasePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open Gateway VPN database for verification failed")
		return 1
	}
	schema, schemaErr := databasepkg.ReadSchemaVersion(ctx, database)
	historyErr := databasepkg.VerifyMigrationHistory(ctx, database, *expectedSchema)
	quickErr := databasepkg.QuickCheck(ctx, database)
	integrityErr := databasepkg.IntegrityCheck(ctx, database)
	foreignKeyErr := databasepkg.ForeignKeyCheck(ctx, database)
	closeErr := database.Close()
	if schemaErr != nil || schema != *expectedSchema || historyErr != nil || quickErr != nil || integrityErr != nil || foreignKeyErr != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, "Gateway VPN database verification failed")
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema_version":    schema,
		"migration_history": "ok",
		"quick_check":       "ok",
		"integrity_check":   "ok",
		"foreign_key_check": "ok",
	}); err != nil {
		return 1
	}
	return 0
}
