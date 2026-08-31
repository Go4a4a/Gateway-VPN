package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

var markerPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	flags := flag.NewFlagSet("restore-point-marker", flag.ContinueOnError)
	databasePath := flags.String("database", "", "absolute Gateway SQLite path")
	value := flags.String("value", "", "bounded release-gate marker")
	set := flags.Bool("set", false, "atomically update the marker")
	get := flags.Bool("get", false, "read the exact marker")
	confirmed := flags.Bool("release-gate-only", false, "confirm isolated release-gate use")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if os.Getenv("GATEWAY_VPN_RELEASE_GATE") != "1" || !*confirmed || *set == *get ||
		!filepath.IsAbs(*databasePath) || filepath.Base(filepath.Clean(*databasePath)) != "state.db" {
		fmt.Fprintln(os.Stderr, "exact isolated release-gate arguments are required")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *set {
		if !markerPattern.MatchString(*value) {
			fmt.Fprintln(os.Stderr, "release-gate marker is invalid")
			return 2
		}
		database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Clean(*databasePath)})
		if err != nil {
			fmt.Fprintln(os.Stderr, "open Gateway database failed")
			return 1
		}
		_, execErr := database.ExecContext(ctx, `
INSERT INTO settings(key,value_json,updated_at) VALUES('release_gate_restore_marker',?,?)
ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at`, strconv.Quote(*value), time.Now().UTC().Format(time.RFC3339Nano))
		if execErr == nil {
			_, execErr = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
		}
		closeErr := database.Close()
		if execErr != nil || closeErr != nil {
			fmt.Fprintln(os.Stderr, "write Gateway release-gate marker failed")
			return 1
		}
		fmt.Println(*value)
		return 0
	}
	database, err := databasepkg.OpenReadOnly(ctx, filepath.Clean(*databasePath))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open Gateway database read-only failed")
		return 1
	}
	var encoded string
	queryErr := database.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='release_gate_restore_marker'").Scan(&encoded)
	closeErr := database.Close()
	decoded, decodeErr := strconv.Unquote(encoded)
	if queryErr != nil || closeErr != nil || decodeErr != nil || !markerPattern.MatchString(decoded) {
		fmt.Fprintln(os.Stderr, "read Gateway release-gate marker failed")
		return 1
	}
	fmt.Println(decoded)
	return 0
}
