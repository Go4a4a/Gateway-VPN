package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gateway-vpn/internal/firewall"

	_ "modernc.org/sqlite"
)

type nftManifest struct {
	FormatVersion int               `json:"format_version"`
	GeneratedBy   string            `json:"generated_by"`
	SHA256        map[string]string `json:"sha256"`
	Required      []string          `json:"required_markers"`
	Forbidden     []string          `json:"forbidden_markers"`
}

func main() {
	rootFlag := flag.String("root", "test/fixtures", "fixture root")
	repoFlag := flag.String("repo", ".", "repository root")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("unexpected positional arguments"))
	}
	root, err := safeDirectory(*rootFlag)
	if err != nil {
		fatal(err)
	}
	repo, err := safeDirectory(*repoFlag)
	if err != nil {
		fatal(err)
	}
	if err := generateNFT(root); err != nil {
		fatal(err)
	}
	if err := generateDatabases(root, repo); err != nil {
		fatal(err)
	}
}

func generateNFT(root string) error {
	directory := filepath.Join(root, "nftables")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt",
		APIPort: 8443, WireGuardListenPort: 51821,
	})
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"boot-blocked.nft": []byte(ruleset.Text),
		"two-modems-policy-routing.nft": []byte(`flush set inet gateway_vpn hilink_interfaces
flush set inet gateway_vpn hilink_management_v4
flush set inet gateway_vpn bootstrap_dns_v4
add element inet gateway_vpn hilink_interfaces { "enx001", "enx002" }
add element inet gateway_vpn hilink_management_v4 { "enx001" . 192.168.8.1, "enx002" . 192.168.9.1 }
add element inet gateway_vpn bootstrap_dns_v4 { "enx001" . 4353 . 1.1.1.1, "enx002" . 4354 . 1.1.1.1 }
`),
		"path-active-modem-a.nft": []byte(`flush set inet gateway_vpn active_tun_interfaces
flush set inet gateway_vpn active_direct_interfaces
flush set inet gateway_vpn active_direct_context
flush map inet gateway_vpn active_direct_marks
flush set inet gateway_vpn active_path_generation
flush set inet gateway_vpn active_route_generation
flush set inet gateway_vpn wireguard_ingress_allowed_v4
add element inet gateway_vpn active_path_generation { 101 }
add element inet gateway_vpn active_tun_interfaces { "gateway-vpn-tun" }
`),
		"path-active-modem-b.nft": []byte(`flush set inet gateway_vpn active_tun_interfaces
flush set inet gateway_vpn active_direct_interfaces
flush set inet gateway_vpn active_direct_context
flush map inet gateway_vpn active_direct_marks
flush set inet gateway_vpn active_path_generation
flush set inet gateway_vpn active_route_generation
flush set inet gateway_vpn wireguard_ingress_allowed_v4
add element inet gateway_vpn active_path_generation { 202 }
add element inet gateway_vpn active_tun_interfaces { "gateway-vpn-tun" }
`),
		"path-direct-modem-a.nft": []byte(`flush set inet gateway_vpn active_tun_interfaces
flush set inet gateway_vpn active_direct_interfaces
flush set inet gateway_vpn active_direct_context
flush map inet gateway_vpn active_direct_marks
flush set inet gateway_vpn active_path_generation
flush set inet gateway_vpn active_route_generation
flush set inet gateway_vpn wireguard_ingress_allowed_v4
add element inet gateway_vpn active_path_generation { 303 }
add element inet gateway_vpn active_route_generation { 1 }
add element inet gateway_vpn active_direct_interfaces { "wan0" }
add element inet gateway_vpn active_direct_context { "wan0" . 0x00001101 }
add element inet gateway_vpn active_direct_marks { "enp2s0" : 0x00001101 }
add element inet gateway_vpn active_direct_marks { "wg-ingress" : 0x00001101 }
`),
	}
	manifest := nftManifest{
		FormatVersion: 1, GeneratedBy: "go run ./test/fixtures/generate",
		SHA256: make(map[string]string, len(files)),
		Required: []string{
			"table inet gateway_vpn", "policy drop", "gateway-vpn PATH_BLOCKED",
			"counter user_upload", "counter user_download", "counter service_upload", "counter service_download",
			"wireguard_ingress_allowed_v4",
		},
		Forbidden: []string{"flush ruleset", "policy accept", "LAN to HiLink direct accept"},
	}
	for name, content := range files {
		if err := writeFixture(filepath.Join(directory, name), content); err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		manifest.SHA256[name] = hex.EncodeToString(digest[:])
	}
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return writeFixture(filepath.Join(directory, "expected-ruleset.json"), append(content, '\n'))
}

func generateDatabases(root, repo string) error {
	directory := filepath.Join(root, "database")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	migrationPath := filepath.Join(repo, "migrations", "000001_initial.sql")
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("read initial migration: %w", err)
	}
	cleanPath := filepath.Join(directory, "clean-v1.db")
	if err := createSchemaV1(cleanPath, migration); err != nil {
		return err
	}
	clean, err := os.ReadFile(cleanPath)
	if err != nil {
		return err
	}
	pageSize, err := sqlitePageSize(clean)
	if err != nil || len(clean) <= pageSize+128 {
		return errors.New("generated clean-v1 database is unexpectedly small")
	}
	corrupted := append([]byte(nil), clean...)
	corrupted[pageSize] = 0xff
	if err := writeFixture(filepath.Join(directory, "page-corrupted.db"), corrupted); err != nil {
		return err
	}
	// Simulate a torn main-file write after the header and only half of the
	// second database page. This is distinct from an invalid WAL tail, which
	// SQLite is expected to discard safely.
	partial := append([]byte(nil), clean[:pageSize+pageSize/2]...)
	if err := writeFixture(filepath.Join(directory, "partial-main-write.db"), partial); err != nil {
		return err
	}
	return generateWALFixtures(directory, clean)
}

func createSchemaV1(path string, migration []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	database.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer database.Close()
	for _, statement := range []string{"PRAGMA page_size=4096", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum_sha256 TEXT NOT NULL, applied_at TEXT NOT NULL)`} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize schema-v1 fixture: %w", err)
		}
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, string(migration)); err != nil {
		transaction.Rollback()
		return fmt.Errorf("apply schema-v1 fixture migration: %w", err)
	}
	digest := sha256.Sum256(migration)
	if _, err := transaction.ExecContext(ctx, `INSERT INTO schema_migrations(version,name,checksum_sha256,applied_at) VALUES(1,'initial',?,'2026-08-23T00:00:00Z')`, hex.EncodeToString(digest[:])); err != nil {
		transaction.Rollback()
		return err
	}
	// The initial migration uses SQLite's current time for the singleton
	// runtime row. Fixtures must be byte-reproducible, so replace that value
	// before VACUUM lays out the final database image.
	if _, err := transaction.ExecContext(ctx, `UPDATE runtime_state SET updated_at='2026-08-23T00:00:00Z' WHERE singleton_id=1`); err != nil {
		transaction.Rollback()
		return err
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, "VACUUM"); err != nil {
		return err
	}
	if err := database.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func generateWALFixtures(directory string, clean []byte) error {
	temporary, err := os.MkdirTemp("", "gateway-vpn-wal-fixture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	databasePath := filepath.Join(temporary, "state.db")
	if err := os.WriteFile(databasePath, clean, 0o600); err != nil {
		return err
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return err
	}
	database.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer database.Close()
	if _, err := database.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA wal_autocheckpoint=0"); err != nil {
		return err
	}
	for index := 1; index <= 3; index++ {
		if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?,?,?,?)`, fmt.Sprintf("2026-08-23T00:00:0%dZ", index), "INFO", fmt.Sprintf("WAL_FIXTURE_%d", index), "{}"); err != nil {
			return err
		}
	}
	mainImage, err := os.ReadFile(databasePath)
	if err != nil {
		return err
	}
	walImage, err := os.ReadFile(databasePath + "-wal")
	if err != nil || len(walImage) < 128 {
		return errors.New("generated WAL fixture is missing or too small")
	}
	if err := canonicalizeWAL(walImage, [8]byte{'G', 'W', 'V', 'P', 'N', '2', '0', '2'}); err != nil {
		return fmt.Errorf("canonicalize WAL fixture: %w", err)
	}
	if err := validateCanonicalWAL(temporary, mainImage, walImage); err != nil {
		return err
	}
	truncated := append([]byte(nil), walImage[:len(walImage)-31]...)
	invalidChecksum := append([]byte(nil), walImage...)
	invalidChecksum[len(invalidChecksum)-1] ^= 0x5a
	for name, wal := range map[string][]byte{
		"wal-truncated-recoverable":        truncated,
		"wal-invalid-checksum-recoverable": invalidChecksum,
	} {
		target := filepath.Join(directory, name)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		if err := writeFixture(filepath.Join(target, "state.db"), mainImage); err != nil {
			return err
		}
		if err := writeFixture(filepath.Join(target, "state.db-wal"), wal); err != nil {
			return err
		}
	}
	return nil
}

func validateCanonicalWAL(parent string, mainImage, walImage []byte) error {
	directory := filepath.Join(parent, "canonical-validation")
	if err := os.Mkdir(directory, 0o700); err != nil {
		return err
	}
	databasePath := filepath.Join(directory, "state.db")
	if err := os.WriteFile(databasePath, mainImage, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(databasePath+"-wal", walImage, 0o600); err != nil {
		return err
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return err
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var integrity string
	if err := database.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fmt.Errorf("query canonical WAL integrity: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("canonical WAL integrity check = %q", integrity)
	}
	var events int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type LIKE 'WAL_FIXTURE_%'`).Scan(&events); err != nil {
		return err
	}
	if events != 3 {
		return fmt.Errorf("canonical WAL exposes %d of 3 committed events", events)
	}
	return nil
}

// canonicalizeWAL replaces SQLite's random WAL salts and recalculates every
// dependent checksum. WAL integers are stored big-endian, while checksum input
// words use the byte order selected by the low bit of the WAL magic value.
func canonicalizeWAL(content []byte, salt [8]byte) error {
	const (
		walHeaderSize   = 32
		walFrameHdrSize = 24
		walMagicLE      = uint32(0x377f0682)
		walMagicBE      = uint32(0x377f0683)
	)
	if len(content) < walHeaderSize {
		return errors.New("WAL header is truncated")
	}
	magic := binary.BigEndian.Uint32(content[0:4])
	var checksumOrder binary.ByteOrder
	switch magic {
	case walMagicLE:
		checksumOrder = binary.LittleEndian
	case walMagicBE:
		checksumOrder = binary.BigEndian
	default:
		return fmt.Errorf("unsupported WAL magic %#x", magic)
	}
	pageSize := int(binary.BigEndian.Uint32(content[8:12]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return fmt.Errorf("invalid WAL page size %d", pageSize)
	}
	frameSize := walFrameHdrSize + pageSize
	if payload := len(content) - walHeaderSize; payload == 0 || payload%frameSize != 0 {
		return fmt.Errorf("invalid WAL frame area length %d", payload)
	}

	copy(content[16:24], salt[:])
	s0, s1, err := updateWALChecksum(checksumOrder, content[:24], 0, 0)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(content[24:28], s0)
	binary.BigEndian.PutUint32(content[28:32], s1)

	for offset := walHeaderSize; offset < len(content); offset += frameSize {
		frame := content[offset : offset+frameSize]
		copy(frame[8:16], salt[:])
		s0, s1, err = updateWALChecksum(checksumOrder, frame[:8], s0, s1)
		if err != nil {
			return err
		}
		s0, s1, err = updateWALChecksum(checksumOrder, frame[walFrameHdrSize:], s0, s1)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(frame[16:20], s0)
		binary.BigEndian.PutUint32(frame[20:24], s1)
	}
	return nil
}

func updateWALChecksum(order binary.ByteOrder, content []byte, s0, s1 uint32) (uint32, uint32, error) {
	if len(content) < 8 || len(content)%8 != 0 {
		return 0, 0, fmt.Errorf("WAL checksum input length %d is not a positive multiple of 8", len(content))
	}
	for offset := 0; offset < len(content); offset += 8 {
		s0 += order.Uint32(content[offset:offset+4]) + s1
		s1 += order.Uint32(content[offset+4:offset+8]) + s0
	}
	return s0, s1, nil
}

func sqlitePageSize(content []byte) (int, error) {
	if len(content) < 100 || string(content[:16]) != "SQLite format 3\x00" {
		return 0, errors.New("invalid SQLite header")
	}
	value := int(binary.BigEndian.Uint16(content[16:18]))
	if value == 1 {
		value = 65536
	}
	if value < 512 || value > 65536 || value&(value-1) != 0 {
		return 0, errors.New("invalid SQLite page size")
	}
	return value, nil
}

func writeFixture(path string, content []byte) error {
	if !filepath.IsAbs(path) || strings.Contains(filepath.ToSlash(path), "/../") {
		return errors.New("unsafe fixture output path")
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func safeDirectory(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("fixture directory must be an existing non-symlink directory")
	}
	return filepath.Clean(absolute), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
