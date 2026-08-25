package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
)

type OfflineResult struct {
	SchemaVersion   int64  `json:"schema_version"`
	DatabaseBytes   int64  `json:"database_bytes"`
	DatabaseSHA256  string `json:"database_sha256"`
	QuickCheck      string `json:"quick_check"`
	IntegrityCheck  string `json:"integrity_check"`
	ForeignKeyCheck string `json:"foreign_key_check"`
}

func CheckCandidateComponents(ctx context.Context, executor platformexec.Executor, releaseRoot, stateDir, expectedVersion, expectedMihomo string, expectedSchema int64) error {
	if executor == nil || !filepath.IsAbs(releaseRoot) || !filepath.IsAbs(stateDir) || !versionPattern.MatchString(expectedVersion) || !mihomoVersionPattern.MatchString(expectedMihomo) || expectedSchema < 1 {
		return errors.New("candidate component check requires fixed release/state paths and versions")
	}
	release, err := ReadReleaseMetadata(releaseRoot)
	if err != nil || release.GatewayVersion != expectedVersion || release.MihomoVersion != expectedMihomo || release.DatabaseSchemaMaximum != expectedSchema {
		return errors.New("candidate component metadata does not match the update request")
	}
	mihomo := filepath.Join(releaseRoot, "libexec", "mihomo")
	digest, _, err := hashFile(mihomo, MaximumFileBytes)
	if err != nil || digest != release.MihomoSHA256 {
		return errors.New("candidate Mihomo binary hash does not match release metadata")
	}
	version, err := executor.Run(ctx, platformexec.Request{Executable: mihomo, Arguments: []string{"-v"}, MaxOutputBytes: 64 << 10})
	if err != nil {
		return errors.New("candidate Mihomo version command failed")
	}
	coreVersion := strings.TrimPrefix(expectedMihomo, "v")
	if coreVersion == "" || !strings.Contains(version.Stdout+version.Stderr, coreVersion) {
		return errors.New("candidate Mihomo version output does not match the pinned release")
	}
	active := filepath.Join(stateDir, "mihomo", "active")
	if !pathExists(active) {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(active)
	if err != nil || !pathInside(filepath.Join(stateDir, "mihomo", "generations"), resolved) {
		return errors.New("active Mihomo generation is outside the managed state root")
	}
	if _, err := executor.Run(ctx, platformexec.Request{Executable: mihomo, Arguments: []string{"-t", "-d", active}, MaxOutputBytes: 1 << 20}); err != nil {
		return errors.New("candidate Mihomo rejected the active LKG configuration")
	}
	return nil
}

func CheckCandidateDatabase(ctx context.Context, databasePath, configPath string, expectedMaximumSchema int64) (OfflineResult, error) {
	if !filepath.IsAbs(databasePath) || !filepath.IsAbs(configPath) || expectedMaximumSchema < 1 {
		return OfflineResult{}, errors.New("absolute candidate paths and expected schema are required")
	}
	configuration, err := config.Load(configPath)
	if err != nil || configuration.Version != config.CurrentVersion {
		return OfflineResult{}, errors.New("candidate bootstrap config is incompatible")
	}
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		return OfflineResult{}, fmt.Errorf("open candidate database: %w", err)
	}
	closeDatabase := true
	defer func() {
		if closeDatabase {
			_ = database.Close()
		}
	}()
	before, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil || before < 1 || before > expectedMaximumSchema {
		return OfflineResult{}, errors.New("candidate database source schema is incompatible")
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil || latest != expectedMaximumSchema {
		return OfflineResult{}, errors.New("candidate binary migration set does not match release metadata")
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		return OfflineResult{}, fmt.Errorf("migrate candidate database: %w", err)
	}
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return OfflineResult{}, err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return OfflineResult{}, err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return OfflineResult{}, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return OfflineResult{}, errors.New("checkpoint migrated candidate database failed")
	}
	if err := database.Close(); err != nil {
		return OfflineResult{}, errors.New("close migrated candidate database failed")
	}
	closeDatabase = false
	if err := removeDatabaseSidecars(databasePath); err != nil {
		return OfflineResult{}, err
	}
	immutable, err := databasepkg.OpenImmutable(ctx, databasePath)
	if err != nil {
		return OfflineResult{}, errors.New("reopen migrated candidate database failed")
	}
	defer immutable.Close()
	if err := databasepkg.QuickCheck(ctx, immutable); err != nil {
		return OfflineResult{}, err
	}
	if err := databasepkg.IntegrityCheck(ctx, immutable); err != nil {
		return OfflineResult{}, err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, immutable); err != nil {
		return OfflineResult{}, err
	}
	schema, err := databasepkg.ReadSchemaVersion(ctx, immutable)
	if err != nil || schema != expectedMaximumSchema {
		return OfflineResult{}, errors.New("migrated candidate schema does not match release metadata")
	}
	digest, size, err := hashDatabase(databasePath)
	if err != nil {
		return OfflineResult{}, err
	}
	return OfflineResult{SchemaVersion: schema, DatabaseBytes: size, DatabaseSHA256: digest, QuickCheck: "PASS", IntegrityCheck: "PASS", ForeignKeyCheck: "PASS"}, nil
}

func verifyOfflineResult(result OfflineResult, expectedSchema int64) error {
	if result.SchemaVersion != expectedSchema || result.DatabaseBytes <= 0 || result.DatabaseBytes > MaximumFileBytes || !digestPattern.MatchString(result.DatabaseSHA256) || result.QuickCheck != "PASS" || result.IntegrityCheck != "PASS" || result.ForeignKeyCheck != "PASS" {
		return errors.New("candidate offline check result is invalid")
	}
	return nil
}

func verifyCandidateDatabase(ctx context.Context, path string, result OfflineResult) error {
	database, err := databasepkg.OpenImmutable(ctx, path)
	if err != nil {
		return errors.New("open candidate database after offline check failed")
	}
	defer database.Close()
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return err
	}
	schema, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil || schema != result.SchemaVersion {
		return errors.New("candidate database schema changed after offline check")
	}
	digest, size, err := hashDatabase(path)
	if err != nil || digest != result.DatabaseSHA256 || size != result.DatabaseBytes {
		return errors.New("candidate database changed after offline check")
	}
	return nil
}

func hashDatabase(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumFileBytes {
		return "", 0, errors.New("candidate database must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, MaximumFileBytes+1))
	if err != nil || read != info.Size() || read > MaximumFileBytes {
		return "", 0, errors.New("hash candidate database failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), read, nil
}

func removeDatabaseSidecars(databasePath string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := databasePath + suffix
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("candidate SQLite sidecar is unsafe")
		}
		if err := os.Remove(path); err != nil {
			return errors.New("remove candidate SQLite sidecar failed")
		}
	}
	return syncDirectoryPath(filepath.Dir(databasePath))
}
