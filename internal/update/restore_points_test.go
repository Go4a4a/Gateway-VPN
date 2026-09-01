package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestRestorePointInventoryProtectsCurrentAndDetectsTampering(t *testing.T) {
	store, databasePath, clock := restorePointFixture(t)
	point, err := store.CreatePreUpdate(context.Background(), "1.2.0", 34, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	items, err := store.Inventory(context.Background(), "1.2.0", "1.2.0", nil)
	if err != nil || len(items) != 1 || !items[0].Protected || strings.Join(items[0].Roles, ",") != "CURRENT,RECOVERY" || items[0].Manifest.PointID != point.Manifest.PointID {
		t.Fatalf("inventory = %+v,%v", items, err)
	}
	if err := store.Delete(context.Background(), point.Manifest.PointID, "1.2.0", "1.2.0", nil); err == nil {
		t.Fatal("protected current/recovery point was deleted")
	}
	secret := filepath.Join(store.Root, point.Manifest.PointID, "state", "secrets", "mihomo-api-secret")
	if err := os.WriteFile(secret, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inventory(context.Background(), "", "", nil); err == nil {
		t.Fatal("tampered restore point was accepted")
	}
	_ = clock
}

func TestRestorePointDeletionAndRetentionKeepNewestHistoricalPoints(t *testing.T) {
	store, databasePath, clock := restorePointFixture(t)
	var points []RestorePoint
	for index := 0; index < 4; index++ {
		*clock = clock.Add(time.Hour)
		point, err := store.CreatePreUpdate(context.Background(), "1.2.0", 34, databasePath)
		if err != nil {
			t.Fatal(err)
		}
		points = append(points, point)
	}
	policy := DefaultRestorePointPolicy()
	policy.MaximumPoints = 2
	policy.MinimumOldPoints = 1
	removed, err := store.Prune(context.Background(), policy, "", "", nil)
	if err != nil || len(removed) != 2 {
		t.Fatalf("Prune() = %v,%v", removed, err)
	}
	items, err := store.Inventory(context.Background(), "", "", nil)
	if err != nil || len(items) != 2 || items[0].Manifest.PointID != points[3].Manifest.PointID || items[1].Manifest.PointID != points[2].Manifest.PointID {
		t.Fatalf("retained inventory = %+v,%v", items, err)
	}
	if err := store.Delete(context.Background(), items[1].Manifest.PointID, "", "", nil); err != nil {
		t.Fatal(err)
	}
	items, err = store.Inventory(context.Background(), "", "", nil)
	if err != nil || len(items) != 1 || items[0].Manifest.PointID != points[3].Manifest.PointID {
		t.Fatalf("inventory after delete = %+v,%v", items, err)
	}
}

func restorePointFixture(t *testing.T) (*RestorePointStore, string, *time.Time) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "secrets", "mihomo-api-secret"), []byte("private-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(stateDir, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeDatabaseSidecars(databasePath); err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configuration, []byte(testBootstrapConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	release, publicKey, _ := signedReleaseFixture(t, "1.2.0", 1, 34)
	releaseMetadata, err := ReadReleaseMetadata(release)
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(root, "opt")
	destination := filepath.Join(releaseRoot, "releases", "v1.2.0")
	copyRestorePointReleaseFixture(t, release, destination)
	clock := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	store := &RestorePointStore{
		Root: filepath.Join(root, "privileged", "update-restore-points"), ReleaseRoot: releaseRoot,
		StateDir: stateDir, Configuration: configuration,
		Verification: VerificationPolicy{PublicKey: publicKey, ExpectedOS: "linux", ExpectedArch: "amd64", ConfigGeneration: 1, CurrentHostContractSHA256: releaseMetadata.HostContractSHA256, GatewayAPIContract: GatewayAPIContract, MihomoAPIContract: MihomoAPIContract},
		Now:          func() time.Time { return clock },
	}
	return store, databasePath, &clock
}

func copyRestorePointReleaseFixture(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, filename)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
}
