package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestorePointControllerProtectsReleasePointersAndSerializesDeletion(t *testing.T) {
	store, databasePath, _ := restorePointFixture(t)
	point, err := store.CreatePreUpdate(context.Background(), "1.2.0", 32, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"current", "recovery"} {
		if err := createCurrentLink(filepath.Join(store.ReleaseRoot, name), filepath.FromSlash("releases/v1.2.0")); err != nil {
			t.Fatal(err)
		}
	}
	controller := &RestorePointController{
		Store: store, Journals: JournalStore{Root: filepath.Join(filepath.Dir(store.Root), "update-transactions")},
		Requests: RollbackRequestStore{Root: filepath.Join(filepath.Dir(store.Root), "update-rollback")}, ReleaseRoot: store.ReleaseRoot,
	}
	items, err := controller.Inventory(context.Background())
	if err != nil || len(items) != 1 || !items[0].Protected || !items[0].Compatible || items[0].Manifest.PointID != point.Manifest.PointID {
		t.Fatalf("Inventory() = %+v,%v", items, err)
	}
	if err := controller.Delete(context.Background(), point.Manifest.PointID); err == nil {
		t.Fatal("controller deleted a point protected by current and recovery pointers")
	}
}

func TestRestorePointControllerStagesOnlyCompatibleExactPoint(t *testing.T) {
	controller, point := rollbackControllerFixture(t)
	request, err := controller.StageRollback(context.Background(), point.Manifest.PointID)
	if err != nil || request.PointID != point.Manifest.PointID {
		t.Fatalf("StageRollback() = %+v,%v", request, err)
	}
	loaded, exists, err := controller.Requests.Load()
	if err != nil || !exists || loaded != request {
		t.Fatalf("staged request = %+v,%t,%v", loaded, exists, err)
	}
	if _, err := controller.StageRollback(context.Background(), testRollbackPointTwo); err == nil {
		t.Fatal("unknown restore point was staged")
	}
	items, err := controller.Inventory(context.Background())
	if err != nil || len(items) != 1 || !items[0].Protected || !containsRestoreRole(items[0].Roles, "ACTIVE_TRANSACTION") {
		t.Fatalf("pending rollback target protection = %+v,%v", items, err)
	}
}

func containsRestoreRole(roles []string, expected string) bool {
	for _, role := range roles {
		if role == expected {
			return true
		}
	}
	return false
}

func TestRestorePointControllerRejectsIncompatiblePointBeforeStaging(t *testing.T) {
	controller, point := rollbackControllerFixture(t)
	controller.Store.Verification.CurrentHostContractSHA256 = strings.Repeat("f", 64)
	if _, err := controller.StageRollback(context.Background(), point.Manifest.PointID); err == nil {
		t.Fatal("host-contract-incompatible restore point was staged")
	}
	if _, exists, err := controller.Requests.Load(); err != nil || exists {
		t.Fatalf("rollback request after incompatibility = exists:%t error:%v", exists, err)
	}
}

func rollbackControllerFixture(t *testing.T) (*RestorePointController, RestorePoint) {
	t.Helper()
	store, databasePath, _ := restorePointFixture(t)
	point, err := store.CreatePreUpdate(context.Background(), "1.2.0", 32, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"current", "recovery"} {
		if err := createCurrentLink(filepath.Join(store.ReleaseRoot, name), filepath.FromSlash("releases/v1.2.0")); err != nil {
			t.Fatal(err)
		}
	}
	requestsRoot := filepath.Join(filepath.Dir(store.Root), "update-rollback")
	if err := os.MkdirAll(requestsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	return &RestorePointController{
		Store: store, Journals: JournalStore{Root: filepath.Join(filepath.Dir(store.Root), "update-transactions")},
		Requests: RollbackRequestStore{Root: requestsRoot}, ReleaseRoot: store.ReleaseRoot,
	}, point
}
