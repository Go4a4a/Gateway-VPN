package hilink

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
)

func TestDiscoveryRegistryRedactsIdentityAndAdoptsCurrentUnambiguousDevice(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	registry := NewDiscoveryRegistry(modem.NewRepository(database, 1101, 0x1101))
	identity := strings.Repeat("a", 64)
	registry.Replace([]Match{{State: DiscoveryUnadopted, Candidate: Candidate{DiscoveryID: "discovery-a", InterfaceName: "enx1", VendorID: "12d1", ProductID: "14db", IdentityKind: "usb_serial_hash", IdentityHash: identity, MaskedSerial: "****1234", Carrier: true}}})
	views := registry.List()
	if len(views) != 1 || views[0].DiscoveryID != "discovery-a" || strings.Contains(strings.Join([]string{views[0].Reason, views[0].MaskedSerial, views[0].TopologyHint}, " "), identity) {
		t.Fatalf("redacted discovery views = %+v", views)
	}
	created, err := registry.Adopt(ctx, "discovery-a", "modem-a", "Operator A", "SIM A")
	if err != nil || created.DisplayNumber != 1 || created.IdentityHash != identity {
		t.Fatalf("Adopt() = %+v, %v", created, err)
	}
	if len(registry.List()) != 0 {
		t.Fatal("adopted discovery remained in registry")
	}
}

func TestDiscoveryRegistryReplacesOfflineIdentityWithoutExposingHash(t *testing.T) {
	database := registryDatabase(t)
	repository := modem.NewRepository(database, 1101, 0x1101)
	oldIdentity := strings.Repeat("a", 64)
	if _, err := repository.Adopt(context.Background(), modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: oldIdentity}); err != nil {
		t.Fatal(err)
	}
	registry := NewDiscoveryRegistry(repository)
	newIdentity := strings.Repeat("b", 64)
	registry.Replace([]Match{{State: DiscoveryUnadopted, Candidate: Candidate{DiscoveryID: "replacement-a", InterfaceName: "enx2", IdentityKind: "usb_serial_hash", IdentityHash: newIdentity, MaskedSerial: "****4321"}}})
	if err := registry.ReplaceIdentity(context.Background(), "replacement-a", "modem-a"); err != nil {
		t.Fatal(err)
	}
	updated, err := repository.Get(context.Background(), "modem-a")
	if err != nil || updated.IdentityHash != newIdentity || updated.MaskedSerial != "****4321" || len(registry.List()) != 0 {
		t.Fatalf("identity replacement = %+v, %v, discoveries=%+v", updated, err, registry.List())
	}
}

func registryDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	return database
}
