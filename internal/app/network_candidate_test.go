package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
)

func TestNetworkCandidateBuilderRejectsWireGuardAndModemOverlap(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	digest := sha256.Sum256([]byte("modem-a"))
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enx1", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"192.168.8.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	builder := networkCandidateBuilder(configuration, database)
	candidate, err := builder(ctx, "192.168.210.1/24")
	if err != nil || candidate.NewURL != "https://192.168.210.1:8443" || candidate.OldURL != "https://192.168.200.1:8443" {
		t.Fatalf("valid candidate = %+v, %v", candidate, err)
	}
	for _, value := range []string{"192.168.8.10/24", "10.80.0.10/24"} {
		if _, err := builder(ctx, value); err == nil || !strings.Contains(strings.ToLower(err.Error()), "overlap") {
			t.Errorf("builder(%s) error = %v", value, err)
		}
	}
}
