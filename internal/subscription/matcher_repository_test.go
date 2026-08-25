package subscription

import (
	"testing"
	"time"

	"gateway-vpn/internal/modem"
)

func TestMatcherChangesInvalidateMatrixPolicy(t *testing.T) {
	ctx, database := migratedDatabase(t)
	if _, err := NewRepository(database).Create(ctx, CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := modem.NewRepository(database, 1101, 0x1101).Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_modem_paths (
    id, modem_id, subscription_id, state, transport_state,
    policy_generation, route_generation, created_at, updated_at
) VALUES ('path-a', 'modem-a', 'sub-a', 'UNTESTED', 'UNKNOWN', 0, 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	repository := NewMatcherRepository(database)
	seeded, err := repository.EnsureDefaults(ctx)
	if err != nil || !seeded {
		t.Fatalf("EnsureDefaults() = %v, %v", seeded, err)
	}
	seeded, err = repository.EnsureDefaults(ctx)
	if err != nil || seeded {
		t.Fatalf("EnsureDefaults(second) = %v, %v", seeded, err)
	}
	var generation int64
	var state string
	if err := database.QueryRowContext(ctx, "SELECT policy_generation, state FROM subscription_modem_paths WHERE id='path-a'").Scan(&generation, &state); err != nil {
		t.Fatal(err)
	}
	if generation != 1 || state != "STALE" {
		t.Fatalf("path after default seed = %d/%s", generation, state)
	}
	created, err := repository.Create(ctx, MatcherCreateInput{ID: "carrier", Pattern: "operator", Type: MatcherSubstring})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(ctx, created.ID, MatcherUpdateInput{Pattern: "carrier", Type: MatcherSubstring, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT policy_generation FROM subscription_modem_paths WHERE id='path-a'").Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != 3 {
		t.Fatalf("policy generation after create/update = %d, want 3", generation)
	}
}
