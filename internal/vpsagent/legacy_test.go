package vpsagent

import (
	"context"
	"testing"
	"time"

	"gateway-vpn/internal/wgingress"
)

func TestAdoptLegacyInstallerPeersIsExactAndNonDestructive(t *testing.T) {
	repository := testHubRepository(t)
	database := repository.Database
	repository.Now = func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }
	gateway, _ := wgingress.GenerateKeyPair()
	admin, _ := wgingress.GenerateKeyPair()
	result, err := repository.AdoptLegacyInstallerPeers(context.Background(), LegacyAdoptionInput{
		GatewayPublicKey: gateway.Public, AdminPublicKey: admin.Public, Endpoint: "vps.example:51821",
	})
	if err != nil || !result.Adopted || result.SiteID == "" {
		t.Fatalf("adopt legacy = %+v, %v", result, err)
	}
	plan, err := repository.RenderHostPlan(context.Background())
	if err != nil || plan.Generation != 1 || len(plan.InterfaceAddresses) != 1 || plan.InterfaceAddresses[0] != "10.80.0.1/24" || len(plan.Peers) != 2 {
		t.Fatalf("legacy plan = %+v, %v", plan, err)
	}
	desired, applied, err := repository.FabricGenerations(context.Background())
	if err != nil || desired != 1 || applied != 1 {
		t.Fatalf("legacy generations = %d/%d, %v", applied, desired, err)
	}
	repeated, err := repository.AdoptLegacyInstallerPeers(context.Background(), LegacyAdoptionInput{
		GatewayPublicKey: gateway.Public, AdminPublicKey: admin.Public, Endpoint: "vps.example:51821",
	})
	if err != nil || repeated.Adopted || repeated.Reason != "TOPOLOGY_ALREADY_CONFIGURED" {
		t.Fatalf("repeated adoption = %+v, %v", repeated, err)
	}
	var stored string
	if err := database.QueryRow("SELECT public_key FROM gateway_peers WHERE id=?", LegacyGatewayPeerID).Scan(&stored); err != nil || stored != gateway.Public {
		t.Fatalf("legacy peer was overwritten: %q, %v", stored, err)
	}
}

func TestMarkHostPlanAppliedRejectsGenerationRace(t *testing.T) {
	repository := testHubRepository(t)
	database := repository.Database
	if _, err := database.Exec("UPDATE vps_settings SET value_json='{" + `"desired_generation":3,"applied_generation":1,"state":"PENDING"` + "}' WHERE key='fabric'"); err != nil {
		t.Fatal(err)
	}
	if err := repository.MarkHostPlanApplied(context.Background(), 2, time.Now()); err == nil {
		t.Fatal("stale generation was accepted")
	}
	if err := repository.MarkHostPlanApplied(context.Background(), 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	desired, applied, err := repository.FabricGenerations(context.Background())
	if err != nil || desired != 3 || applied != 3 {
		t.Fatalf("generations = %d/%d, %v", applied, desired, err)
	}
	if err := repository.MarkHostPlanApplied(context.Background(), 4, time.Now()); err == nil {
		t.Fatal("future generation was accepted")
	}
}
