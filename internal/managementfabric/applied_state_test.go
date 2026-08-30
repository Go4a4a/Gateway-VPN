package managementfabric

import (
	"context"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/modem"
)

func TestGatewayAppliedStateCommitsAndRestoresConvergenceMetadata(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	vps, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem:a", Name: "A", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem:a", modem.LeaseInput{InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	link, err := repository.CreateLink(ctx, CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
		LocalPublicKey:           testPublicKey(t), RemotePublicKey: vps.PublicKey,
		UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
		Endpoints: []EndpointSpec{{Host: "203.0.113.10", Port: 51821}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertGatewayHostPlanObjects(t, ctx, database, link)
	plan, err := repository.BuildGatewayHostPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, err := repository.CaptureGatewayAppliedState(ctx)
	if err != nil || before.Generation != 0 {
		t.Fatalf("initial applied state = %+v, %v", before, err)
	}
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	if err := repository.MarkGatewayHostPlanApplied(ctx, plan, now); err != nil {
		t.Fatal(err)
	}
	desired, applied, state, code, err := repository.GatewayFabricGenerations(ctx)
	if err != nil || desired != plan.Generation || applied != plan.Generation || state != "APPLIED" || code != "" {
		t.Fatalf("applied generations = %d/%d %s %q, %v", applied, desired, state, code, err)
	}
	linkState, err := repository.GetLink(ctx, link.ID)
	if err != nil || linkState.SelectedUplinkID != "modem:a" || linkState.AppliedRouteGeneration != linkState.DesiredRouteGeneration || linkState.AppliedACLGeneration != linkState.DesiredACLGeneration {
		t.Fatalf("applied link = %+v, %v", linkState, err)
	}
	if err := repository.RestoreGatewayAppliedState(ctx, before, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, applied, state, _, err = repository.GatewayFabricGenerations(ctx)
	if err != nil || applied != 0 || state != before.State {
		t.Fatalf("restored state = %d %s, %v", applied, state, err)
	}
}

func TestGatewayAppliedCommitRejectsStaleDesiredGeneration(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	plan := GatewayHostPlan{Generation: 1, RouteProtocol: OwnedRouteProtocol}
	if _, err := database.ExecContext(context.Background(), `UPDATE management_fabric_generations SET desired_generation=2 WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	if err := repository.MarkGatewayHostPlanApplied(ctx, plan, time.Now()); err == nil {
		t.Fatal("stale Gateway host plan was committed")
	}
}
