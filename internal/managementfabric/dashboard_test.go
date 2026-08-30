package managementfabric

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestDashboardRedactsWireGuardKeysAndSupportsVPSAndLinkControls(t *testing.T) {
	ctx, _, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	firstKey, secondKey, localKey := testPublicKey(t), testPublicKey(t), testPublicKey(t)
	first, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS A", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: firstKey,
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:b", Name: "VPS B", VerifiedFingerprint: strings.Repeat("b", 64), PublicKey: secondKey,
		AdminAddressPool: "10.83.0.0/24", ResourceAliasPool: "10.97.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	link, err := repository.CreateLink(ctx, CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: first.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
		LocalPublicKey:           localKey, RemotePublicKey: firstKey, UplinkPolicy: UplinkAuto,
		PersistentKeepalive: 25, Endpoints: []EndpointSpec{{Host: "203.0.113.10", Port: 51821}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := repository.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboard.VPS) != 2 || len(dashboard.Links) != 1 || dashboard.DesiredGeneration <= dashboard.AppliedGeneration || strings.Contains(string(payload), firstKey) || strings.Contains(string(payload), localKey) || strings.Contains(string(payload), "/var/lib/gateway-vpn/secrets") {
		t.Fatalf("redacted dashboard = %s", payload)
	}

	if _, err := repository.UpdateLink(ctx, link.ID, UpdateLinkInput{Enabled: false, UplinkPolicy: UplinkAuto, PersistentKeepalive: 30}); err != nil {
		t.Fatal(err)
	}
	updatedLink, err := repository.GetLink(ctx, link.ID)
	if err != nil || updatedLink.Enabled || updatedLink.State != "DISABLED" || updatedLink.PersistentKeepalive != 30 {
		t.Fatalf("disabled management link = %+v, %v", updatedLink, err)
	}
	if _, err := repository.UpdateVPS(ctx, first.ID, UpdateVPSInput{Name: "Primary VPS", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.UpdateVPS(ctx, first.ID, UpdateVPSInput{Name: "Primary VPS", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReorderVPS(ctx, []string{second.ID, first.ID}); err != nil {
		t.Fatal(err)
	}
	items, err := repository.ListVPS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ordered := []string{items[0].ID, items[1].ID}
	if !slices.Equal(ordered, []string{second.ID, first.ID}) || items[0].Priority != 10 || items[1].Priority != 20 {
		t.Fatalf("VPS priority order = %+v", items)
	}
}

func TestReorderVPSRequiresEveryEnabledItem(t *testing.T) {
	ctx := context.Background()
	_, _, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	for index, id := range []string{"vps:a", "vps:b"} {
		if _, err := repository.CreateVPS(ctx, CreateVPSInput{
			ID: id, Name: id, VerifiedFingerprint: strings.Repeat(string(rune('a'+index)), 64), PublicKey: testPublicKey(t),
			AdminAddressPool: []string{"10.81.0.0/24", "10.83.0.0/24"}[index], ResourceAliasPool: []string{"10.96.0.0/16", "10.97.0.0/16"}[index],
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.ReorderVPS(ctx, []string{"vps:a"}); err == nil {
		t.Fatal("partial VPS priority order accepted")
	}
}
