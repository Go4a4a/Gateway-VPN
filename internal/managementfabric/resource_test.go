package managementfabric

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/store"
)

func TestResourceKindProfileCompatibilityAndPortBounds(t *testing.T) {
	kinds := []string{ResourceGatewayService, ResourceKeeneticService, ResourceLocalHost, ResourceLocalSubnet, ResourceCustomService}
	profiles := []string{ProfileGatewayOnly, ProfileKeeneticWAN, ProfileKeeneticWANRouted, ProfileWireGuardRouter, ProfileDedicatedLAN}
	allowed := map[string]map[string]bool{
		ResourceGatewayService:  {ProfileGatewayOnly: true},
		ResourceKeeneticService: {ProfileKeeneticWAN: true, ProfileKeeneticWANRouted: true, ProfileWireGuardRouter: true, ProfileDedicatedLAN: true},
		ResourceLocalHost:       {ProfileKeeneticWANRouted: true, ProfileWireGuardRouter: true, ProfileDedicatedLAN: true},
		ResourceLocalSubnet:     {ProfileKeeneticWANRouted: true, ProfileWireGuardRouter: true, ProfileDedicatedLAN: true},
		ResourceCustomService:   {ProfileKeeneticWANRouted: true, ProfileWireGuardRouter: true, ProfileDedicatedLAN: true},
	}
	for _, kind := range kinds {
		for _, profile := range profiles {
			if got, want := ResourceKindProfileCompatible(kind, profile), allowed[kind][profile]; got != want {
				t.Errorf("ResourceKindProfileCompatible(%s, %s) = %t, want %t", kind, profile, got, want)
			}
		}
	}
	valid := []ResourcePort{{Protocol: ProtocolTCP, PortStart: 8000, PortEnd: 8010}, {Protocol: ProtocolUDP, PortStart: 53, PortEnd: 53}, {Protocol: ProtocolICMP}}
	if err := ValidateResourcePorts(ResourceLocalHost, valid); err != nil {
		t.Fatalf("valid bounded ports rejected: %v", err)
	}
	for name, ports := range map[string][]ResourcePort{
		"duplicate": {{Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}, {Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}},
		"overlap":   {{Protocol: ProtocolTCP, PortStart: 8000, PortEnd: 8010}, {Protocol: ProtocolTCP, PortStart: 8005, PortEnd: 8020}},
		"wildcard":  {{Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateResourcePorts(ResourceLocalHost, ports); err == nil {
				t.Fatal("invalid resource ports were accepted")
			}
		})
	}
	if err := ValidateResourcePorts(ResourceCustomService, []ResourcePort{{Protocol: ProtocolTCP, PortStart: 8443, PortEnd: 8443}}); err != nil {
		t.Fatalf("valid CUSTOM_SERVICE port rejected: %v", err)
	}
	for _, ports := range [][]ResourcePort{
		{{Protocol: ProtocolICMP}},
		{{Protocol: ProtocolTCP, PortStart: 8000, PortEnd: 8010}},
		{{Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}, {Protocol: ProtocolUDP, PortStart: 443, PortEnd: 443}},
	} {
		if err := ValidateResourcePorts(ResourceCustomService, ports); err == nil {
			t.Fatal("invalid CUSTOM_SERVICE port set was accepted")
		}
	}
}

func TestResourceLifecycleRequiresUsableSubnetProbeAndInvalidatesQualification(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:resources", "Resources"); err != nil {
		t.Fatal(err)
	}
	base := ResourceInput{
		ID: "resource:subnet", Name: "Keenetic LAN", Kind: ResourceLocalSubnet,
		AccessProfile: ProfileKeeneticWANRouted, LocalDestination: "192.168.50.0/24",
		Enabled: true, AdvancedScopeAcknowledged: true,
		Ports: []ResourcePort{{Protocol: ProtocolTCP, PortStart: 8443, PortEnd: 8443}},
	}
	for name, address := range map[string]string{
		"missing": "", "network": "192.168.50.0", "broadcast": "192.168.50.255", "outside": "192.168.51.10",
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			input.HealthProbeAddress = address
			if _, err := repository.CreateResource(ctx, input); err == nil {
				t.Fatalf("invalid LOCAL_SUBNET health probe %q was accepted", address)
			}
		})
	}

	base.HealthProbeAddress = "192.168.50.10"
	created, err := repository.CreateResource(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if created.HealthProbeAddress != base.HealthProbeAddress || created.HealthState != "WAITING_EXTERNAL_CONFIGURATION" || created.DesiredRouteGeneration != 1 {
		t.Fatalf("created resource = %+v", created)
	}
	if err := repository.RecordResourceProbe(ctx, ResourceProbeResult{
		ResourceID: created.ID, RouteGeneration: created.DesiredRouteGeneration,
		State: "HEALTHY", ReasonCode: "RESOURCE_SUBNET_PATH_CONFIRMED", Interface: "lan0", Gateway: "192.168.200.1",
		CheckedAt: "2026-09-01T10:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	qualified, err := repository.GetResource(ctx, created.ID)
	if err != nil || qualified.HealthState != "HEALTHY" || qualified.LastProbeRouteGeneration != 1 {
		t.Fatalf("qualified resource = %+v, %v", qualified, err)
	}
	beforeFabric := resourceFabricGeneration(t, ctx, database)
	base.Name = "Keenetic LAN renamed"
	renamed, err := repository.UpdateResource(ctx, created.ID, base)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.DesiredRouteGeneration != 1 || renamed.HealthState != "HEALTHY" || resourceFabricGeneration(t, ctx, database) != beforeFabric {
		t.Fatalf("name-only update changed projection = %+v", renamed)
	}

	base.HealthProbeAddress = "192.168.50.11"
	changed, err := repository.UpdateResource(ctx, created.ID, base)
	if err != nil {
		t.Fatal(err)
	}
	if changed.DesiredRouteGeneration != 2 || changed.HealthState != "WAITING_EXTERNAL_CONFIGURATION" || changed.LastProbeAt != "" || changed.LastProbeRouteGeneration != 0 || changed.ProbeInterface != "" {
		t.Fatalf("configuration change did not invalidate qualification = %+v", changed)
	}
	if err := repository.RecordResourceProbe(ctx, ResourceProbeResult{
		ResourceID: created.ID, RouteGeneration: 1, State: "HEALTHY", ReasonCode: "RESOURCE_SUBNET_PATH_CONFIRMED",
		Interface: "lan0", Gateway: "192.168.200.1", CheckedAt: "2026-09-01T10:01:00Z",
	}); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("stale resource probe = %v", err)
	}
	if err := repository.DeleteResource(ctx, created.ID); err == nil {
		t.Fatal("enabled resource was deleted")
	}
	base.Enabled = false
	disabled, err := repository.UpdateResource(ctx, created.ID, base)
	if err != nil || disabled.HealthReasonCode != "RESOURCE_DISABLED" {
		t.Fatalf("disable resource = %+v, %v", disabled, err)
	}
	if err := repository.DeleteResource(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetResource(ctx, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted resource lookup = %v", err)
	}
}

func TestResourceProbeAdvancesProjectionOnlyAcrossHealthyBoundary(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:health", "Health"); err != nil {
		t.Fatal(err)
	}
	item, err := repository.CreateResource(ctx, ResourceInput{
		ID: "resource:health", Name: "Host", Kind: ResourceLocalHost,
		AccessProfile: ProfileDedicatedLAN, LocalDestination: "192.168.60.10", Enabled: true,
		Ports: []ResourcePort{{Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := resourceFabricGeneration(t, ctx, database)
	record := func(state, reason string) {
		t.Helper()
		if err := repository.RecordResourceProbe(ctx, ResourceProbeResult{
			ResourceID: item.ID, RouteGeneration: item.DesiredRouteGeneration, State: state,
			ReasonCode: reason, Interface: "mgmt0", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatal(err)
		}
	}
	record("FAILED", "RESOURCE_TRANSPORT_UNREACHABLE")
	if got := resourceFabricGeneration(t, ctx, database); got != initial {
		t.Fatalf("non-healthy to non-healthy transition advanced generation: %d -> %d", initial, got)
	}
	record("HEALTHY", "RESOURCE_PROBE_PASSED")
	if got := resourceFabricGeneration(t, ctx, database); got != initial+1 {
		t.Fatalf("transition into HEALTHY generation = %d, want %d", got, initial+1)
	}
	record("HEALTHY", "RESOURCE_PROBE_PASSED_AGAIN")
	if got := resourceFabricGeneration(t, ctx, database); got != initial+1 {
		t.Fatalf("HEALTHY refresh advanced generation: %d", got)
	}
	record("DEGRADED", "RESOURCE_TRANSPORT_UNREACHABLE")
	if got := resourceFabricGeneration(t, ctx, database); got != initial+2 {
		t.Fatalf("transition out of HEALTHY generation = %d, want %d", got, initial+2)
	}
}

func TestResourcePortsAndPublicationsRemainBounded(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Bounded"); err != nil {
		t.Fatal(err)
	}
	vps, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:bounded", Name: "VPS", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	link := createTestLink(t, ctx, repository, "link:bounded", vps, "10.82.0.0/24", "10.82.0.2", "10.82.0.1")
	resource, err := repository.CreateResource(ctx, ResourceInput{
		ID: "resource:bounded", Name: "Bounded service", Kind: ResourceLocalHost,
		AccessProfile: ProfileDedicatedLAN, LocalDestination: "192.168.60.10", Enabled: true,
		Ports: []ResourcePort{{Protocol: ProtocolTCP, PortStart: 8000, PortEnd: 8010}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateResourcePublication(ctx, ResourcePublicationInput{
		ID: "publication:outside", ResourceID: resource.ID, LinkID: link.ID, PublishedAlias: "10.97.1.10/32", Enabled: true,
	}); err == nil {
		t.Fatal("alias outside selected VPS pool was accepted")
	}
	publication, err := repository.CreateResourcePublication(ctx, ResourcePublicationInput{
		ID: "publication:bounded", ResourceID: resource.ID, LinkID: link.ID, PublishedAlias: "10.96.1.10/32", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec := resourceFabricSpec(t, ctx, database, repository); len(spec.Resources) != 0 || len(spec.Publications) != 0 {
		t.Fatalf("unqualified resource entered host projection: %+v", spec)
	}
	if err := repository.RecordResourceProbe(ctx, ResourceProbeResult{
		ResourceID: resource.ID, RouteGeneration: resource.DesiredRouteGeneration,
		State: "HEALTHY", ReasonCode: "RESOURCE_PROBE_PASSED", Interface: "mgmt0", CheckedAt: "2026-09-01T12:30:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if spec := resourceFabricSpec(t, ctx, database, repository); len(spec.Resources) != 1 || len(spec.Publications) != 1 {
		t.Fatalf("fresh healthy resource missing from host projection: %+v", spec)
	}
	if _, err := repository.CreateResourcePublication(ctx, ResourcePublicationInput{
		ID: "publication:overlap", ResourceID: resource.ID, LinkID: link.ID, PublishedAlias: "10.96.1.10/32", Enabled: true,
	}); err == nil {
		t.Fatal("overlapping publication alias was accepted")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at)
VALUES('admin:bounded','Admin','ADMIN',1,'ACTIVE',?,?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO management_admin_vps_peers(id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at)
VALUES('peer:bounded','admin:bounded',?,?,?,'CONFIGURED',1,0,?,?)`, vps.ID, testPublicKey(t), "10.81.0.10", stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateResourceACL(ctx, ResourceACLInput{
		ID: "acl:outside", AdminID: "admin:bounded", ResourceID: resource.ID,
		Protocol: ProtocolTCP, PortStart: 7999, PortEnd: 8001, Enabled: true,
	}); err == nil {
		t.Fatal("ACL outside declared resource ports was accepted")
	}
	acl, err := repository.CreateResourceACL(ctx, ResourceACLInput{
		ID: "acl:bounded", AdminID: "admin:bounded", ResourceID: resource.ID,
		Protocol: ProtocolTCP, PortStart: 8001, PortEnd: 8002, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec := resourceFabricSpec(t, ctx, database, repository); len(spec.ACL) != 1 {
		t.Fatalf("bounded ACL missing from host projection: %+v", spec)
	}
	if _, err := repository.UpdateResource(ctx, resource.ID, ResourceInput{
		Name: resource.Name, Kind: resource.Kind, AccessProfile: resource.AccessProfile,
		LocalDestination: resource.LocalDestination, Enabled: true,
		Ports: []ResourcePort{{Protocol: ProtocolTCP, PortStart: 8005, PortEnd: 8010}},
	}); err == nil {
		t.Fatal("resource ports were narrowed past an enabled ACL")
	}
	if err := repository.DeleteResourceACL(ctx, acl.ID); err == nil {
		t.Fatal("enabled ACL was deleted")
	}
	if err := repository.DeleteResourcePublication(ctx, publication.ID); err == nil {
		t.Fatal("enabled publication was deleted")
	}
	if err := repository.RecordResourceProbe(ctx, ResourceProbeResult{
		ResourceID: resource.ID, RouteGeneration: resource.DesiredRouteGeneration,
		State: "DEGRADED", ReasonCode: "RESOURCE_TRANSPORT_UNREACHABLE", Interface: "mgmt0", CheckedAt: "2026-09-01T12:31:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if spec := resourceFabricSpec(t, ctx, database, repository); len(spec.Resources) != 0 || len(spec.Publications) != 0 || len(spec.ACL) != 0 {
		t.Fatalf("unhealthy resource remained in host projection: %+v", spec)
	}
}

func resourceFabricGeneration(t *testing.T, ctx context.Context, database *sql.DB) int64 {
	t.Helper()
	var generation int64
	if err := database.QueryRowContext(ctx, "SELECT desired_generation FROM management_fabric_generations WHERE singleton_id=1").Scan(&generation); err != nil {
		t.Fatal(err)
	}
	return generation
}

func resourceFabricSpec(t *testing.T, ctx context.Context, database *sql.DB, repository *Repository) FabricSpec {
	t.Helper()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	spec, _, err := repository.fabricSpecTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
