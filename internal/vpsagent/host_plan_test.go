package vpsagent

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gateway-vpn/internal/wgingress"
)

func TestVPSHostPlanIsDeterministicTypedAndDefaultDenyReady(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	gateway := pairTestGateway(t, repository, "10.82.0.0/30")
	adminPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := repository.CreateAdmin(ctx, AdminCreateInput{Name: "Ноутбук", PublicKey: adminPair.Public, AssignedAddress: "10.81.0.10", KeyMode: "EXTERNAL"})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := repository.CreateResource(ctx, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "gateway:web", DisplayName: "Gateway WebUI",
		ResourceKind: "GATEWAY_SERVICE", LocalDestination: "192.168.200.2", PublishedAlias: "10.96.0.2",
		AccessProfile: "GATEWAY_ONLY", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := repository.CreateACL(ctx, ACLInput{AdminPeerID: admin.ID, PublicationID: resource.ID, Protocol: "TCP", PortStart: 443, PortEnd: 443})
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.RenderHostPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.RenderHostPlan(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("host plan is not deterministic: equal=%t error=%v", reflect.DeepEqual(first, second), err)
	}
	if first.InterfaceName != "wg-mgmt" || first.ListenPort != 51821 || first.RouteProtocol != 186 || !reflect.DeepEqual(first.InterfaceAddresses, []string{"10.80.0.1/24", "10.82.0.1/30"}) {
		t.Fatalf("host plan ownership/address = %+v", first)
	}
	if len(first.Peers) != 2 || len(first.ResourceRoutes) != 1 || len(first.ACL) != 1 || len(first.HubAdminSources) != 1 {
		t.Fatalf("host plan contour = %+v", first)
	}
	peers := map[string]VPSHostPeer{}
	for _, peer := range first.Peers {
		peers[peer.ID] = peer
		for _, allowed := range peer.AllowedIPs {
			if allowed == "0.0.0.0/0" {
				t.Fatal("wildcard AllowedIPs reached VPS host plan")
			}
		}
	}
	if !reflect.DeepEqual(peers[admin.ID].AllowedIPs, []string{"10.81.0.10/32"}) || !reflect.DeepEqual(peers[gateway.ID].AllowedIPs, []string{"10.82.0.2/32", "10.96.0.2/32"}) {
		t.Fatalf("host plan peer AllowedIPs = %+v", peers)
	}
	if peers[gateway.ID].WebUIPort != 8443 || peers[admin.ID].WebUIPort != 0 {
		t.Fatalf("host plan WebUI ports = %+v", peers)
	}
	rule := first.ACL[0]
	if rule.ID != grant.ID || rule.Source != "10.81.0.10/32" || rule.Destination != "10.96.0.2/32" || rule.Protocol != "TCP" || rule.PortStart != 443 || rule.PortEnd != 443 {
		t.Fatalf("host plan ACL = %+v", rule)
	}
	encoded, _ := json.Marshal(first)
	for _, forbidden := range []string{"private_key", "secret_ref", "command", "executable", "0.0.0.0/0"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("host plan exposed forbidden value %q: %s", forbidden, encoded)
		}
	}
	if err := repository.RevokeAdmin(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	withoutAdmin, err := repository.RenderHostPlan(ctx)
	if err != nil || len(withoutAdmin.HubAdminSources) != 0 || len(withoutAdmin.ACL) != 0 || len(withoutAdmin.Peers) != 1 {
		t.Fatalf("revoked administrator survived host plan: %+v, %v", withoutAdmin, err)
	}
}

func TestVPSHostPlanRetainsHubAddressWithoutGateway(t *testing.T) {
	repository := testHubRepository(t)
	plan, err := repository.RenderHostPlan(context.Background())
	if err != nil || !reflect.DeepEqual(plan.InterfaceAddresses, []string{VPSHubAddressPrefix}) || len(plan.Peers) != 0 {
		t.Fatalf("empty topology plan = %+v, %v", plan, err)
	}
}

func TestVPSHostPlanRelaysEndToEndAdminWithoutTrustingIt(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	gateway := pairTestGateway(t, repository, "10.82.0.0/30")
	adminPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := repository.CreateAdmin(ctx, AdminCreateInput{
		Name: "End-to-end administrator", PublicKey: adminPair.Public,
		AssignedAddress: "10.81.0.10", KeyMode: "EXTERNAL", TrustMode: TrustEndToEndRelay,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := repository.CreateResource(ctx, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "gateway:web", DisplayName: "Gateway WebUI",
		ResourceKind: "GATEWAY_SERVICE", LocalDestination: "192.168.200.2", PublishedAlias: "10.96.0.2",
		AccessProfile: "GATEWAY_ONLY", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateACL(ctx, ACLInput{AdminPeerID: admin.ID, PublicationID: resource.ID, Protocol: "TCP", PortStart: 443, PortEnd: 443}); err != nil {
		t.Fatal(err)
	}
	relay, err := repository.CreateAdminRelay(ctx, AdminRelayInput{
		ID: "relay:a", GatewayPeerID: gateway.ID, PublicEndpointHost: "vps.example.net",
		PublicBindAddress: "203.0.113.10", PublicUDPPort: 51823,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := repository.RenderHostPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Peers) != 1 || plan.Peers[0].Kind != "GATEWAY" || len(plan.HubAdminSources) != 0 || len(plan.ACL) != 0 {
		t.Fatalf("VPS trusted an end-to-end administrator: %+v", plan)
	}
	if strings.Contains(strings.Join(plan.Peers[0].AllowedIPs, ","), "10.81.0.10") {
		t.Fatalf("end-to-end administrator reached outer AllowedIPs: %+v", plan.Peers[0])
	}
	if len(plan.AdminRelays) != 1 {
		t.Fatalf("VPS relay projection count = %d", len(plan.AdminRelays))
	}
	projected := plan.AdminRelays[0]
	if projected.ID != relay.ID || projected.GatewayAddress != gateway.AssignedAddress ||
		projected.VPSSourceAddress != gateway.RemoteAddress || projected.DestinationPort != AdminRelayDestinationPort {
		t.Fatalf("VPS relay projection = %+v", projected)
	}
}

func TestVPSRejectsManagedEndToEndAdministratorKey(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	firstPair, _ := wgingress.GenerateKeyPair()
	if _, err := repository.CreateAdmin(ctx, AdminCreateInput{
		Name: "Invalid managed relay", PublicKey: firstPair.Public, AssignedAddress: "10.81.0.10",
		KeyMode: "MANAGED", PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/admin/invalid.key",
		TrustMode: TrustEndToEndRelay,
	}); err == nil {
		t.Fatal("VPS accepted a managed private key for an end-to-end administrator")
	}
	secondPair, _ := wgingress.GenerateKeyPair()
	managed, err := repository.CreateAdmin(ctx, AdminCreateInput{
		Name: "Managed routed administrator", PublicKey: secondPair.Public, AssignedAddress: "10.81.0.11",
		KeyMode: "MANAGED", PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/admin/routed.key",
		TrustMode: TrustRoutedHub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetAdminTrustMode(ctx, managed.ID, TrustEndToEndRelay); err == nil {
		t.Fatal("VPS converted a managed administrator into end-to-end trust")
	}
}

func TestVPSHostPlanRejectsCorruptedPublicKeyAndGeneration(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	gateway := pairTestGateway(t, repository, "10.82.0.0/30")
	if _, err := repository.Database.ExecContext(ctx, "UPDATE gateway_peers SET public_key='invalid' WHERE id=?", gateway.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RenderHostPlan(ctx); err == nil {
		t.Fatal("corrupted Gateway public key reached host plan")
	}
	pair, _ := wgingress.GenerateKeyPair()
	if _, err := repository.Database.ExecContext(ctx, "UPDATE gateway_peers SET public_key=? WHERE id=?", pair.Public, gateway.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Database.ExecContext(ctx, "UPDATE vps_settings SET value_json='{}' WHERE key='fabric'"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RenderHostPlan(ctx); err == nil {
		t.Fatal("invalid fabric generation reached host plan")
	}
}
