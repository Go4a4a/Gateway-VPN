package gatewayfabric

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
)

type gatewayInterface struct {
	address, publicKey, fwmark, listenPort string
	peers                                  map[string]string
}

type gatewayRoute struct {
	destination, device, gateway, table string
}

type gatewayExecutor struct {
	interfaces        map[string]*gatewayInterface
	routes            map[string]gatewayRoute
	firewall          string
	failACLLoad       bool
	failAdminIdentity bool
	failedAdminPublic string
	keepRouteOnDelete bool
	keepLinkOnDelete  bool
	requests          []platformexec.Request
}

func (executor *gatewayExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	command := strings.TrimSuffix(filepath.Base(request.Executable), ".exe")
	args := strings.Join(request.Arguments, " ")
	switch {
	case command == "nft" && args == "--check --file -":
		if !strings.Contains(string(request.Stdin), "management_fabric_generation") {
			return platformexec.Result{}, errors.New("invalid management firewall")
		}
		return platformexec.Result{}, nil
	case command == "nft" && args == "--file -":
		if executor.failACLLoad && strings.Contains(string(request.Stdin), "management ACL") {
			executor.failACLLoad = false
			return platformexec.Result{}, errors.New("injected management firewall failure")
		}
		executor.firewall = string(request.Stdin)
		return platformexec.Result{}, nil
	case command == "nft" && args == "list table inet gateway_vpn":
		return platformexec.Result{Stdout: executor.firewall}, nil
	case command == "ip" && len(request.Arguments) == 5 && strings.HasPrefix(args, "-json link show dev "):
		name := request.Arguments[4]
		if _, exists := executor.interfaces[name]; !exists {
			return platformexec.Result{}, errors.New("link missing")
		}
		return platformexec.Result{Stdout: fmt.Sprintf(`[{"ifname":%q}]`, name)}, nil
	case command == "ip" && args == "-json link show":
		rows := make([]map[string]string, 0, len(executor.interfaces))
		for name := range executor.interfaces {
			rows = append(rows, map[string]string{"ifname": name})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i]["ifname"] < rows[j]["ifname"] })
		content, _ := json.Marshal(rows)
		return platformexec.Result{Stdout: string(content)}, nil
	case command == "ip" && strings.HasPrefix(args, "link add name "):
		name := request.Arguments[3]
		if _, exists := executor.interfaces[name]; exists {
			return platformexec.Result{}, errors.New("link exists")
		}
		executor.interfaces[name] = &gatewayInterface{peers: map[string]string{}}
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "-4 address replace "):
		name := request.Arguments[5]
		item := executor.interfaces[name]
		if item == nil {
			return platformexec.Result{}, errors.New("link missing")
		}
		item.address = request.Arguments[3]
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "link set dev "):
		if executor.interfaces[request.Arguments[3]] == nil {
			return platformexec.Result{}, errors.New("link missing")
		}
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "link del dev "):
		name := request.Arguments[3]
		if executor.keepLinkOnDelete {
			return platformexec.Result{}, errors.New("injected link deletion failure")
		}
		delete(executor.interfaces, name)
		for key, route := range executor.routes {
			if route.device == name {
				delete(executor.routes, key)
			}
		}
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "-4 route replace "):
		route := parseGatewayRoute(request.Arguments)
		executor.routes[gatewayRouteKey(route)] = route
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "-4 route del "):
		route := parseGatewayRoute(request.Arguments)
		if executor.keepRouteOnDelete {
			return platformexec.Result{}, errors.New("injected route deletion failure")
		}
		delete(executor.routes, gatewayRouteKey(route))
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "-json -4 route get "):
		destination := request.Arguments[4]
		mark := request.Arguments[6]
		for _, route := range executor.routes {
			if strings.TrimSuffix(route.destination, "/32") != destination || route.table == "main" {
				continue
			}
			for _, item := range executor.interfaces {
				if item.fwmark == mark {
					content, _ := json.Marshal([]map[string]any{{"dev": route.device, "gateway": route.gateway, "table": route.table}})
					return platformexec.Result{Stdout: string(content)}, nil
				}
			}
		}
		return platformexec.Result{}, errors.New("policy route missing")
	case command == "ip" && strings.HasPrefix(args, "-json -4 route show table "):
		table, destination, device := request.Arguments[5], request.Arguments[7], request.Arguments[9]
		key := gatewayRouteKey(gatewayRoute{destination: destination, device: device, table: table})
		route, exists := executor.routes[key]
		if !exists {
			return platformexec.Result{Stdout: "[]"}, nil
		}
		content, _ := json.Marshal([]map[string]any{{"dst": route.destination, "dev": route.device, "gateway": route.gateway, "protocol": 186}})
		return platformexec.Result{Stdout: string(content)}, nil
	case command == "ip" && strings.HasPrefix(args, "-json -4 address show dev "):
		name := request.Arguments[5]
		item := executor.interfaces[name]
		if item == nil || item.address == "" {
			return platformexec.Result{}, errors.New("address missing")
		}
		prefix := netip.MustParsePrefix(item.address)
		content, _ := json.Marshal([]map[string]any{{"addr_info": []map[string]any{{"family": "inet", "local": prefix.Addr().String(), "prefixlen": prefix.Bits()}}}})
		return platformexec.Result{Stdout: string(content)}, nil
	case command == "wg" && strings.HasPrefix(args, "set "):
		name := request.Arguments[1]
		item := executor.interfaces[name]
		if item == nil {
			return platformexec.Result{}, errors.New("link missing")
		}
		if item.peers == nil {
			item.peers = map[string]string{}
		}
		for index := 2; index < len(request.Arguments); index++ {
			switch request.Arguments[index] {
			case "private-key":
				private, err := os.ReadFile(request.Arguments[index+1])
				if err != nil {
					return platformexec.Result{}, err
				}
				publicKey, _ := wgingress.PublicKey(strings.TrimSpace(string(private)))
				if name == managementfabric.AdminInterfaceName && executor.failAdminIdentity && publicKey != item.publicKey {
					executor.failAdminIdentity = false
					executor.failedAdminPublic = publicKey
					return platformexec.Result{}, errors.New("injected administrator identity apply failure")
				}
				item.publicKey = publicKey
				index++
			case "fwmark":
				item.fwmark = request.Arguments[index+1]
				index++
			case "listen-port":
				item.listenPort = request.Arguments[index+1]
				index++
			case "peer":
				key := request.Arguments[index+1]
				index++
				if index+1 < len(request.Arguments) && request.Arguments[index+1] == "remove" {
					delete(item.peers, key)
					index++
				} else {
					item.peers[key] = ""
				}
			}
		}
		return platformexec.Result{}, nil
	case command == "wg" && strings.HasPrefix(args, "show "):
		item := executor.interfaces[request.Arguments[1]]
		if item == nil {
			return platformexec.Result{}, errors.New("link missing")
		}
		switch request.Arguments[2] {
		case "public-key":
			return platformexec.Result{Stdout: item.publicKey + "\n"}, nil
		case "peers":
			peers := make([]string, 0, len(item.peers))
			for peer := range item.peers {
				peers = append(peers, peer)
			}
			sort.Strings(peers)
			return platformexec.Result{Stdout: strings.Join(peers, "\n") + "\n"}, nil
		case "fwmark":
			value, _ := strconv.ParseInt(item.fwmark, 10, 64)
			return platformexec.Result{Stdout: fmt.Sprintf("0x%x\n", value)}, nil
		case "listen-port":
			return platformexec.Result{Stdout: item.listenPort + "\n"}, nil
		}
	}
	return platformexec.Result{}, fmt.Errorf("unexpected command: %s %s", request.Executable, args)
}

func parseGatewayRoute(arguments []string) gatewayRoute {
	route := gatewayRoute{destination: arguments[3], table: "main"}
	for index := 4; index+1 < len(arguments); index++ {
		switch arguments[index] {
		case "via":
			route.gateway = arguments[index+1]
		case "dev":
			route.device = arguments[index+1]
		case "table":
			route.table = arguments[index+1]
		}
	}
	return route
}

func gatewayRouteKey(route gatewayRoute) string {
	return route.table + "\x00" + route.destination + "\x00" + route.device
}

func TestGatewayApplierCommitsAndRollsBackExactOwnedProjection(t *testing.T) {
	fixture := newGatewayApplierFixture(t)
	ctx := context.Background()
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	needed, reason, err := fixture.applier.NeedsApply(ctx)
	if err != nil || needed || reason != "HEALTHY" {
		t.Fatalf("healthy Gateway fabric = %t %s %v", needed, reason, err)
	}
	oldFirewall := fixture.executor.firewall
	oldInterfacePointer := fixture.executor.interfaces["gvm1"]
	oldInterface := *fixture.executor.interfaces["gvm1"]
	_, oldApplied, _, _, _ := fixture.repository.GatewayFabricGenerations(ctx)
	if _, err := fixture.database.ExecContext(ctx, `
UPDATE management_resource_acl SET port_start=9443,port_end=9443,generation=generation+1 WHERE id='acl:a';
UPDATE management_fabric_generations SET desired_generation=desired_generation+1,state='PENDING' WHERE singleton_id=1;`); err != nil {
		t.Fatal(err)
	}
	fixture.executor.failACLLoad = true
	if err := fixture.applier.Apply(ctx); err == nil || !strings.Contains(err.Error(), "safely rolled back") {
		t.Fatalf("failed Gateway apply = %v", err)
	}
	desired, applied, state, code, err := fixture.repository.GatewayFabricGenerations(ctx)
	if err != nil || desired != oldApplied+1 || applied != oldApplied || state != "PENDING_RETRY" || code != "HOST_APPLY_FAILED" {
		t.Fatalf("rollback generations = %d/%d %s %s, %v", applied, desired, state, code, err)
	}
	current := fixture.executor.interfaces["gvm1"]
	if current == nil || !reflect.DeepEqual(*current, oldInterface) || fixture.executor.firewall != oldFirewall || exists(fixture.applier.journalPath()) {
		t.Fatalf("previous runtime was not restored: interface=%+v firewall=%q journal=%t", current, fixture.executor.firewall, exists(fixture.applier.journalPath()))
	}
	if current != oldInterfacePointer {
		t.Fatal("ACL-only failed apply reset an unrelated WireGuard interface")
	}
	for _, request := range fixture.executor.requests {
		joined := strings.ToLower(request.Executable + " " + strings.Join(request.Arguments, " ") + " " + string(request.Stdin))
		for _, forbidden := range []string{"flush ruleset", "delete table", "amnezia", "docker", "ufw", "firewalld"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("foreign mutation token %q in %s", forbidden, joined)
			}
		}
	}
}

func TestGatewayRuntimeLinkDeltaPreservesUnchangedLinks(t *testing.T) {
	first := gatewayPlanFixture(t).Links[0]
	second := first
	second.LinkID = "link:b"
	second.VPSID = "vps:b"
	second.InterfaceName = "gvm2"
	second.Routes = append([]managementfabric.RenderedRoute(nil), first.Routes...)
	for index := range second.Routes {
		second.Routes[index].LinkID = second.LinkID
		second.Routes[index].InterfaceName = second.InterfaceName
	}
	oldPlan := managementfabric.GatewayHostPlan{Generation: 7, RouteProtocol: managementfabric.OwnedRouteProtocol, Links: []managementfabric.GatewayHostLink{first, second}}
	newPlan := managementfabric.GatewayHostPlan{Generation: 8, RouteProtocol: managementfabric.OwnedRouteProtocol, Links: []managementfabric.GatewayHostLink{second}}

	remove, apply := runtimeLinkDelta(oldPlan, newPlan)
	if len(remove.Links) != 1 || remove.Links[0].InterfaceName != "gvm1" || len(apply.Links) != 0 {
		t.Fatalf("disable delta remove=%+v apply=%+v", remove.Links, apply.Links)
	}

	changed := second
	changed.EndpointPort++
	remove, apply = runtimeLinkDelta(newPlan, managementfabric.GatewayHostPlan{Generation: 9, RouteProtocol: managementfabric.OwnedRouteProtocol, Links: []managementfabric.GatewayHostLink{changed}})
	if len(remove.Links) != 1 || remove.Links[0].InterfaceName != "gvm2" || len(apply.Links) != 1 || apply.Links[0].EndpointPort != changed.EndpointPort {
		t.Fatalf("changed-link delta remove=%+v apply=%+v", remove.Links, apply.Links)
	}
}

func TestGatewayApplierUpdatesAdminPeerWithoutRecreatingContour(t *testing.T) {
	fixture := newGatewayApplierFixture(t)
	ctx := context.Background()
	innerGateway, _ := wgingress.GenerateKeyPair()
	innerAdmin, _ := wgingress.GenerateKeyPair()
	stamp := "2026-08-30T16:05:00Z"
	statements := []struct {
		query string
		args  []any
	}{
		{`UPDATE management_admin_vps_peers
SET trust_mode='END_TO_END_RELAY',desired_generation=desired_generation+1,updated_at=? WHERE id='peer:a'`, []any{stamp}},
		{`INSERT INTO management_admin_contour(
  singleton_id,enabled,interface_name,private_key_secret_ref,public_key,subnet,gateway_address,
  listen_port,desired_generation,applied_generation,state,last_error_code,created_at,updated_at
) VALUES(1,1,'wg-admin','/var/lib/gateway-vpn/secrets/management/wg-admin.key',?,'10.83.0.0/24','10.83.0.1',51822,1,0,'CONFIGURED','',?,?)`, []any{innerGateway.Public, stamp, stamp}},
		{`INSERT INTO management_admin_relays(
  id,link_id,enabled,public_endpoint_host,public_bind_address,public_udp_port,destination_port,
  rate_limit_per_second,burst_packets,desired_generation,applied_generation,state,last_error_code,created_at,updated_at
) VALUES('relay:a','link:a',1,'vps-a.example.net','203.0.113.10',51823,51822,100,200,1,0,'CONFIGURED','',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_admin_tunnels(
  id,admin_id,relay_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at
) VALUES('tunnel:a','admin:a','relay:a',?,'10.83.0.10','CONFIGURED',1,0,?,?)`, []any{innerAdmin.Public, stamp, stamp}},
		{`UPDATE management_fabric_generations
SET desired_generation=desired_generation+1,state='PENDING',updated_at=? WHERE singleton_id=1`, []any{stamp}},
	}
	for _, statement := range statements {
		if _, err := fixture.database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(fixture.applier.Paths.SecretRoot, "wg-admin.key"), []byte(innerGateway.Private+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	contour := fixture.executor.interfaces[managementfabric.AdminInterfaceName]
	if contour == nil || len(contour.peers) != 1 {
		t.Fatalf("initial administrator contour = %+v", contour)
	}
	requestOffset := len(fixture.executor.requests)
	replacement, _ := wgingress.GenerateKeyPair()
	if _, err := fixture.database.ExecContext(ctx, `
UPDATE management_admin_tunnels
SET public_key=?,desired_generation=desired_generation+1,updated_at=? WHERE id='tunnel:a';
UPDATE management_fabric_generations
SET desired_generation=desired_generation+1,state='PENDING',updated_at=? WHERE singleton_id=1`, replacement.Public, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if fixture.executor.interfaces[managementfabric.AdminInterfaceName] != contour {
		t.Fatal("peer-only update recreated the wg-admin interface")
	}
	if len(contour.peers) != 1 {
		t.Fatalf("peer-only update left stale peers: %+v", contour.peers)
	}
	if _, exists := contour.peers[replacement.Public]; !exists {
		t.Fatalf("replacement administrator peer missing: %+v", contour.peers)
	}
	for _, request := range fixture.executor.requests[requestOffset:] {
		joined := strings.Join(request.Arguments, " ")
		if strings.Contains(joined, "link del dev wg-admin") || strings.Contains(joined, "link add name wg-admin") {
			t.Fatalf("peer-only update reset wg-admin: %s", joined)
		}
	}
}

func TestGatewayAdminIdentityRotationFailureRestoresPreviousIdentityAndRuntime(t *testing.T) {
	fixture := newGatewayApplierFixture(t)
	ctx := context.Background()
	before, err := fixture.applier.ConfigureAdminContour(ctx, managementfabric.AdminContourRequest{
		Enabled: true, Subnet: "10.83.0.0/24", GatewayAddress: "10.83.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(fixture.applier.Paths.SecretRoot, "wg-admin.key")
	oldPrivateBytes, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	oldPrivate := strings.TrimSpace(string(oldPrivateBytes))
	oldReceipt, found, err := fixture.applier.readReceipt()
	if err != nil || !found {
		t.Fatalf("read previous receipt = %t %v", found, err)
	}
	oldRuntime := *fixture.executor.interfaces[managementfabric.AdminInterfaceName]
	oldRuntime.peers = make(map[string]string, len(fixture.executor.interfaces[managementfabric.AdminInterfaceName].peers))
	for key, value := range fixture.executor.interfaces[managementfabric.AdminInterfaceName].peers {
		oldRuntime.peers[key] = value
	}
	oldFirewall := fixture.executor.firewall

	fixture.executor.failAdminIdentity = true
	_, err = fixture.applier.RotateAdminContourIdentity(ctx)
	if err == nil || !strings.Contains(err.Error(), "identity rotation failed and rollback was requested") {
		t.Fatalf("rotation failure = %v", err)
	}
	rotationErr := err
	failedPublic := fixture.executor.failedAdminPublic
	if failedPublic == "" || failedPublic == before.PublicKey {
		t.Fatalf("injected candidate public identity = %q", failedPublic)
	}
	for _, forbidden := range []string{oldPrivate, failedPublic, secretPath, managementfabric.AdminPrivateKeySecretRef} {
		if forbidden != "" && strings.Contains(err.Error(), forbidden) {
			t.Fatalf("rotation failure exposes identity material or path %q: %v", forbidden, err)
		}
	}

	privateBytes, err := os.ReadFile(secretPath)
	if err != nil || strings.TrimSpace(string(privateBytes)) != oldPrivate {
		t.Fatalf("previous private identity was not restored: err=%v", err)
	}
	after, err := fixture.repository.GetAdminContour(ctx)
	if err != nil || after.PublicKey != before.PublicKey {
		t.Fatalf("durable public identity was not restored: before=%+v after=%+v err=%v", before, after, err)
	}
	receipt, found, err := fixture.applier.readReceipt()
	if err != nil || !found || receipt.Generation != oldReceipt.Generation {
		t.Fatalf("previous runtime generation was not restored: before=%d after=%d found=%t err=%v", oldReceipt.Generation, receipt.Generation, found, err)
	}
	runtimeContour := fixture.executor.interfaces[managementfabric.AdminInterfaceName]
	if runtimeContour == nil || !reflect.DeepEqual(*runtimeContour, oldRuntime) || fixture.executor.firewall != oldFirewall {
		t.Fatalf("previous administrator runtime was not restored: contour=%+v firewall_changed=%t rotation_error=%v", runtimeContour, fixture.executor.firewall != oldFirewall, rotationErr)
	}
	if runtimeContour.publicKey == failedPublic || after.PublicKey == failedPublic {
		t.Fatalf("failed candidate identity remained active: runtime=%q durable=%q", runtimeContour.publicKey, after.PublicKey)
	}
	needed, reason, err := fixture.applier.NeedsApply(ctx)
	if err != nil || needed || reason != "HEALTHY" {
		t.Fatalf("restored administrator contour is not healthy: needed=%t reason=%s err=%v", needed, reason, err)
	}
}

func TestGatewayOwnedRouteParsersAcceptKernelFilteredHostRouteForms(t *testing.T) {
	if !exactOwnedEndpointRoute(`[{"dst":"172.30.1.1","gateway":"172.30.1.1"}]`, "172.30.1.1/32", "up1", "172.30.1.1") {
		t.Fatal("bare kernel endpoint host route was rejected")
	}
	if !exactOwnedRoute(`[{"dst":"10.81.0.10","dev":"gvm1","protocol":"bgp"}]`, "10.81.0.10/32", "gvm1") {
		t.Fatal("bare kernel owned host route was rejected")
	}
	if exactOwnedEndpointRoute(`[{"dst":"172.30.1.2","gateway":"172.30.1.1"}]`, "172.30.1.1/32", "up1", "172.30.1.1") {
		t.Fatal("different endpoint host route was accepted")
	}
}

func TestGatewayApplierRemovesDisabledLinkAndRejectsStaleReservedInterface(t *testing.T) {
	fixture := newGatewayApplierFixture(t)
	ctx := context.Background()
	fixture.executor.interfaces["gvm9"] = &gatewayInterface{publicKey: "foreign-reserved-name"}
	if err := fixture.applier.Apply(ctx); err == nil || !strings.Contains(err.Error(), "outside the applied receipt") {
		t.Fatalf("orphan reserved interface was not rejected: %v", err)
	}
	if fixture.executor.firewall != "table inet gateway_vpn {}" {
		t.Fatal("preflight conflict changed the firewall")
	}
	delete(fixture.executor.interfaces, "gvm9")
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(ctx, `
UPDATE management_links SET enabled=0,state='DISABLED',updated_at='2026-08-30T16:10:00Z' WHERE id='link:a';
UPDATE management_fabric_generations SET desired_generation=desired_generation+1,state='PENDING',updated_at='2026-08-30T16:10:00Z' WHERE singleton_id=1;`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if _, exists := fixture.executor.interfaces["gvm1"]; exists || len(fixture.executor.routes) != 0 {
		t.Fatalf("disabled link left runtime objects: interfaces=%v routes=%v", fixture.executor.interfaces, fixture.executor.routes)
	}
	needed, reason, err := fixture.applier.NeedsApply(ctx)
	if err != nil || needed || reason != "HEALTHY" {
		t.Fatalf("disabled-link projection = %t %s %v", needed, reason, err)
	}
}

func TestGatewayApplierDoesNotIgnoreOwnedRouteOrInterfaceRemovalFailure(t *testing.T) {
	cases := map[string]func(*gatewayExecutor){
		"route":     func(executor *gatewayExecutor) { executor.keepRouteOnDelete = true },
		"interface": func(executor *gatewayExecutor) { executor.keepLinkOnDelete = true },
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newGatewayApplierFixture(t)
			ctx := context.Background()
			if err := fixture.applier.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			receipt, found, err := fixture.applier.readReceipt()
			if err != nil || !found {
				t.Fatalf("read applied receipt = %t %v", found, err)
			}
			configure(fixture.executor)
			err = fixture.applier.removePlan(ctx, receipt.Plan)
			if err == nil || !strings.Contains(err.Error(), "remained") {
				t.Fatalf("persistent %s deletion failure was ignored: %v", name, err)
			}
		})
	}
}

type gatewayApplierFixture struct {
	database   *sql.DB
	repository *managementfabric.Repository
	applier    *Applier
	executor   *gatewayExecutor
}

func newGatewayApplierFixture(t *testing.T) gatewayApplierFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(root, "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := managementfabric.NewRepository(database, []managementfabric.ReservedPrefix{{Owner: "LAN", CIDR: "192.168.200.0/24"}})
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	remote, _ := wgingress.GenerateKeyPair()
	local, _ := wgingress.GenerateKeyPair()
	vps, err := repository.CreateVPS(ctx, managementfabric.CreateVPSInput{ID: "vps:a", Name: "VPS", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: remote.Public, AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem:a", Name: "Operator", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem:a", modem.LeaseInput{InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	link, err := repository.CreateLink(ctx, managementfabric.CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link-a.key",
		LocalPublicKey:           local.Public, RemotePublicKey: remote.Public, UplinkPolicy: managementfabric.UplinkAuto,
		PersistentKeepalive: 25, Endpoints: []managementfabric.EndpointSpec{{Host: "203.0.113.10", Port: 51821}},
	})
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := wgingress.GenerateKeyPair()
	stamp := "2026-08-30T12:00:00Z"
	statements := []string{
		`INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at) VALUES('admin:a','Admin','ADMIN',1,'ACTIVE','` + stamp + `','` + stamp + `')`,
		`INSERT INTO management_admin_vps_peers(id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at) VALUES('peer:a','admin:a','vps:a','` + admin.Public + `','10.81.0.10','CONFIGURED',1,0,'` + stamp + `','` + stamp + `')`,
		`INSERT INTO management_resources(id,site_id,name,resource_kind,access_profile,local_destination,enabled,advanced_scope_acknowledged,desired_route_generation,applied_route_generation,health_state,created_at,updated_at) VALUES('resource:a','site:home','Gateway','GATEWAY_SERVICE','GATEWAY_ONLY','192.168.200.1',1,0,1,0,'UNKNOWN','` + stamp + `','` + stamp + `')`,
		`INSERT INTO management_resource_publications(id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,desired_acl_generation,applied_acl_generation,state,created_at,updated_at) VALUES('publication:a','resource:a','` + link.ID + `','10.96.1.1/32',1,0,1,0,'PENDING','` + stamp + `','` + stamp + `')`,
		`INSERT INTO management_resource_acl(id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at) VALUES('acl:a','admin:a','resource:a','TCP',8443,8443,1,1,'` + stamp + `','` + stamp + `')`,
		`UPDATE management_fabric_generations SET desired_generation=desired_generation+1,state='PENDING' WHERE singleton_id=1`,
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	secretRoot := filepath.Join(root, "secrets")
	transactionRoot := filepath.Join(root, "transactions")
	for _, directory := range []string{secretRoot, transactionRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(secretRoot, "link-a.key"), []byte(local.Private+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := func(name string) string {
		if runtime.GOOS == "windows" {
			return filepath.Join(`C:\fake`, name+".exe")
		}
		return "/fake/" + name
	}
	executor := &gatewayExecutor{interfaces: map[string]*gatewayInterface{}, routes: map[string]gatewayRoute{}, firewall: "table inet gateway_vpn {}"}
	applier := &Applier{Repository: repository, Executor: executor, Paths: Paths{
		TransactionRoot: transactionRoot, SecretRoot: secretRoot,
		SecretReferenceRoot: "/var/lib/gateway-vpn/secrets/management",
		IP:                  executable("ip"), NFT: executable("nft"), WG: executable("wg"),
	}, Now: func() time.Time { return time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC) }}
	return gatewayApplierFixture{database: database, repository: repository, applier: applier, executor: executor}
}
