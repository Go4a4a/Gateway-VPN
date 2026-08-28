package subscriptionnet

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/subscription"
)

type ladderSelector struct {
	mutex      sync.Mutex
	selections [][2]string
	failTarget string
}

func (selector *ladderSelector) Select(_ context.Context, group, target string) error {
	selector.mutex.Lock()
	defer selector.mutex.Unlock()
	selector.selections = append(selector.selections, [2]string{group, target})
	if target == selector.failTarget {
		return errors.New("synthetic selector failure")
	}
	return nil
}

type ladderResolver struct{}

func (ladderResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
}

func TestRouteRepositoryOrdersTargetSubscriptionFirstAndNeverReturnsExcludedNodes(t *testing.T) {
	ctx, database, modems, subscriptions, versions := routeFixture(t)
	defer database.Close()
	targetNodes := activateRouteSubscription(t, ctx, subscriptions, versions, "sub-a", "A", "version-a")
	otherNodes := activateRouteSubscription(t, ctx, subscriptions, versions, "sub-b", "B", "version-b")
	if _, err := subscription.NewNodeRepository(database).SetOverride(ctx, otherNodes[1].ID, subscription.OverrideExclude); err != nil {
		t.Fatal(err)
	}
	if err := accesspolicy.NewRepository(database).SetMethodEnabled(ctx, "access:subscription:sub-b", false); err != nil {
		t.Fatal(err)
	}
	if err := pathmatrix.NewRepository(database).ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE runtime_state
	SET gateway_state='ONLINE', path_state='PATH_ACTIVE', active_method_id='access:subscription:sub-a',
	    active_method_kind='SUBSCRIPTION', active_quality_class='FULL',
	    active_uplink_id='modem-b', active_modem_id='modem-b',
	    active_path_id=(SELECT id FROM subscription_uplink_paths WHERE uplink_id='modem-b' AND subscription_id='sub-a'),
	    active_subscription_id='sub-a', active_node_id=?
WHERE singleton_id=1`, targetNodes[0].ID); err != nil {
		t.Fatal(err)
	}
	routes, err := NewRouteRepository(database).ListVPNRoutes(ctx, "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 6 {
		t.Fatalf("route count = %d, want 2 target nodes × 2 modems + 1 allowed other node × 2 modems", len(routes))
	}
	if !routes[0].ActiveForTarget || routes[0].ModemID != "modem-b" || routes[0].NodeID != targetNodes[0].ID {
		t.Fatalf("first route is not exact active target route: %+v", routes[0])
	}
	seenOther := false
	for _, route := range routes {
		if route.NodeID == otherNodes[1].ID {
			t.Fatalf("excluded node returned as a route: %+v", route)
		}
		if route.SubscriptionID == "sub-b" {
			seenOther = true
			if route.MethodEnabled {
				t.Fatalf("disabled user method was reported enabled: %+v", route)
			}
		} else if seenOther {
			t.Fatalf("target-subscription route appeared after another subscription: %+v", route)
		}
	}
	if err := NewRouteRepository(database).ValidateVPNRoute(ctx, routes[0]); err != nil {
		t.Fatalf("ValidateVPNRoute(current) error = %v", err)
	}
	if _, err := subscription.NewNodeRepository(database).SetOverride(ctx, routes[0].NodeID, subscription.OverrideExclude); err != nil {
		t.Fatal(err)
	}
	if err := NewRouteRepository(database).ValidateVPNRoute(ctx, routes[0]); err == nil {
		t.Fatal("ValidateVPNRoute accepted node excluded after route inventory")
	}
	_ = modems
}

func TestRouteLadderSerializesSelectorAndHTTPSAndPersistsRedactedAttempts(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("vless://payload"))
	}))
	defer server.Close()
	ctx, database, modems, subscriptions, versions := routeFixture(t)
	defer database.Close()
	nodes := activateRouteSubscription(t, ctx, subscriptions, versions, "sub-a", "A", "version-a")
	if err := pathmatrix.NewRepository(database).ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE runtime_state
	SET gateway_state='ONLINE', path_state='PATH_ACTIVE', active_method_id='access:subscription:sub-a',
	    active_method_kind='SUBSCRIPTION', active_quality_class='FULL',
	    active_uplink_id='modem-a', active_modem_id='modem-a',
	    active_path_id=(SELECT id FROM subscription_uplink_paths WHERE uplink_id='modem-a' AND subscription_id='sub-a'),
	    active_subscription_id='sub-a', active_node_id=?
WHERE singleton_id=1`, nodes[0].ID); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	base, err := subscription.NewFetcherWithRootCAs(ladderResolver{}, nil, roots)
	if err != nil {
		t.Fatal(err)
	}
	broker := &fakeBootstrapBroker{}
	direct, err := NewModemBoundFetcher(base, modems, broker, []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	operationRepository := operations.NewRepository(database)
	if _, err := operationRepository.Create(ctx, operations.CreateInput{ID: "refresh-test", Kind: "SUBSCRIPTION_REFRESH", ScopeType: "SUBSCRIPTION", ScopeID: "sub-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := operationRepository.Start(ctx, "refresh-test", operations.StepInput{Severity: "INFO", Stage: "SOURCE", Code: "SOURCE_READY", Message: "ready"}); err != nil {
		t.Fatal(err)
	}
	operationLock := &sync.Mutex{}
	names, _ := mihomo.StablePathNames("modem-a", "sub-a")
	selector := &ladderSelector{failTarget: names.NodePrefix + nodes[0].ExternalName}
	ladder, err := NewRouteLadderFetcher(base, NewRouteRepository(database), accesspolicy.NewRepository(database), direct, selector, "127.0.0.1:17890", []string{"1.1.1.1"}, operationLock, operationRepository)
	if err != nil {
		t.Fatal(err)
	}
	lockObserved := false
	ladder.DialerFactory = func(string) (subscription.DialContextFunc, error) {
		return func(dialContext context.Context, _, _ string) (net.Conn, error) {
			if operationLock.TryLock() {
				operationLock.Unlock()
				return nil, errors.New("selector lock was not held through HTTPS dial")
			}
			lockObserved = true
			return (&net.Dialer{}).DialContext(dialContext, "tcp", server.Listener.Addr().String())
		}, nil
	}
	ladder.ResolverFactory = func(subscription.DialContextFunc, []string) subscription.Resolver { return ladderResolver{} }
	before := runtimeIdentity(t, database)
	result, err := ladder.FetchForSubscription(ctx, "sub-a", "https://example.com/sub?token=must-not-appear", subscription.FetchOptions{OperationID: "refresh-test"})
	if err != nil {
		t.Fatalf("FetchForSubscription() error = %v", err)
	}
	if string(result.Payload) != "vless://payload" || !lockObserved {
		t.Fatalf("result/lock = %q/%t", result.Payload, lockObserved)
	}
	if after := runtimeIdentity(t, database); after != before {
		t.Fatalf("service fetch changed user runtime: before=%q after=%q", before, after)
	}
	operation, err := operationRepository.Get(ctx, "refresh-test", true)
	if err != nil {
		t.Fatal(err)
	}
	serialized := ""
	codes := map[string]bool{}
	for _, step := range operation.Steps {
		serialized += step.Message + step.DetailsJSON
		codes[step.Code] = true
	}
	if !codes["VPN_NODE_SELECT_FAILED"] || !codes["VPN_HTTP_SUCCEEDED"] || !codes["DNS_STARTED"] || !codes["DNS_SUCCEEDED"] || !codes["TLS_STARTED"] || !codes["TLS_SUCCEEDED"] || !codes["HTTP_RESPONSE"] {
		t.Fatalf("operation codes = %#v", codes)
	}
	if strings.Contains(serialized, "must-not-appear") || strings.Contains(serialized, "example.com") {
		t.Fatalf("operation leaked source URL: %s", serialized)
	}
}

func routeFixture(t *testing.T) (context.Context, *sql.DB, *modem.Repository, *subscription.Repository, *subscription.VersionRepository) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	for index, id := range []string{"modem-a", "modem-b"} {
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: id, Name: id, IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat(string(rune('a'+index)), 64)}); err != nil {
			t.Fatal(err)
		}
		if _, err := modems.ApplyLease(ctx, id, modem.LeaseInput{InterfaceName: "enx000" + string(rune('1'+index)), ManagementCIDR: "192.168." + string(rune('8'+index)) + ".0/24", Gateway: "192.168." + string(rune('8'+index)) + ".1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, database, modems, subscription.NewRepository(database), subscription.NewVersionRepository(database)
}

func activateRouteSubscription(t *testing.T, ctx context.Context, subscriptions *subscription.Repository, versions *subscription.VersionRepository, id, name, versionID string) []subscription.StoredNode {
	t.Helper()
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: id, Name: name, SourceType: "url", SourceSecretRef: "/secret/" + id, RefreshInterval: time.Minute}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one\n" +
		"vless://22222222-2222-2222-2222-222222222222@two.example:443#LTE-two")
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: versionID, SubscriptionID: id, Payload: payload, Matchers: subscription.DefaultMatchers()})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, versionID); err != nil {
		t.Fatal(err)
	}
	return staged.Nodes
}

func runtimeIdentity(t *testing.T, database *sql.DB) string {
	t.Helper()
	var method, modemID, subscriptionID, nodeID sql.NullString
	if err := database.QueryRow(`SELECT active_method_id, active_uplink_id, active_subscription_id, active_node_id FROM runtime_state WHERE singleton_id=1`).Scan(&method, &modemID, &subscriptionID, &nodeID); err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{method.String, modemID.String, subscriptionID.String, nodeID.String}, "|")
}
