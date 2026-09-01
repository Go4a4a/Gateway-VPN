package updatenet

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/subscriptionnet"
	"gateway-vpn/internal/uplink"
)

type testSelector struct {
	selections [][2]string
}

func (selector *testSelector) Select(_ context.Context, group, target string) error {
	selector.selections = append(selector.selections, [2]string{group, target})
	return nil
}

type testBroker struct {
	syncs      int
	authorizes int
	uplinkID   string
	addresses  []string
	port       uint16
}

func (broker *testBroker) SyncRouting(context.Context) error {
	broker.syncs++
	return nil
}

func (broker *testBroker) AuthorizeUpdateService(_ context.Context, uplinkID string, addresses []string, port uint16) error {
	broker.authorizes++
	broker.uplinkID = uplinkID
	broker.addresses = append([]string(nil), addresses...)
	broker.port = port
	return nil
}

type testResolver struct{}

func (testResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type callbackLocker struct {
	sync.Mutex
	once   sync.Once
	before func()
}

func (locker *callbackLocker) Lock() {
	locker.once.Do(locker.before)
	locker.Mutex.Lock()
}

func TestLadderRetriesRetryableVPNResponseWithoutChangingUserPath(t *testing.T) {
	ctx, database, uplinks, policies := updateRouteFixture(t)
	defer database.Close()
	subscriptions := subscription.NewRepository(database)
	versions := subscription.NewVersionRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	staged, err := versions.Stage(ctx, subscription.StageInput{
		VersionID: "version-a", SubscriptionID: "sub-a",
		Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one\n" +
			"vless://22222222-2222-2222-2222-222222222222@two.example:443#LTE-two"),
		Matchers: subscription.DefaultMatchers(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, "version-a"); err != nil {
		t.Fatal(err)
	}
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
WHERE singleton_id=1`, staged.Nodes[0].ID); err != nil {
		t.Fatal(err)
	}
	before := updateRuntimeIdentity(t, database)
	lock := &sync.Mutex{}
	selector := &testSelector{}
	broker := &testBroker{}
	attempts := []Attempt{}
	httpAttempts := 0
	ladder := &Ladder{
		Routes: subscriptionnet.NewRouteRepository(database), Policy: policies, Uplinks: uplinks,
		Broker: broker, Selector: selector, ProbeAddress: "127.0.0.1:17890",
		BootstrapDNS: []string{"1.1.1.1"}, OperationLock: lock,
		OnAttempt: func(attempt Attempt) { attempts = append(attempts, attempt) },
	}
	ladder.roundTrip = func(_ context.Context, _ *http.Request, _ subscription.Resolver, _ subscription.DialContextFunc, _ subscription.EndpointAuthorizer) (*http.Response, error) {
		if lock.TryLock() {
			lock.Unlock()
			t.Fatal("Mihomo selector lock was not held through update HTTP attempt")
		}
		httpAttempts++
		status := http.StatusServiceUnavailable
		if httpAttempts == 2 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response"))}, nil
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/Go4a4a/Gateway-VPN", nil)
	response, err := ladder.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("RoundTrip() response=%+v error=%v", response, err)
	}
	response.Body.Close()
	if httpAttempts != 2 || len(selector.selections) != 4 || len(attempts) != 2 || attempts[0].ResultCode != "HTTP_RETRYABLE" || attempts[1].ResultCode != "HTTPS_SUCCEEDED" {
		t.Fatalf("VPN attempts=%d selections=%+v audit=%+v", httpAttempts, selector.selections, attempts)
	}
	if after := updateRuntimeIdentity(t, database); after != before {
		t.Fatalf("service route changed user runtime: before=%q after=%q", before, after)
	}
	if broker.syncs != 0 || broker.authorizes != 0 {
		t.Fatalf("direct service fallback was used after VPN success: %+v", broker)
	}
}

func TestLadderRejectsVPNMethodDisabledAfterInventoryBeforeSelector(t *testing.T) {
	ctx, database, uplinks, policies := updateRouteFixture(t)
	defer database.Close()
	subscriptions := subscription.NewRepository(database)
	versions := subscription.NewVersionRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	staged, err := versions.Stage(ctx, subscription.StageInput{
		VersionID: "version-a", SubscriptionID: "sub-a",
		Payload:  []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one"),
		Matchers: subscription.DefaultMatchers(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	policy, err := policies.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
		StartupBlockUntilQualified: policy.StartupBlockUntilQualified, DirectServiceRefresh: false,
		FailureHoldSeconds: policy.FailureHoldSeconds, RecoveryStableSeconds: policy.RecoveryStableSeconds,
		SwitchCooldownSeconds: policy.SwitchCooldownSeconds,
	}); err != nil {
		t.Fatal(err)
	}
	var disableErr error
	locker := &callbackLocker{before: func() {
		disableErr = policies.SetMethodEnabled(context.Background(), "access:subscription:sub-a", false)
	}}
	selector := &testSelector{}
	attempts := []Attempt{}
	httpAttempts := 0
	ladder := &Ladder{
		Routes: subscriptionnet.NewRouteRepository(database), Policy: policies, Uplinks: uplinks,
		Broker: &testBroker{}, Selector: selector, ProbeAddress: "127.0.0.1:17890",
		BootstrapDNS: []string{"1.1.1.1"}, OperationLock: locker,
		OnAttempt: func(attempt Attempt) { attempts = append(attempts, attempt) },
	}
	ladder.roundTrip = func(context.Context, *http.Request, subscription.Resolver, subscription.DialContextFunc, subscription.EndpointAuthorizer) (*http.Response, error) {
		httpAttempts++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unexpected"))}, nil
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/Go4a4a/Gateway-VPN", nil)
	if response, err := ladder.RoundTrip(request); err == nil || response != nil {
		t.Fatalf("disabled post-inventory route response=%+v error=%v", response, err)
	}
	if disableErr != nil {
		t.Fatalf("disable access method under selector lock: %v", disableErr)
	}
	if httpAttempts != 0 || len(selector.selections) != 0 || len(attempts) != 1 || attempts[0].ResultCode != "ROUTE_STALE" {
		t.Fatalf("stale route crossed selector/HTTPS boundary: HTTP=%d selections=%+v attempts=%+v", httpAttempts, selector.selections, attempts)
	}
}

func TestLadderUsesOnlyPolicyPermittedBoundDirectUplinkFallback(t *testing.T) {
	ctx, database, uplinks, policies := updateRouteFixture(t)
	defer database.Close()
	broker := &testBroker{}
	ladder := &Ladder{
		Routes: subscriptionnet.NewRouteRepository(database), Policy: policies, Uplinks: uplinks,
		Broker: broker, Selector: &testSelector{}, ProbeAddress: "127.0.0.1:17890",
		BootstrapDNS: []string{"1.1.1.1"}, OperationLock: &sync.Mutex{},
	}
	ladder.roundTrip = func(ctx context.Context, _ *http.Request, _ subscription.Resolver, _ subscription.DialContextFunc, authorize subscription.EndpointAuthorizer) (*http.Response, error) {
		if authorize == nil {
			t.Fatal("direct update attempt omitted root endpoint authorization")
		}
		if err := authorize(ctx, []netip.Addr{netip.MustParseAddr("8.8.4.4")}, 443); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/Go4a4a/Gateway-VPN", nil)
	response, err := ladder.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("direct RoundTrip() response=%+v error=%v", response, err)
	}
	response.Body.Close()
	if broker.syncs != 1 || broker.authorizes != 1 || broker.uplinkID != "modem-a" || strings.Join(broker.addresses, ",") != "8.8.4.4" || broker.port != 443 {
		t.Fatalf("direct broker evidence=%+v", broker)
	}
	policy, err := policies.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
		StartupBlockUntilQualified: policy.StartupBlockUntilQualified, DirectServiceRefresh: false,
		FailureHoldSeconds: policy.FailureHoldSeconds, RecoveryStableSeconds: policy.RecoveryStableSeconds,
		SwitchCooldownSeconds: policy.SwitchCooldownSeconds,
	}); err != nil {
		t.Fatal(err)
	}
	broker.syncs, broker.authorizes = 0, 0
	if _, err := ladder.RoundTrip(request); err == nil || broker.syncs != 0 || broker.authorizes != 0 {
		t.Fatalf("disabled direct service fallback result=%v broker=%+v", err, broker)
	}
}

func TestRequestAndAddressPolicyRejectsLocalReservedAndUnsafeInputs(t *testing.T) {
	for _, raw := range []string{"https://localhost/update", "https://192.168.1.1/update", "https://203.0.113.10/update", "https://example.com:8443/update"} {
		request, _ := http.NewRequest(http.MethodGet, raw, nil)
		if err := validateRequest(request); err == nil {
			t.Fatalf("unsafe update request accepted: %s", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "198.51.100.10", "203.0.113.10"} {
		if publicIPv4(netip.MustParseAddr(raw)) {
			t.Fatalf("non-public address accepted: %s", raw)
		}
	}
	if !publicIPv4(netip.MustParseAddr("8.8.8.8")) || !retryableHTTPStatus(http.StatusUnavailableForLegalReasons) || retryableHTTPStatus(http.StatusNotFound) {
		t.Fatal("public/retryable update route policy is invalid")
	}
}

func TestBoundDialerAgainstKernelUpdateServiceFirewall(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_UPDATE_BOUND_DIAL_INTEGRATION") != "1" {
		t.Skip("set GATEWAY_VPN_UPDATE_BOUND_DIAL_INTEGRATION=1 inside the prepared Linux namespace")
	}
	interfaceName := os.Getenv("GATEWAY_VPN_UPDATE_INTERFACE")
	rawMark := strings.TrimPrefix(os.Getenv("GATEWAY_VPN_UPDATE_MARK"), "0x")
	mark, err := strconv.ParseUint(rawMark, 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	dial, err := boundDialer(interfaceName, uint32(mark))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, dialErr := dial(ctx, "tcp4", os.Getenv("GATEWAY_VPN_UPDATE_TARGET"))
	expectFailure := os.Getenv("GATEWAY_VPN_UPDATE_EXPECT_FAILURE") == "1"
	if expectFailure {
		if dialErr == nil {
			connection.Close()
			t.Fatal("unauthorized update-service packet unexpectedly connected")
		}
		return
	}
	if dialErr != nil {
		t.Fatalf("authorized bound update-service connection: %v", dialErr)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != "ok" {
		t.Fatalf("bound update-service response=%q error=%v", response, err)
	}
}

func updateRouteFixture(t *testing.T) (context.Context, *sql.DB, *uplink.Repository, *accesspolicy.Repository) {
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
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "LTE", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("a", 64)}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return ctx, database, uplink.NewRepository(database, 1101, 0x1101), accesspolicy.NewRepository(database)
}

func updateRuntimeIdentity(t *testing.T, database *sql.DB) string {
	t.Helper()
	var method, uplinkID, subscriptionID, nodeID sql.NullString
	if err := database.QueryRow(`SELECT active_method_id,active_uplink_id,active_subscription_id,active_node_id FROM runtime_state WHERE singleton_id=1`).Scan(&method, &uplinkID, &subscriptionID, &nodeID); err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{method.String, uplinkID.String, subscriptionID.String, nodeID.String}, "|")
}
