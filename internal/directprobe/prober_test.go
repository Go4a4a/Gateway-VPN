package directprobe

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/uplink"
)

type probeBroker struct {
	syncs          int
	authorizations []probeAuthorization
	syncFunc       func() error
}

type probeAuthorization struct {
	modemID   string
	targetID  string
	addresses []string
	port      uint16
}

func (broker *probeBroker) SyncRouting(context.Context) error {
	broker.syncs++
	if broker.syncFunc != nil {
		return broker.syncFunc()
	}
	return nil
}

func (broker *probeBroker) AuthorizeDirectProbe(_ context.Context, modemID, targetID string, addresses []string, port uint16) error {
	broker.authorizations = append(broker.authorizations, probeAuthorization{modemID: modemID, targetID: targetID, addresses: append([]string(nil), addresses...), port: port})
	return nil
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (function resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return function(ctx, network, host)
}

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) { return function(request) }

func TestProbePathUsesOneModemContextAndPublishesFullThenLimited(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	broker := &probeBroker{}
	probeScheduler := testProbeScheduler(t, 10<<20)
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, broker, probeScheduler, []string{"1.1.1.1", "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)
	prober.now = func() time.Time {
		clock = clock.Add(10 * time.Millisecond)
		return clock
	}
	var dialContext string
	prober.DialerFactory = func(interfaceName string, fwmark uint32) (DialContextFunc, error) {
		dialContext = interfaceName + "/" + strings.ToUpper(hex.EncodeToString([]byte{byte(fwmark >> 8), byte(fwmark)}))
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected real dial")
		}, nil
	}
	var dnsAttempts []string
	prober.ResolverFactory = func(_ DialContextFunc, dns string) Resolver {
		return resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
			dnsAttempts = append(dnsAttempts, dns+"/"+network+"/"+host)
			if dns == "1.1.1.1" {
				return nil, errors.New("first resolver unavailable")
			}
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		})
	}
	mode := "full"
	prober.ClientFactory = func(_ DialContextFunc, host, port string, addresses []netip.Addr, timeout time.Duration) (HTTPDoer, func(), error) {
		if port != "443" || len(addresses) != 1 || addresses[0].String() != "203.0.113.10" || timeout != 5*time.Second {
			t.Fatalf("HTTP client context = %s/%s/%v/%s", host, port, addresses, timeout)
		}
		return doerFunc(func(request *http.Request) (*http.Response, error) {
			status, body := 200, "open"
			switch request.URL.Hostname() {
			case "required-status.example":
				status = 204
			case "required-body.example":
				if mode == "limited" {
					body = "closed"
				}
			case "optional.example":
				if mode == "full" {
					status = 503
				}
			default:
				t.Fatalf("unexpected target host %q", request.URL.Hostname())
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}), func() {}, nil
	}

	result, err := prober.ProbePath(ctx, path.ID, scheduler.ClassFailover)
	if err != nil {
		t.Fatalf("ProbePath(FULL) error = %v", err)
	}
	if result.QualityClass != accesspolicy.QualityFull || result.RequiredTargetsPassed != 2 || result.RequiredTargetsTotal != 2 || result.OptionalTargetsPassed != 0 || result.FunctionalScore != 2000 || len(result.Targets) != 3 {
		t.Fatalf("FULL result = %+v", result)
	}
	if dialContext != "enx-test/1101" || broker.syncs != 1 || len(broker.authorizations) != 3 {
		t.Fatalf("bound context/sync/authorizations = %q/%d/%+v", dialContext, broker.syncs, broker.authorizations)
	}
	for _, authorization := range broker.authorizations {
		if authorization.modemID != "modem-a" || authorization.port != 443 || len(authorization.addresses) != 1 || authorization.addresses[0] != "203.0.113.10" {
			t.Fatalf("authorization = %+v", authorization)
		}
	}
	if len(dnsAttempts) != 6 || !strings.HasPrefix(dnsAttempts[0], "1.1.1.1/ip4/") || !strings.HasPrefix(dnsAttempts[1], "8.8.8.8/ip4/") {
		t.Fatalf("DNS fallback attempts = %v", dnsAttempts)
	}
	stored, err := paths.Get(ctx, path.ID)
	if err != nil || stored.QualityClass != accesspolicy.QualityFull || stored.State != "QUALIFIED" {
		t.Fatalf("stored FULL path = %+v, %v", stored, err)
	}

	mode = "limited"
	broker.authorizations = nil
	result, err = prober.ProbePath(ctx, path.ID, scheduler.ClassFailover)
	if err != nil {
		t.Fatalf("ProbePath(LIMITED) error = %v", err)
	}
	if result.QualityClass != accesspolicy.QualityLimited || result.RequiredTargetsPassed != 1 || result.OptionalTargetsPassed != 1 || result.FunctionalScore != 1001 || result.FailureCode != "PARTIAL_TARGET_ACCESS" {
		t.Fatalf("LIMITED result = %+v", result)
	}
	stored, _ = paths.Get(ctx, path.ID)
	if stored.QualityClass != accesspolicy.QualityLimited || stored.State != "DEGRADED" || stored.FunctionalScore != 1001 {
		t.Fatalf("stored LIMITED path = %+v", stored)
	}
	_ = database
}

func TestProbePathBudgetDeferralDoesNotOverwriteEvidence(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, &probeBroker{}, testProbeScheduler(t, 1), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) { return nil, nil }, nil
	}
	if _, err := prober.ProbePath(ctx, path.ID, scheduler.ClassStandby); !errors.Is(err, ErrDeferredBudget) {
		t.Fatalf("ProbePath() error = %v, want budget deferral", err)
	}
	stored, err := paths.Get(ctx, path.ID)
	if err != nil || stored.QualityClass != accesspolicy.QualityUnknown || stored.ExpiresAt != "" {
		t.Fatalf("deferred probe changed evidence = %+v, %v", stored, err)
	}
}

func TestProbePathTreatsTargetTimeoutAsEvidenceButCallerCancellationAsAbort(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, &probeBroker{}, testProbeScheduler(t, 10<<20), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) { return nil, nil }, nil
	}
	prober.ResolverFactory = func(DialContextFunc, string) Resolver {
		return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.32")}, nil
		})
	}
	prober.ClientFactory = func(DialContextFunc, string, string, []netip.Addr, time.Duration) (HTTPDoer, func(), error) {
		return doerFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded }), func() {}, nil
	}
	result, err := prober.ProbePath(ctx, path.ID, scheduler.ClassStandby)
	if err != nil || result.QualityClass != accesspolicy.QualityFailed || len(result.Targets) != 3 {
		t.Fatalf("target-timeout ProbePath() = %+v, %v", result, err)
	}
	for _, target := range result.Targets {
		if target.State != "FAILED" || target.ErrorCode != "TIMEOUT" {
			t.Fatalf("target timeout evidence = %+v", target)
		}
	}

	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	beforeCancellation, err := paths.Get(ctx, path.ID)
	if err != nil {
		t.Fatal(err)
	}
	callContext, cancel := context.WithCancel(ctx)
	prober.ClientFactory = func(DialContextFunc, string, string, []netip.Addr, time.Duration) (HTTPDoer, func(), error) {
		return doerFunc(func(*http.Request) (*http.Response, error) {
			cancel()
			return nil, errors.New("transport interrupted after caller cancellation")
		}), func() {}, nil
	}
	if _, err := prober.ProbePath(callContext, path.ID, scheduler.ClassStandby); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller-cancelled ProbePath() error = %v", err)
	}
	stored, err := paths.Get(ctx, path.ID)
	if err != nil || stored.QualityClass != accesspolicy.QualityFailed || stored.LastCheckedAt != beforeCancellation.LastCheckedAt {
		t.Fatalf("caller cancellation overwrote prior evidence = %+v, %v", stored, err)
	}
}

func TestResolveIPv4RejectsPrivateMixedAndIPv6Answers(t *testing.T) {
	_, database, _, paths, targets, _ := directProbeFixture(t)
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, &probeBroker{}, testProbeScheduler(t, 10<<20), []string{"1.1.1.1", "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	prober.ResolverFactory = func(DialContextFunc, string) Resolver {
		return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			attempts++
			if attempts == 1 {
				return []netip.Addr{netip.MustParseAddr("203.0.113.33"), netip.MustParseAddr("192.168.8.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil
		})
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	if _, err := prober.resolveIPv4(context.Background(), dial, "mixed.example"); err == nil || attempts != 2 {
		t.Fatalf("mixed/private/IPv6 DNS result accepted or fallback missing: attempts=%d err=%v", attempts, err)
	}
	if _, err := prober.resolveIPv4(context.Background(), dial, "192.168.8.1"); err == nil {
		t.Fatal("private literal target was accepted")
	}
}

func TestProbePathRejectsRouteGenerationChangedDuringRoutingSync(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	broker := &probeBroker{syncFunc: func() error {
		_, err := database.ExecContext(ctx, "UPDATE modems SET route_generation=route_generation+1 WHERE id='modem-a'")
		return err
	}}
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, broker, testProbeScheduler(t, 10<<20), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	dialed := false
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		dialed = true
		return nil, errors.New("must not create a socket for stale routing")
	}
	if _, err := prober.ProbePath(ctx, path.ID, scheduler.ClassStandby); err == nil {
		t.Fatal("ProbePath() accepted a route generation changed during synchronization")
	}
	if dialed || len(broker.authorizations) != 0 {
		t.Fatalf("stale route opened a socket or firewall tuple: dialed=%t authorizations=%+v", dialed, broker.authorizations)
	}
	stored, err := paths.Get(ctx, path.ID)
	if err != nil || stored.QualityClass != accesspolicy.QualityUnknown || stored.ExpiresAt != "" {
		t.Fatalf("stale route changed evidence = %+v, %v", stored, err)
	}
}

func TestProbePathWithOnlyOptionalTargetIsLimitedAndNoTargetsIsFailed(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	setProbeTargetEnabled(t, ctx, targets, "required-status", false, false)
	setProbeTargetEnabled(t, ctx, targets, "required-body", false, true)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	broker := &probeBroker{}
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, broker, testProbeScheduler(t, 10<<20), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) { return nil, nil }, nil
	}
	prober.ResolverFactory = func(DialContextFunc, string) Resolver {
		return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.31")}, nil
		})
	}
	prober.ClientFactory = func(DialContextFunc, string, string, []netip.Addr, time.Duration) (HTTPDoer, func(), error) {
		return doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("open")), Header: make(http.Header)}, nil
		}), func() {}, nil
	}
	result, err := prober.ProbePath(ctx, path.ID, scheduler.ClassStandby)
	if err != nil || result.QualityClass != accesspolicy.QualityLimited || result.RequiredTargetsTotal != 0 || result.OptionalTargetsPassed != 1 || result.FunctionalScore != 1 {
		t.Fatalf("optional-only ProbePath() = %+v, %v", result, err)
	}

	setProbeTargetEnabled(t, ctx, targets, "optional", false, true)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	broker.authorizations = nil
	result, err = prober.ProbePath(ctx, path.ID, scheduler.ClassStandby)
	if err != nil || result.QualityClass != accesspolicy.QualityFailed || result.FailureCode != "NO_ACTIVE_TARGETS" || len(result.Targets) != 0 {
		t.Fatalf("no-target ProbePath() = %+v, %v", result, err)
	}
	if len(broker.authorizations) != 0 {
		t.Fatalf("no-target probe authorized endpoints: %+v", broker.authorizations)
	}
}

func TestProbePathClassifiesWhitelistOnlyAndSkipsServiceEndpoints(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	setProbeTargetEnabled(t, ctx, targets, "required-status", false, false)
	setProbeTargetEnabled(t, ctx, targets, "required-body", false, true)
	setProbeTargetEnabled(t, ctx, targets, "optional", false, true)
	if _, err := targets.Create(ctx, bypass.CreateInput{
		ID: "whitelist", Name: "Whitelist", Kind: bypass.KindDomain,
		Value: "whitelist.example", TargetClass: bypass.TargetClassWhitelistIndicator,
		Timeout: 5 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := targets.Create(ctx, bypass.CreateInput{
		ID: "service", Name: "Service", Kind: bypass.KindDomain,
		Value: "service.example", TargetClass: bypass.TargetClassServiceEndpoint,
		Timeout: 5 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	path, err := paths.Get(ctx, path.ID)
	if err != nil {
		t.Fatal(err)
	}
	broker := &probeBroker{}
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, broker, testProbeScheduler(t, 10<<20), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) { return nil, nil }, nil
	}
	prober.ResolverFactory = func(DialContextFunc, string) Resolver {
		return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.41")}, nil
		})
	}
	prober.ClientFactory = func(DialContextFunc, string, string, []netip.Addr, time.Duration) (HTTPDoer, func(), error) {
		return doerFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Hostname() != "whitelist.example" {
				t.Fatalf("service endpoint was probed as user Internet evidence: %s", request.URL.Hostname())
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("available")), Header: make(http.Header)}, nil
		}), func() {}, nil
	}
	result, err := prober.ProbePath(ctx, path.ID, scheduler.ClassStandby)
	if err != nil || result.QualityClass != accesspolicy.QualityWhitelistOnly || result.WhitelistTargetsPassed != 1 || result.WhitelistTargetsTotal != 1 || result.RequiredTargetsTotal != 0 || result.OptionalTargetsTotal != 0 || result.FunctionalScore != 1 || result.FailureCode != "WHITELIST_ONLY_ACCESS" {
		t.Fatalf("whitelist-only ProbePath() = %+v, %v", result, err)
	}
	if len(result.Targets) != 1 || result.Targets[0].TargetClass != bypass.TargetClassWhitelistIndicator || len(broker.authorizations) != 1 || broker.authorizations[0].targetID != "whitelist" {
		t.Fatalf("whitelist/service evidence = targets %+v authorizations %+v", result.Targets, broker.authorizations)
	}
	stored, err := paths.Get(ctx, path.ID)
	if err != nil || stored.State != "DEGRADED" || stored.QualityClass != accesspolicy.QualityWhitelistOnly || stored.WhitelistTargetsPassed != 1 || stored.WhitelistTargetsTotal != 1 {
		t.Fatalf("stored whitelist-only path = %+v, %v", stored, err)
	}
}

func TestPinnedDialerUsesOnlyResolvedIPv4AndExactOrigin(t *testing.T) {
	var called string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		called = network + "/" + address
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	pinned, err := pinnedDialer(dial, "access.example", "443", []netip.Addr{netip.MustParseAddr("203.0.113.20")})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := pinned(context.Background(), "tcp", "access.example:443")
	if err != nil || called != "tcp4/203.0.113.20:443" {
		t.Fatalf("pinned dial = %q, %v", called, err)
	}
	_ = connection.Close()
	if _, err := pinned(context.Background(), "tcp", "redirect.example:443"); err == nil {
		t.Fatal("pinned dial accepted a different host")
	}
	if _, err := pinnedDialer(dial, "access.example", "443", []netip.Addr{netip.MustParseAddr("192.168.8.1")}); err == nil {
		t.Fatal("pinned dial accepted a private address")
	}
}

func TestRunnerProbesDuePathAndSkipsFreshEvidence(t *testing.T) {
	ctx, database, _, paths, targets, path := directProbeFixture(t)
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, &probeBroker{}, testProbeScheduler(t, 10<<20), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 27, 19, 0, 0, 0, time.UTC)
	prober.now = func() time.Time { return clock }
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) { return nil, nil }, nil
	}
	prober.ResolverFactory = func(DialContextFunc, string) Resolver {
		return resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.30")}, nil
		})
	}
	prober.ClientFactory = func(DialContextFunc, string, string, []netip.Addr, time.Duration) (HTTPDoer, func(), error) {
		return doerFunc(func(request *http.Request) (*http.Response, error) {
			status := 200
			if request.URL.Hostname() == "required-status.example" {
				status = 204
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("open")), Header: make(http.Header)}, nil
		}), func() {}, nil
	}
	runner, err := NewRunner(prober, DefaultRunnerConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return clock }
	first, err := runner.RunOnce(ctx)
	if err != nil || first.Due != 1 || first.Probed != 1 || first.Published != 1 {
		t.Fatalf("first RunOnce() = %+v, %v", first, err)
	}
	second, err := runner.RunOnce(ctx)
	if err != nil || second.Due != 0 || second.Probed != 0 {
		t.Fatalf("fresh RunOnce() = %+v, %v", second, err)
	}
	manual, err := runner.ProbeAllNow(ctx)
	if err != nil || manual.Due != 1 || manual.Probed != 1 || manual.Published != 1 {
		t.Fatalf("manual ProbeAllNow() with fresh evidence = %+v, %v", manual, err)
	}
	stored, _ := paths.Get(ctx, path.ID)
	if stored.QualityClass != accesspolicy.QualityFull {
		t.Fatalf("runner stored path = %+v", stored)
	}
}

func TestRunnerRotatesDuePathsAfterFailures(t *testing.T) {
	ctx, database, modems, paths, targets, _ := directProbeFixture(t)
	for _, item := range []struct {
		id     string
		subnet int
	}{{"modem-b", 9}, {"modem-c", 10}} {
		digest := sha256.Sum256([]byte(item.id))
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: item.id, Name: item.id, IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
			t.Fatal(err)
		}
		if _, err := modems.ApplyLease(ctx, item.id, modem.LeaseInput{InterfaceName: "enx-" + item.id, ManagementCIDR: "192.168." + strconv.Itoa(item.subnet) + ".0/24", Gateway: "192.168." + strconv.Itoa(item.subnet) + ".1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
			t.Fatal(err)
		}
	}
	prober, err := New(uplink.NewRepository(database, 1101, 0x1101), paths, targets, &probeBroker{}, testProbeScheduler(t, 10<<20), []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	prober.DialerFactory = func(string, uint32) (DialContextFunc, error) {
		return nil, errors.New("forced socket failure")
	}
	configuration := DefaultRunnerConfig()
	configuration.DueLimit = 1
	runner, err := NewRunner(prober, configuration)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]string, 0, 3)
	for cycle := 0; cycle < 3; cycle++ {
		result, runErr := runner.RunOnce(ctx)
		if runErr == nil || result.Due != 3 || result.Probed != 1 || len(result.Errors) != 1 {
			t.Fatalf("RunOnce(%d) = %+v, %v", cycle, result, runErr)
		}
		for pathID := range result.Errors {
			seen = append(seen, pathID)
		}
	}
	if strings.Join(seen, ",") != "direct:path:modem-a,direct:path:modem-b,direct:path:modem-c" {
		t.Fatalf("due path rotation = %v", seen)
	}
}

func directProbeFixture(t *testing.T) (context.Context, *sql.DB, *modem.Repository, *accesspolicy.DirectPathRepository, *bypass.Repository, accesspolicy.DirectPath) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	digest := sha256.Sum256([]byte("modem-a"))
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "Modem A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enx-test", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"192.168.8.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	targets := bypass.NewRepository(database)
	for _, input := range []bypass.CreateInput{
		{ID: "required-status", Name: "Required status", Kind: bypass.KindDomain, Value: "required-status.example", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessExpectedStatus, ExpectedStatus: "204"},
		{ID: "required-body", Name: "Required body", Kind: bypass.KindDomain, Value: "required-body.example", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessExpectedBody, ExpectedStatus: "200", ExpectedBodySubstring: "open"},
		{ID: "optional", Name: "Optional", Kind: bypass.KindDomain, Value: "optional.example", Required: false, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessExpectedStatus, ExpectedStatus: "200"},
	} {
		if _, err := targets.Create(ctx, input); err != nil {
			t.Fatal(err)
		}
	}
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := paths.List(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("direct paths = %+v, %v", items, err)
	}
	return ctx, database, modems, paths, targets, items[0]
}

func testProbeScheduler(t *testing.T, dailyLimit int64) *scheduler.Scheduler {
	t.Helper()
	value, err := scheduler.New(scheduler.Config{MaxConcurrency: 2, MaxConcurrencyPerModem: 1, MaxRequestsPerWindow: 100, RequestWindow: time.Second, DailySoftLimitBytes: dailyLimit})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func setProbeTargetEnabled(t *testing.T, ctx context.Context, repository *bypass.Repository, id string, enabled, allowNoRequired bool) {
	t.Helper()
	target, err := repository.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(ctx, id, bypass.UpdateInput{
		Name: target.Name, Kind: target.Kind, Value: target.Value, Enabled: enabled,
		Required: target.Required, Timeout: time.Duration(target.TimeoutSeconds) * time.Second,
		SuccessMode: target.SuccessMode, ExpectedStatus: target.ExpectedStatus,
		ExpectedBodySubstring: target.ExpectedBodySubstring, AllowNoRequired: allowNoRequired,
	}); err != nil {
		t.Fatalf("set target %s enabled=%t: %v", id, enabled, err)
	}
}
