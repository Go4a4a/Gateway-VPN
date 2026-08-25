package subscriptionnet

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/subscription"
)

type bootstrapAuthorization struct {
	modemID        string
	subscriptionID string
	addresses      []string
	port           uint16
}

type fakeBootstrapBroker struct {
	syncs          int
	authorizations []bootstrapAuthorization
}

func (broker *fakeBootstrapBroker) SyncRouting(context.Context) error {
	broker.syncs++
	return nil
}

func (broker *fakeBootstrapBroker) AuthorizeSubscriptionBootstrap(_ context.Context, modemID, subscriptionID string, addresses []string, port uint16) error {
	broker.authorizations = append(broker.authorizations, bootstrapAuthorization{modemID: modemID, subscriptionID: subscriptionID, addresses: append([]string(nil), addresses...), port: port})
	return nil
}

type publicResolver struct{}

func (publicResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

func TestModemBoundFetcherFallsBackInPriorityOrderAndAuthorizesExactEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("subscription-payload"))
	}))
	defer server.Close()

	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
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
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	base, err := subscription.NewFetcherWithRootCAs(publicResolver{}, nil, roots)
	if err != nil {
		t.Fatal(err)
	}
	broker := &fakeBootstrapBroker{}
	fetcher, err := NewModemBoundFetcher(base, modems, broker, []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	fetcher.ResolverFactory = func(subscription.DialContextFunc, []string) subscription.Resolver { return publicResolver{} }
	fetcher.DialerFactory = func(interfaceName string, _ uint32) (subscription.DialContextFunc, error) {
		if interfaceName == "enx0001" {
			return func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("operator A blocked") }, nil
		}
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		}, nil
	}
	result, err := fetcher.FetchForSubscription(ctx, "sub-a", "https://example.com/sub", subscription.FetchOptions{})
	if err != nil {
		t.Fatalf("FetchForSubscription() error = %v", err)
	}
	if string(result.Payload) != "subscription-payload" || broker.syncs != 1 || len(broker.authorizations) != 2 {
		t.Fatalf("result/sync/authorizations = %q/%d/%+v", result.Payload, broker.syncs, broker.authorizations)
	}
	if broker.authorizations[0].modemID != "modem-a" || broker.authorizations[1].modemID != "modem-b" || broker.authorizations[1].subscriptionID != "sub-a" || broker.authorizations[1].port != 443 || len(broker.authorizations[1].addresses) != 1 || broker.authorizations[1].addresses[0] != "203.0.113.10" {
		t.Fatalf("authorization order/content = %+v", broker.authorizations)
	}
}

func TestModemBoundFetcherRequiresReadyModem(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	base, _ := subscription.NewFetcher(publicResolver{}, nil)
	broker := &fakeBootstrapBroker{}
	fetcher, err := NewModemBoundFetcher(base, modem.NewRepository(database, 1101, 0x1101), broker, []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.FetchForSubscription(ctx, "sub-a", "https://example.com/sub", subscription.FetchOptions{}); err == nil || !strings.Contains(err.Error(), "ready modem") {
		t.Fatalf("FetchForSubscription(no modem) error = %v", err)
	}
}
