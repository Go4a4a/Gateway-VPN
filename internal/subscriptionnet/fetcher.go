package subscriptionnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/netbind"
	"gateway-vpn/internal/subscription"
)

type BootstrapBroker interface {
	SyncRouting(context.Context) error
	AuthorizeSubscriptionBootstrap(context.Context, string, string, []string, uint16) error
}

type ModemDialerFactory func(string, uint32) (subscription.DialContextFunc, error)
type ModemResolverFactory func(subscription.DialContextFunc, []string) subscription.Resolver

// ModemBoundFetcher tries ready modems in explicit priority order. Both DNS
// and HTTPS sockets use the same interface and fwmark, and the resolved HTTPS
// addresses must be authorized in the root-owned firewall before dialing.
type ModemBoundFetcher struct {
	Base            *subscription.Fetcher
	Modems          *modem.Repository
	Broker          BootstrapBroker
	BootstrapDNS    []string
	DialerFactory   ModemDialerFactory
	ResolverFactory ModemResolverFactory
}

func NewModemBoundFetcher(base *subscription.Fetcher, modems *modem.Repository, broker BootstrapBroker, bootstrapDNS []string) (*ModemBoundFetcher, error) {
	current := &ModemBoundFetcher{Base: base, Modems: modems, Broker: broker, BootstrapDNS: append([]string(nil), bootstrapDNS...), DialerFactory: defaultModemDialer, ResolverFactory: defaultModemResolver}
	if err := current.validate(); err != nil {
		return nil, err
	}
	return current, nil
}

func (fetcher *ModemBoundFetcher) Fetch(context.Context, string, subscription.FetchOptions) (subscription.FetchResult, error) {
	return subscription.FetchResult{}, errors.New("modem-bound subscription fetch requires subscription identity")
}

func (fetcher *ModemBoundFetcher) FetchForSubscription(ctx context.Context, subscriptionID, secretURL string, options subscription.FetchOptions) (subscription.FetchResult, error) {
	if err := fetcher.validate(); err != nil {
		return subscription.FetchResult{}, err
	}
	if strings.TrimSpace(subscriptionID) == "" {
		return subscription.FetchResult{}, errors.New("subscription identity is required for modem-bound fetch")
	}
	if err := fetcher.Broker.SyncRouting(ctx); err != nil {
		return subscription.FetchResult{}, errors.New("modem routing is unavailable for subscription fetch")
	}
	stored, err := fetcher.Modems.List(ctx)
	if err != nil {
		return subscription.FetchResult{}, errors.New("read modem candidates for subscription fetch failed")
	}
	ready := 0
	for _, currentModem := range stored {
		if !currentModem.Enabled || currentModem.State != modem.StateReady {
			continue
		}
		ready++
		dial, err := fetcher.DialerFactory(currentModem.InterfaceName, currentModem.Fwmark)
		if err != nil {
			continue
		}
		resolver := &ipv4OnlyResolver{inner: fetcher.ResolverFactory(dial, fetcher.BootstrapDNS)}
		authorize := func(authorizeContext context.Context, addresses []netip.Addr, port uint16) error {
			values := make([]string, 0, len(addresses))
			for _, address := range addresses {
				address = address.Unmap()
				if !address.Is4() {
					return errors.New("subscription bootstrap resolved IPv6 while IPv6 is disabled")
				}
				values = append(values, address.String())
			}
			return fetcher.Broker.AuthorizeSubscriptionBootstrap(authorizeContext, currentModem.ID, subscriptionID, values, port)
		}
		result, err := fetcher.Base.FetchThrough(ctx, secretURL, options, resolver, dial, authorize)
		if err == nil {
			return result, nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return subscription.FetchResult{}, err
		}
	}
	if ready == 0 {
		return subscription.FetchResult{}, errors.New("subscription fetch requires at least one ready modem")
	}
	return subscription.FetchResult{}, errors.New("subscription HTTPS request failed through every ready modem")
}

func (fetcher *ModemBoundFetcher) validate() error {
	if fetcher == nil || fetcher.Base == nil || fetcher.Modems == nil || fetcher.Broker == nil || fetcher.DialerFactory == nil || fetcher.ResolverFactory == nil || len(fetcher.BootstrapDNS) == 0 || len(fetcher.BootstrapDNS) > 8 {
		return errors.New("modem-bound fetcher dependencies are incomplete")
	}
	for _, raw := range fetcher.BootstrapDNS {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return errors.New("modem-bound fetcher requires usable IPv4 bootstrap DNS")
		}
	}
	return nil
}

func defaultModemDialer(interfaceName string, fwmark uint32) (subscription.DialContextFunc, error) {
	configuration := netbind.Config{InterfaceName: interfaceName, Fwmark: fwmark}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second, KeepAlive: 15 * time.Second,
		Control: netbind.SocketControl(configuration),
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		}
		return dialer.DialContext(ctx, network, address)
	}, nil
}

func defaultModemResolver(dial subscription.DialContextFunc, bootstrapDNS []string) subscription.Resolver {
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if strings.HasPrefix(network, "tcp") {
				network = "tcp4"
			} else {
				network = "udp4"
			}
			return dial(ctx, network, net.JoinHostPort(bootstrapDNS[0], "53"))
		},
	}
}

type ipv4OnlyResolver struct {
	inner subscription.Resolver
}

func (resolver *ipv4OnlyResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	addresses, err := resolver.inner.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is4() {
			result = append(result, address)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("subscription endpoint has no IPv4 address")
	}
	return result, nil
}
