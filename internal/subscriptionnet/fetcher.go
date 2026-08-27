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
	"gateway-vpn/internal/operations"
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
	Operations      *operations.Repository
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
	attempt := 0
	var requestedRetry time.Duration
	for _, currentModem := range stored {
		if !currentModem.Enabled || currentModem.State != modem.StateReady {
			continue
		}
		ready++
		attempt++
		if err := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
			Severity: "INFO", Stage: "ROUTE_SELECTED", Code: "DIRECT_ROUTE_SELECTED",
			Message: "Проверяется прямой маршрут для обновления подписки.",
			Details: map[string]any{"attempt": attempt, "route_kind": "DIRECT", "modem_id": currentModem.ID},
		}); err != nil {
			return subscription.FetchResult{}, errors.New("record subscription direct route attempt failed")
		}
		attemptContext, cancelAttempt := context.WithTimeout(ctx, routeAttemptTimeout)
		dial, err := fetcher.DialerFactory(currentModem.InterfaceName, currentModem.Fwmark)
		if err != nil {
			cancelAttempt()
			if stepErr := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
				Severity: "WARNING", Stage: "ROUTE_SELECTED", Code: "DIRECT_ROUTE_BIND_FAILED",
				Message: "Не удалось создать изолированный маршрут через модем; будет проверен следующий готовый модем.",
				Details: map[string]any{"attempt": attempt, "route_kind": "DIRECT", "modem_id": currentModem.ID},
			}); stepErr != nil {
				return subscription.FetchResult{}, errors.New("record failed subscription direct binding failed")
			}
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
		attemptOptions := withRouteProgress(fetcher.Operations, options, map[string]any{"attempt": attempt, "route_kind": "DIRECT", "modem_id": currentModem.ID})
		result, err := fetcher.Base.FetchThrough(attemptContext, secretURL, attemptOptions, resolver, dial, authorize)
		cancelAttempt()
		if err == nil {
			if stepErr := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
				Severity: "INFO", Stage: "HTTP", Code: "DIRECT_HTTP_SUCCEEDED",
				Message: "Подписка получена через прямой маршрут.",
				Details: map[string]any{"attempt": attempt, "route_kind": "DIRECT", "modem_id": currentModem.ID},
			}); stepErr != nil {
				return subscription.FetchResult{}, errors.New("record successful subscription direct route failed")
			}
			return result, nil
		}
		requestedRetry = largerRetryAfter(requestedRetry, err)
		failureCode := "DIRECT_HTTP_FAILED"
		if errors.Is(err, context.DeadlineExceeded) {
			failureCode = "DIRECT_ATTEMPT_TIMEOUT"
		}
		if stepErr := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
			Severity: "WARNING", Stage: "HTTP", Code: failureCode,
			Message: "Прямой маршрут не смог получить подписку; будет проверен следующий готовый модем.",
			Details: map[string]any{"attempt": attempt, "route_kind": "DIRECT", "modem_id": currentModem.ID},
		}); stepErr != nil {
			return subscription.FetchResult{}, errors.New("record failed subscription direct route failed")
		}
		if ctx.Err() != nil {
			return subscription.FetchResult{}, ctx.Err()
		}
	}
	if ready == 0 {
		return subscription.FetchResult{}, errors.New("subscription fetch requires at least one ready modem")
	}
	return subscription.FetchResult{}, subscription.WithRetryAfter(errors.New("subscription HTTPS request failed through every ready modem"), requestedRetry)
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
