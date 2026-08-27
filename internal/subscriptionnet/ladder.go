package subscriptionnet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/subscription"
)

type routeSelector interface {
	Select(context.Context, string, string) error
}

type ProxyDialerFactory func(string) (subscription.DialContextFunc, error)
type ProxyResolverFactory func(subscription.DialContextFunc, []string) subscription.Resolver

const (
	routeAttemptTimeout  = 20 * time.Second
	routeLadderTimeout   = 5 * time.Minute
	maximumRouteAttempts = 1024
)

// RouteLadderFetcher tries service-only routes without changing the active
// user path: active node of the target subscription, its other allowed nodes,
// allowed nodes of other subscriptions, and finally direct ready modems when
// policy permits direct service refresh.
type RouteLadderFetcher struct {
	Base            *subscription.Fetcher
	Routes          *RouteRepository
	Policy          *accesspolicy.Repository
	Direct          *ModemBoundFetcher
	Selector        routeSelector
	ProbeAddress    string
	BootstrapDNS    []string
	OperationLock   sync.Locker
	Operations      *operations.Repository
	DialerFactory   ProxyDialerFactory
	ResolverFactory ProxyResolverFactory
}

func NewRouteLadderFetcher(base *subscription.Fetcher, routes *RouteRepository, policy *accesspolicy.Repository, direct *ModemBoundFetcher, selector routeSelector, probeAddress string, bootstrapDNS []string, operationLock sync.Locker, operationRepository *operations.Repository) (*RouteLadderFetcher, error) {
	current := &RouteLadderFetcher{
		Base: base, Routes: routes, Policy: policy, Direct: direct,
		Selector: selector, ProbeAddress: probeAddress,
		BootstrapDNS:  append([]string(nil), bootstrapDNS...),
		OperationLock: operationLock, Operations: operationRepository,
		DialerFactory: newSOCKS5Dialer, ResolverFactory: proxyResolver,
	}
	if current.Direct != nil && current.Direct.Operations == nil {
		current.Direct.Operations = operationRepository
	}
	if err := current.validate(); err != nil {
		return nil, err
	}
	return current, nil
}

func (fetcher *RouteLadderFetcher) Fetch(context.Context, string, subscription.FetchOptions) (subscription.FetchResult, error) {
	return subscription.FetchResult{}, errors.New("route-ladder subscription fetch requires subscription identity")
}

func (fetcher *RouteLadderFetcher) FetchForSubscription(ctx context.Context, subscriptionID, secretURL string, options subscription.FetchOptions) (subscription.FetchResult, error) {
	if err := fetcher.validate(); err != nil {
		return subscription.FetchResult{}, err
	}
	ladderContext, cancelLadder := context.WithTimeout(ctx, routeLadderTimeout)
	defer cancelLadder()
	routes, err := fetcher.Routes.ListVPNRoutes(ladderContext, subscriptionID)
	if err != nil {
		return subscription.FetchResult{}, err
	}
	var requestedRetry time.Duration
	if len(routes) > maximumRouteAttempts {
		routes = routes[:maximumRouteAttempts]
		if err := appendOperationStep(ladderContext, fetcher.Operations, options.OperationID, operations.StepInput{
			Severity: "WARNING", Stage: "ROUTE_SELECTED", Code: "VPN_ROUTE_LIMIT_APPLIED",
			Message: "Число VPN-маршрутов ограничено безопасным лимитом одной операции; после них будет проверен прямой маршрут.",
			Details: map[string]any{"maximum_attempts": maximumRouteAttempts},
		}); err != nil {
			return subscription.FetchResult{}, errors.New("record subscription route limit failed")
		}
	}
	for index, route := range routes {
		attempt := index + 1
		if err := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
			Severity: "INFO", Stage: "ROUTE_SELECTED", Code: "VPN_ROUTE_SELECTED",
			Message: "Проверяется VPN-маршрут для обновления подписки.",
			Details: routeDetails(attempt, route),
		}); err != nil {
			return subscription.FetchResult{}, errors.New("record subscription VPN route attempt failed")
		}
		attemptContext, cancelAttempt := context.WithTimeout(ladderContext, routeAttemptTimeout)
		result, attemptErr := fetcher.fetchVPNRoute(attemptContext, attempt, route, secretURL, options)
		cancelAttempt()
		if attemptErr == nil {
			if err := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
				Severity: "INFO", Stage: "HTTP", Code: "VPN_HTTP_SUCCEEDED",
				Message: "Подписка получена через VPN-маршрут.",
				Details: routeDetails(attempt, route),
			}); err != nil {
				return subscription.FetchResult{}, errors.New("record successful subscription VPN route failed")
			}
			return result, nil
		}
		requestedRetry = largerRetryAfter(requestedRetry, attemptErr)
		if err := appendOperationStep(ctx, fetcher.Operations, options.OperationID, operations.StepInput{
			Severity: "WARNING", Stage: "HTTP", Code: vpnAttemptCode(attemptErr),
			Message: "VPN-маршрут не смог получить подписку; будет проверен следующий разрешённый маршрут.",
			Details: routeDetails(attempt, route),
		}); err != nil {
			return subscription.FetchResult{}, errors.New("record failed subscription VPN route failed")
		}
		if ladderContext.Err() != nil {
			if ctx.Err() != nil {
				return subscription.FetchResult{}, ctx.Err()
			}
			return subscription.FetchResult{}, errors.New("subscription refresh route ladder exhausted its time budget")
		}
	}
	policy, err := fetcher.Policy.GetPolicy(ladderContext)
	if err != nil {
		return subscription.FetchResult{}, errors.New("read direct service refresh policy failed")
	}
	if !policy.DirectServiceRefresh {
		return subscription.FetchResult{}, subscription.WithRetryAfter(errors.New("subscription HTTPS request failed through every permitted VPN route; direct service refresh is disabled"), requestedRetry)
	}
	result, err := fetcher.Direct.FetchForSubscription(ladderContext, subscriptionID, secretURL, options)
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return subscription.FetchResult{}, ctx.Err()
	}
	requestedRetry = largerRetryAfter(requestedRetry, err)
	return subscription.FetchResult{}, subscription.WithRetryAfter(errors.New("subscription HTTPS request failed through every permitted VPN and direct route"), requestedRetry)
}

func (fetcher *RouteLadderFetcher) fetchVPNRoute(ctx context.Context, attempt int, route VPNRoute, secretURL string, options subscription.FetchOptions) (subscription.FetchResult, error) {
	fetcher.OperationLock.Lock()
	defer fetcher.OperationLock.Unlock()
	if err := fetcher.Routes.ValidateVPNRoute(ctx, route); err != nil {
		return subscription.FetchResult{}, errors.New("subscription VPN route became stale")
	}
	if err := fetcher.Selector.Select(ctx, route.ProbeGroupName, route.ProviderNodeName); err != nil {
		return subscription.FetchResult{}, errors.New("select subscription VPN node failed")
	}
	if err := fetcher.Selector.Select(ctx, mihomo.ProbeGroupName, route.ProbeGroupName); err != nil {
		return subscription.FetchResult{}, errors.New("select subscription VPN path failed")
	}
	dial, err := fetcher.DialerFactory(fetcher.ProbeAddress)
	if err != nil {
		return subscription.FetchResult{}, err
	}
	resolver := fetcher.ResolverFactory(dial, fetcher.BootstrapDNS)
	attemptOptions := withRouteProgress(fetcher.Operations, options, routeDetails(attempt, route))
	return fetcher.Base.FetchThrough(ctx, secretURL, attemptOptions, resolver, dial, nil)
}

func (fetcher *RouteLadderFetcher) validate() error {
	if fetcher == nil || fetcher.Base == nil || fetcher.Routes == nil || fetcher.Policy == nil || fetcher.Direct == nil || fetcher.Selector == nil || fetcher.OperationLock == nil || fetcher.Operations == nil || fetcher.DialerFactory == nil || fetcher.ResolverFactory == nil {
		return errors.New("subscription route-ladder dependencies are incomplete")
	}
	if len(fetcher.BootstrapDNS) == 0 || len(fetcher.BootstrapDNS) > 8 {
		return errors.New("subscription route-ladder bootstrap DNS is invalid")
	}
	if _, err := fetcher.DialerFactory(fetcher.ProbeAddress); err != nil {
		return fmt.Errorf("subscription route-ladder proxy listener: %w", err)
	}
	return nil
}

func routeDetails(attempt int, route VPNRoute) map[string]any {
	return map[string]any{
		"attempt": attempt, "route_kind": "VPN", "modem_id": route.ModemID,
		"carrier_subscription_id": route.SubscriptionID, "node_id": route.NodeID,
		"target_subscription": route.TargetSubscription,
	}
}

func vpnAttemptCode(err error) string {
	if err == nil {
		return "VPN_HTTP_SUCCEEDED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "VPN_ATTEMPT_TIMEOUT"
	}
	message := err.Error()
	switch message {
	case "subscription VPN route became stale":
		return "VPN_ROUTE_STALE"
	case "select subscription VPN node failed":
		return "VPN_NODE_SELECT_FAILED"
	case "select subscription VPN path failed":
		return "VPN_PATH_SELECT_FAILED"
	default:
		return "VPN_HTTP_FAILED"
	}
}

func appendOperationStep(ctx context.Context, repository *operations.Repository, operationID string, input operations.StepInput) error {
	if repository == nil || operationID == "" {
		return nil
	}
	progress, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := repository.AppendStep(progress, operationID, input)
	return err
}

func withRouteProgress(repository *operations.Repository, options subscription.FetchOptions, route map[string]any) subscription.FetchOptions {
	result := options
	result.Progress = func(ctx context.Context, progress subscription.FetchProgress) error {
		details := make(map[string]any, len(route)+len(progress.Details))
		for key, value := range route {
			details[key] = value
		}
		for key, value := range progress.Details {
			details[key] = value
		}
		return appendOperationStep(ctx, repository, options.OperationID, operations.StepInput{
			Severity: progress.Severity, Stage: progress.Stage, Code: progress.Code,
			Message: progress.Message, Details: details,
		})
	}
	return result
}

func largerRetryAfter(current time.Duration, err error) time.Duration {
	requested, ok := subscription.FetchRetryAfter(err)
	if ok && requested > current {
		return requested
	}
	return current
}
