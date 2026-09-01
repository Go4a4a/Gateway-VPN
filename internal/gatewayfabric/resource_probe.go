package gatewayfabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/managementfabric"
)

type ResourceTransportProbe func(context.Context, string, string, string, int) error

type resourceRoute struct {
	Type    string `json:"type"`
	Gateway string `json:"gateway"`
	Device  string `json:"dev"`
}

// ProbeResource accepts only a stable resource id. It independently reloads
// the typed destination, ports, profile and current topology from SQLite,
// then checks the kernel route and bounded transports. No interface, address,
// command, executable or probe payload crosses the WebUI/root boundary.
func (applier *Applier) ProbeResource(ctx context.Context, resourceID string) (managementfabric.ResourceProbeResult, error) {
	if err := applier.validate(); err != nil {
		return managementfabric.ResourceProbeResult{}, err
	}
	applier.mutex.Lock()
	defer applier.mutex.Unlock()
	spec, err := applier.Repository.LoadResourceProbeSpec(ctx, resourceID)
	if err != nil {
		return managementfabric.ResourceProbeResult{}, err
	}
	checkedAt := applier.now().UTC()
	result := managementfabric.ResourceProbeResult{
		ResourceID: spec.ResourceID, RouteGeneration: spec.RouteGeneration,
		State: failureHealth(spec.AccessProfile), ReasonCode: "RESOURCE_ROUTE_UNAVAILABLE",
		CheckedAt: checkedAt.Format(time.RFC3339Nano), Checks: []managementfabric.ResourceProbeCheck{},
	}
	target, err := resourceProbeAddress(spec.Kind, spec.LocalDestination, spec.HealthProbeAddress)
	if err != nil {
		return managementfabric.ResourceProbeResult{}, err
	}
	route, routeErr := applier.resourceRoute(ctx, target)
	if routeErr == nil {
		result.Interface, result.Gateway = route.Device, route.Gateway
		routeErr = validateResourceRoute(spec, route)
		if routeErr == nil && spec.AccessProfile == managementfabric.ProfileWireGuardRouter {
			routeErr = applier.validateWireGuardResourceRoute(ctx, spec)
		}
	}
	if routeErr != nil {
		result.ReasonCode = resourceRouteReason(spec.AccessProfile, routeErr)
		if err := applier.Repository.RecordResourceProbe(ctx, result); err != nil {
			return managementfabric.ResourceProbeResult{}, err
		}
		return result, nil
	}
	if spec.AccessProfile == managementfabric.ProfileDedicatedLAN {
		defaults, defaultErr := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "show", "table", "main", "default", "dev", route.Device}, nil))
		var defaultRows []json.RawMessage
		if defaultErr != nil || json.Unmarshal([]byte(defaults.Stdout), &defaultRows) != nil {
			result.ReasonCode = "DEDICATED_DEFAULT_ROUTE_CHECK_FAILED"
			if err := applier.Repository.RecordResourceProbe(ctx, result); err != nil {
				return managementfabric.ResourceProbeResult{}, err
			}
			return result, nil
		}
		if len(defaultRows) != 0 {
			result.ReasonCode = "DEDICATED_INTERFACE_HAS_DEFAULT_ROUTE"
			if err := applier.Repository.RecordResourceProbe(ctx, result); err != nil {
				return managementfabric.ResourceProbeResult{}, err
			}
			return result, nil
		}
	}

	for _, port := range spec.Ports {
		check := managementfabric.ResourceProbeCheck{Protocol: port.Protocol, Port: port.PortStart, State: "FAILED"}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		switch port.Protocol {
		case managementfabric.ProtocolICMP:
			_, err = applier.Executor.Run(probeCtx, request(applier.Paths.Ping, []string{"-n", "-c", "1", "-W", "2", "-I", route.Device, target}, nil))
		case managementfabric.ProtocolTCP, managementfabric.ProtocolUDP:
			probe := applier.TransportProbe
			if probe == nil {
				probe = defaultResourceTransportProbe
			}
			err = probe(probeCtx, strings.ToLower(port.Protocol), route.Device, target, port.PortStart)
		default:
			err = errors.New("unsupported resource probe protocol")
		}
		cancel()
		if err != nil {
			check.ReasonCode = "RESOURCE_TRANSPORT_UNREACHABLE"
			result.Checks = append(result.Checks, check)
			result.ReasonCode = check.ReasonCode
			if recordErr := applier.Repository.RecordResourceProbe(ctx, result); recordErr != nil {
				return managementfabric.ResourceProbeResult{}, recordErr
			}
			return result, nil
		}
		check.State = "PASSED"
		if port.Protocol == managementfabric.ProtocolUDP {
			check.ReasonCode = "UDP_NO_IMMEDIATE_REJECTION"
		}
		result.Checks = append(result.Checks, check)
	}
	result.State, result.ReasonCode = "HEALTHY", "RESOURCE_PROBE_PASSED"
	if spec.Kind == managementfabric.ResourceLocalSubnet {
		result.ReasonCode = "RESOURCE_SUBNET_PATH_CONFIRMED"
	}
	if err := applier.Repository.RecordResourceProbe(ctx, result); err != nil {
		return managementfabric.ResourceProbeResult{}, err
	}
	return result, nil
}

func (applier *Applier) resourceRoute(ctx context.Context, target string) (resourceRoute, error) {
	output, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{"-json", "-4", "route", "get", target}, nil))
	if err != nil {
		return resourceRoute{}, errors.New("resource route lookup failed")
	}
	var rows []resourceRoute
	if json.Unmarshal([]byte(output.Stdout), &rows) != nil || len(rows) != 1 || rows[0].Device == "" {
		return resourceRoute{}, errors.New("resource route lookup returned an invalid projection")
	}
	return rows[0], nil
}

func validateResourceRoute(spec managementfabric.ResourceProbeSpec, route resourceRoute) error {
	if !containsExact(spec.AllowedInterfaces, route.Device) {
		return errors.New("route uses an interface outside the access profile")
	}
	gatewayValid := func() bool {
		address, err := netip.ParseAddr(route.Gateway)
		return err == nil && address.Is4() && address.IsPrivate() && !address.IsUnspecified()
	}
	switch spec.AccessProfile {
	case managementfabric.ProfileGatewayOnly:
		if route.Device != "lo" || route.Gateway != "" || route.Type != "" && route.Type != "local" {
			return errors.New("Gateway service is not a local route")
		}
	case managementfabric.ProfileKeeneticWAN:
		if route.Gateway != "" {
			return errors.New("Keenetic WAN service is not directly connected")
		}
	case managementfabric.ProfileKeeneticWANRouted:
		if !gatewayValid() {
			return errors.New("Keenetic routed profile has no private next hop")
		}
	case managementfabric.ProfileWireGuardRouter:
		if route.Device != "wg-ingress" || route.Gateway != "" {
			return errors.New("resource is not routed through the owned wg-ingress route")
		}
		if spec.ExpectedWireGuardPrefix == "" {
			return errors.New("resource has no matching ROUTER_ROUTED prefix")
		}
	case managementfabric.ProfileDedicatedLAN:
		if route.Gateway != "" {
			return errors.New("dedicated management LAN resource is not directly connected")
		}
	default:
		return errors.New("unknown resource access profile")
	}
	return nil
}

func (applier *Applier) validateWireGuardResourceRoute(ctx context.Context, spec managementfabric.ResourceProbeSpec) error {
	result, err := applier.Executor.Run(ctx, request(applier.Paths.IP, []string{
		"-json", "-4", "route", "show", "table", "main", "exact", spec.ExpectedWireGuardPrefix,
		"dev", "wg-ingress", "protocol", fmt.Sprint(managementfabric.OwnedRouteProtocol),
	}, nil))
	if err != nil || !exactOwnedRoute(result.Stdout, spec.ExpectedWireGuardPrefix, "wg-ingress") {
		return errors.New("resource has no exact owned wg-ingress route")
	}
	return nil
}

func resourceProbeAddress(kind, destination, healthProbeAddress string) (string, error) {
	if kind != managementfabric.ResourceLocalSubnet {
		address, err := netip.ParseAddr(destination)
		if err != nil || !address.Is4() {
			return "", errors.New("resource probe destination is invalid")
		}
		return address.String(), nil
	}
	prefix, err := netip.ParsePrefix(destination)
	target, targetErr := netip.ParseAddr(healthProbeAddress)
	if err != nil || targetErr != nil || !prefix.Addr().Is4() || !target.Is4() || !prefix.Contains(target) {
		return "", errors.New("resource probe subnet is invalid")
	}
	return target.String(), nil
}

func failureHealth(profile string) string {
	if profile == managementfabric.ProfileGatewayOnly {
		return "FAILED"
	}
	return "WAITING_EXTERNAL_CONFIGURATION"
}

func resourceRouteReason(profile string, _ error) string {
	switch profile {
	case managementfabric.ProfileGatewayOnly:
		return "GATEWAY_LOCAL_ROUTE_MISSING"
	case managementfabric.ProfileKeeneticWAN:
		return "KEENETIC_WAN_PATH_NOT_CONFIRMED"
	case managementfabric.ProfileKeeneticWANRouted:
		return "KEENETIC_FIREWALL_OR_RETURN_PATH_REQUIRED"
	case managementfabric.ProfileWireGuardRouter:
		return "WG_ROUTER_ROUTE_NOT_CONFIRMED"
	case managementfabric.ProfileDedicatedLAN:
		return "DEDICATED_MANAGEMENT_INTERFACE_REQUIRED"
	default:
		return "RESOURCE_ROUTE_UNAVAILABLE"
	}
}

func containsExact(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

func formatResourceEndpoint(address string, port int) string {
	return fmt.Sprintf("%s:%d", address, port)
}
