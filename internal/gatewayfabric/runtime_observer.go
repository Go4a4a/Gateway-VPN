package gatewayfabric

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/managementfabric"
)

// ObserveManagementLinks reads only the expected peer handshake of each link
// in the currently applied typed host plan. It never accepts an interface,
// peer key, executable or path from the broker request.
func (applier *Applier) ObserveManagementLinks(ctx context.Context) (int64, []managementfabric.LinkRuntimeObservation, error) {
	applier.mutex.Lock()
	defer applier.mutex.Unlock()
	if err := applier.validate(); err != nil {
		return 0, nil, err
	}
	plan, err := applier.Repository.BuildGatewayHostPlan(ctx)
	if err != nil {
		return 0, nil, err
	}
	desired, applied, _, _, err := applier.Repository.GatewayFabricGenerations(ctx)
	if err != nil || desired != plan.Generation || applied != plan.Generation {
		return 0, nil, errors.New("management fabric runtime generation is not applied")
	}
	now := applier.now()
	observations := make([]managementfabric.LinkRuntimeObservation, 0, len(plan.Links))
	for _, link := range plan.Links {
		result, readErr := applier.Executor.Run(ctx, request(applier.Paths.WG, []string{"show", link.InterfaceName, "latest-handshakes"}, nil))
		if readErr != nil {
			observations = append(observations, managementfabric.LinkRuntimeObservation{
				LinkID: link.LinkID, State: managementfabric.RuntimeLinkDegraded, ErrorCode: "HANDSHAKE_READ_FAILED",
			})
			continue
		}
		observation := parseLinkHandshake(link.LinkID, link.RemotePublicKey, result.Stdout, now)
		observations = append(observations, observation)
	}
	return plan.Generation, observations, nil
}

func parseLinkHandshake(linkID, expectedPeer, output string, now time.Time) managementfabric.LinkRuntimeObservation {
	invalid := func(code string) managementfabric.LinkRuntimeObservation {
		return managementfabric.LinkRuntimeObservation{LinkID: linkID, State: managementfabric.RuntimeLinkDegraded, ErrorCode: code}
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 || strings.TrimSpace(lines[0]) == "" {
		return invalid("HANDSHAKE_OUTPUT_INVALID")
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 2 || fields[0] != expectedPeer {
		return invalid("HANDSHAKE_OUTPUT_INVALID")
	}
	seconds, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || seconds < 0 {
		return invalid("HANDSHAKE_OUTPUT_INVALID")
	}
	if seconds == 0 {
		return managementfabric.LinkRuntimeObservation{
			LinkID: linkID, State: managementfabric.RuntimeLinkConnecting, ErrorCode: "NEVER_CONNECTED",
		}
	}
	handshake := time.Unix(seconds, 0).UTC()
	if handshake.After(now.Add(30 * time.Second)) {
		return invalid("HANDSHAKE_TIME_INVALID")
	}
	observation := managementfabric.LinkRuntimeObservation{LinkID: linkID, LastHandshakeAt: handshake.Format(time.RFC3339Nano)}
	if now.Sub(handshake) > managementfabric.RuntimeHandshakeFreshness {
		observation.State = managementfabric.RuntimeLinkStale
		observation.ErrorCode = "HANDSHAKE_STALE"
	} else {
		observation.State = managementfabric.RuntimeLinkReachable
	}
	return observation
}
