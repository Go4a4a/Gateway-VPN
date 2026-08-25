package wireguard

import (
	"sort"
	"time"

	"gateway-vpn/internal/modem"
)

type SelectionPolicy struct {
	ReconnectStable  time.Duration
	FailbackCooldown time.Duration
}

type Selection struct {
	Modem   modem.Modem
	Changed bool
	Reason  string
}

func SelectManagementModem(candidates []modem.Modem, currentID string, lastSwitch, now time.Time, policy SelectionPolicy) Selection {
	eligible := make([]modem.Modem, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Enabled && candidate.State == modem.StateReady && candidate.ManagementReachabilityState == "REACHABLE" {
			eligible = append(eligible, candidate)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].Priority == eligible[j].Priority {
			return eligible[i].DisplayNumber < eligible[j].DisplayNumber
		}
		return eligible[i].Priority < eligible[j].Priority
	})
	if len(eligible) == 0 {
		return Selection{Reason: "NO_REACHABLE_MANAGEMENT_MODEM"}
	}
	var current *modem.Modem
	for index := range eligible {
		if eligible[index].ID == currentID {
			current = &eligible[index]
			break
		}
	}
	preferred := eligible[0]
	if current == nil {
		return Selection{Modem: preferred, Changed: preferred.ID != currentID, Reason: "CURRENT_MODEM_UNAVAILABLE"}
	}
	if current.ID == preferred.ID {
		return Selection{Modem: *current, Reason: "CURRENT_MODEM_PREFERRED"}
	}
	stableSince, err := time.Parse(time.RFC3339Nano, preferred.StableSince)
	stable := err == nil && now.Sub(stableSince) >= policy.ReconnectStable
	cooldownDone := lastSwitch.IsZero() || now.Sub(lastSwitch) >= policy.FailbackCooldown
	if stable && cooldownDone {
		return Selection{Modem: preferred, Changed: true, Reason: "PREFERRED_MODEM_STABLE"}
	}
	return Selection{Modem: *current, Reason: "FAILBACK_HYSTERESIS"}
}
