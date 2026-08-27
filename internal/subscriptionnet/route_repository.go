package subscriptionnet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gateway-vpn/internal/mihomo"
)

const (
	maximumVPNRouteCandidates = mihomo.MaxGeneratedProxies
	missingPreferredRank      = int64(^uint64(0) >> 1)
)

// VPNRoute identifies one exact service-only route through the loopback
// Mihomo probe selector. It never represents or mutates the user data path.
type VPNRoute struct {
	ModemID            string
	SubscriptionID     string
	NodeID             string
	ExternalName       string
	ProbeGroupName     string
	ProviderNodeName   string
	MethodEnabled      bool
	MethodPriority     int64
	ModemPriority      int64
	PreferredRank      int64
	EvidenceRank       int
	SelectedForPath    bool
	ActiveForTarget    bool
	TargetSubscription bool
}

type RouteRepository struct {
	database *sql.DB
}

func NewRouteRepository(database *sql.DB) *RouteRepository {
	return &RouteRepository{database: database}
}

// ListVPNRoutes returns every currently representable, non-excluded node on
// every ready modem. The active node of the subscription being refreshed is
// first, followed by the remaining nodes of that subscription and then nodes
// of other subscriptions. Stable IDs, not display names, drive ordering.
func (repository *RouteRepository) ListVPNRoutes(ctx context.Context, targetSubscriptionID string) ([]VPNRoute, error) {
	if repository == nil || repository.database == nil || strings.TrimSpace(targetSubscriptionID) == "" {
		return nil, errors.New("route database and target subscription id are required")
	}
	var activeKind, activeModemID, activeSubscriptionID, activeNodeID sql.NullString
	if err := repository.database.QueryRowContext(ctx, `
SELECT active_method_kind, active_modem_id, active_subscription_id, active_node_id
FROM runtime_state WHERE singleton_id=1`).Scan(&activeKind, &activeModemID, &activeSubscriptionID, &activeNodeID); err != nil {
		return nil, fmt.Errorf("read active route identity for subscription refresh: %w", err)
	}
	rows, err := repository.database.QueryContext(ctx, `
SELECT m.id, m.priority, s.id, a.enabled, a.priority,
       n.id, n.external_name, p.selected_node_id,
       pref.preferred_rank, pn.qualification_state
FROM modems AS m
JOIN subscriptions AS s ON s.active_version_id IS NOT NULL
JOIN access_methods AS a
     ON a.kind='SUBSCRIPTION' AND a.subscription_id=s.id
JOIN nodes AS n ON n.version_id=s.active_version_id
LEFT JOIN subscription_node_preferences AS pref
       ON pref.subscription_id=s.id AND pref.fingerprint=n.fingerprint
LEFT JOIN subscription_modem_paths AS p
       ON p.modem_id=m.id AND p.subscription_id=s.id
LEFT JOIN path_nodes AS pn
       ON pn.path_id=p.id AND pn.node_id=n.id
WHERE m.enabled=1 AND m.state='MODEM_READY'
  AND n.enabled=1
  AND COALESCE(pref.selection_override, n.selection_override, 'auto')<>'exclude'
ORDER BY s.id, n.id, m.priority, m.id
LIMIT ?`, maximumVPNRouteCandidates+1)
	if err != nil {
		return nil, fmt.Errorf("list VPN subscription refresh routes: %w", err)
	}
	defer rows.Close()
	routes := make([]VPNRoute, 0)
	for rows.Next() {
		var item VPNRoute
		var methodEnabled int
		var selectedNodeID, qualification sql.NullString
		var preferredRank sql.NullInt64
		if err := rows.Scan(
			&item.ModemID, &item.ModemPriority, &item.SubscriptionID,
			&methodEnabled, &item.MethodPriority, &item.NodeID,
			&item.ExternalName, &selectedNodeID, &preferredRank, &qualification,
		); err != nil {
			return nil, fmt.Errorf("scan VPN subscription refresh route: %w", err)
		}
		item.MethodEnabled = methodEnabled != 0
		item.PreferredRank = missingPreferredRank
		if preferredRank.Valid {
			item.PreferredRank = preferredRank.Int64
		}
		item.SelectedForPath = selectedNodeID.String == item.NodeID
		item.TargetSubscription = item.SubscriptionID == targetSubscriptionID
		item.ActiveForTarget = activeKind.String == "SUBSCRIPTION" &&
			item.TargetSubscription && activeModemID.String == item.ModemID &&
			activeSubscriptionID.String == item.SubscriptionID && activeNodeID.String == item.NodeID
		item.EvidenceRank = routeEvidenceRank(qualification.String)
		names, err := mihomo.StablePathNames(item.ModemID, item.SubscriptionID)
		if err != nil {
			return nil, fmt.Errorf("derive VPN subscription refresh route names: %w", err)
		}
		item.ProbeGroupName = names.ProbeGroupName
		item.ProviderNodeName = names.NodePrefix + item.ExternalName
		routes = append(routes, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate VPN subscription refresh routes: %w", err)
	}
	if len(routes) > maximumVPNRouteCandidates {
		return nil, fmt.Errorf("VPN subscription refresh route count exceeds hard limit %d", maximumVPNRouteCandidates)
	}
	sort.SliceStable(routes, func(left, right int) bool {
		return lessVPNRoute(routes[left], routes[right])
	})
	return routes, nil
}

// ValidateVPNRoute rechecks the exact stable node after the shared Mihomo
// operation lock is held. An EXCLUDE/payload/modem change between inventory
// creation and selection therefore cannot authorize a stale service route.
func (repository *RouteRepository) ValidateVPNRoute(ctx context.Context, route VPNRoute) error {
	if repository == nil || repository.database == nil || route.ModemID == "" || route.SubscriptionID == "" || route.NodeID == "" || route.ExternalName == "" {
		return errors.New("complete VPN subscription refresh route is required")
	}
	var externalName string
	err := repository.database.QueryRowContext(ctx, `
SELECT n.external_name
FROM modems AS m
JOIN subscriptions AS s ON s.id=? AND s.active_version_id IS NOT NULL
JOIN access_methods AS a ON a.kind='SUBSCRIPTION' AND a.subscription_id=s.id
JOIN nodes AS n ON n.id=? AND n.version_id=s.active_version_id
LEFT JOIN subscription_node_preferences AS pref
       ON pref.subscription_id=s.id AND pref.fingerprint=n.fingerprint
WHERE m.id=? AND m.enabled=1 AND m.state='MODEM_READY'
  AND n.enabled=1
  AND COALESCE(pref.selection_override, n.selection_override, 'auto')<>'exclude'`, route.SubscriptionID, route.NodeID, route.ModemID).Scan(&externalName)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("VPN subscription refresh route became stale or excluded")
	}
	if err != nil {
		return fmt.Errorf("revalidate VPN subscription refresh route: %w", err)
	}
	names, err := mihomo.StablePathNames(route.ModemID, route.SubscriptionID)
	if err != nil || externalName != route.ExternalName || names.ProbeGroupName != route.ProbeGroupName || names.NodePrefix+externalName != route.ProviderNodeName {
		return errors.New("VPN subscription refresh route identity changed")
	}
	return nil
}

func lessVPNRoute(left, right VPNRoute) bool {
	leftClass, rightClass := routeClass(left), routeClass(right)
	if leftClass != rightClass {
		return leftClass < rightClass
	}
	if !left.TargetSubscription && left.MethodEnabled != right.MethodEnabled {
		return left.MethodEnabled
	}
	if !left.TargetSubscription && left.MethodPriority != right.MethodPriority {
		return left.MethodPriority < right.MethodPriority
	}
	if left.SelectedForPath != right.SelectedForPath {
		return left.SelectedForPath
	}
	if left.PreferredRank != right.PreferredRank {
		return left.PreferredRank < right.PreferredRank
	}
	if left.EvidenceRank != right.EvidenceRank {
		return left.EvidenceRank < right.EvidenceRank
	}
	if left.ModemPriority != right.ModemPriority {
		return left.ModemPriority < right.ModemPriority
	}
	if left.SubscriptionID != right.SubscriptionID {
		return left.SubscriptionID < right.SubscriptionID
	}
	if left.NodeID != right.NodeID {
		return left.NodeID < right.NodeID
	}
	return left.ModemID < right.ModemID
}

func routeClass(item VPNRoute) int {
	if item.ActiveForTarget {
		return 0
	}
	if item.TargetSubscription {
		return 1
	}
	return 2
}

func routeEvidenceRank(state string) int {
	switch state {
	case "BYPASS_QUALIFIED":
		return 0
	case "BYPASS_LIMITED":
		return 1
	case "UNTESTED", "":
		return 2
	default:
		return 3
	}
}
