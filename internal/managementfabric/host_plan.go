package managementfabric

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"gateway-vpn/internal/wgingress"
)

// GatewayHostPlan is the complete typed input for the privileged Gateway
// reconciler. It contains fixed executable-independent values only. Private
// key material never enters SQLite or this plan; root receives only a checked
// reference below the Gateway VPN secret root and gives that path directly to
// wg(8)'s private-key option.
type GatewayHostPlan struct {
	Generation    int64                 `json:"generation"`
	RouteProtocol int                   `json:"route_protocol"`
	Links         []GatewayHostLink     `json:"links"`
	AdminContour  *RenderedAdminContour `json:"admin_contour,omitempty"`
	Aliases       []RenderedAlias       `json:"aliases"`
	ACL           []RenderedACLRule     `json:"acl"`
}

type GatewayHostLink struct {
	LinkID              string          `json:"link_id"`
	VPSID               string          `json:"vps_id"`
	InterfaceName       string          `json:"interface_name"`
	LocalAddress        string          `json:"local_address"`
	ManagementSubnet    string          `json:"management_subnet"`
	RemoteAddress       string          `json:"remote_address"`
	PrivateKeyRef       string          `json:"private_key_ref"`
	LocalPublicKey      string          `json:"local_public_key"`
	RemotePublicKey     string          `json:"remote_public_key"`
	AllowedIPs          []string        `json:"allowed_ips"`
	EndpointAddress     string          `json:"endpoint_address"`
	EndpointPort        int             `json:"endpoint_port"`
	PersistentKeepalive int             `json:"persistent_keepalive"`
	UplinkID            string          `json:"uplink_id"`
	UplinkInterface     string          `json:"uplink_interface"`
	UplinkGateway       string          `json:"uplink_gateway"`
	UplinkTable         int64           `json:"uplink_table"`
	UplinkMark          int64           `json:"uplink_mark"`
	UplinkGeneration    int64           `json:"uplink_generation"`
	Routes              []RenderedRoute `json:"routes"`
}

type hostUplink struct {
	id, ifname, gateway string
	priority, number    int64
	table, mark         int64
	generation          int64
}

// BuildGatewayHostPlan re-reads the complete desired projection in one
// read-only transaction. The caller must compare Generation again when it
// commits applied state; a plan built concurrently with a mutation may never
// be acknowledged as current.
func (repository *Repository) BuildGatewayHostPlan(ctx context.Context) (GatewayHostPlan, error) {
	if repository == nil || repository.Database == nil {
		return GatewayHostPlan{}, errors.New("management database is required")
	}
	tx, err := repository.Database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return GatewayHostPlan{}, fmt.Errorf("begin Gateway host-plan read: %w", err)
	}
	defer tx.Rollback()

	var generation int64
	if err := tx.QueryRowContext(ctx, "SELECT desired_generation FROM management_fabric_generations WHERE singleton_id=1").Scan(&generation); err != nil || generation <= 0 {
		return GatewayHostPlan{}, errors.New("management fabric desired generation is unavailable")
	}
	spec, linkRows, err := repository.fabricSpecTx(ctx, tx)
	if err != nil {
		return GatewayHostPlan{}, err
	}
	rendered, err := RenderFabric(spec)
	if err != nil {
		return GatewayHostPlan{}, err
	}
	uplinks, err := readyHostUplinks(ctx, tx)
	if err != nil {
		return GatewayHostPlan{}, err
	}
	routesByLink := make(map[string][]RenderedRoute)
	for _, route := range rendered.Routes {
		routesByLink[route.LinkID] = append(routesByLink[route.LinkID], route)
	}
	peersByLink := make(map[string]RenderedPeer, len(rendered.Peers))
	for _, peer := range rendered.Peers {
		peersByLink[peer.LinkID] = peer
	}

	plan := GatewayHostPlan{Generation: generation, RouteProtocol: OwnedRouteProtocol, AdminContour: rendered.AdminContour, Aliases: rendered.Aliases, ACL: rendered.ACL}
	for _, link := range linkRows {
		peer, exists := peersByLink[link.ID]
		if !exists {
			return GatewayHostPlan{}, fmt.Errorf("enabled management link %s is absent from rendered peers", link.ID)
		}
		uplink, err := selectHostUplink(link, uplinks)
		if err != nil {
			return GatewayHostPlan{}, err
		}
		endpoint, err := selectHostEndpoint(link.Endpoints, repository.now())
		if err != nil {
			return GatewayHostPlan{}, fmt.Errorf("management link %s: %w", link.ID, err)
		}
		plan.Links = append(plan.Links, GatewayHostLink{
			LinkID: link.ID, VPSID: link.VPSID, InterfaceName: link.InterfaceName,
			LocalAddress: peer.LocalAddress, ManagementSubnet: link.ManagementSubnet,
			RemoteAddress: peer.RemoteAddress, PrivateKeyRef: link.privateKeySecretRef,
			LocalPublicKey: link.LocalPublicKey, RemotePublicKey: peer.RemotePublicKey,
			AllowedIPs:      append([]string(nil), peer.AllowedSources...),
			EndpointAddress: endpoint, EndpointPort: linkEndpointPort(link.Endpoints, endpoint, repository.now()),
			PersistentKeepalive: link.PersistentKeepalive,
			UplinkID:            uplink.id, UplinkInterface: uplink.ifname, UplinkGateway: uplink.gateway,
			UplinkTable: uplink.table, UplinkMark: uplink.mark, UplinkGeneration: uplink.generation,
			Routes: append([]RenderedRoute(nil), routesByLink[link.ID]...),
		})
	}
	if err := ValidateGatewayHostPlan(plan); err != nil {
		return GatewayHostPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return GatewayHostPlan{}, fmt.Errorf("commit Gateway host-plan read: %w", err)
	}
	return plan, nil
}

func (repository *Repository) fabricSpecTx(ctx context.Context, tx *sql.Tx) (FabricSpec, []Link, error) {
	spec := FabricSpec{ReservedPrefixes: append([]ReservedPrefix(nil), repository.ReservedPrefixes...)}
	rows, err := tx.QueryContext(ctx, linkSelect+`
WHERE enabled=1 AND state NOT IN ('DISABLED','REVOKED')
  AND vps_id IN (SELECT id FROM vps_nodes WHERE enabled=1 AND state!='REVOKED')
  AND site_id IN (SELECT id FROM management_sites WHERE is_local=1 AND identity_state='ACTIVE')
ORDER BY slot,id`)
	if err != nil {
		return FabricSpec{}, nil, fmt.Errorf("read enabled management links: %w", err)
	}
	links := make([]Link, 0)
	for rows.Next() {
		item, err := scanLink(rows)
		if err != nil {
			rows.Close()
			return FabricSpec{}, nil, err
		}
		links = append(links, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return FabricSpec{}, nil, fmt.Errorf("iterate enabled management links: %w", err)
	}
	if err := rows.Close(); err != nil {
		return FabricSpec{}, nil, fmt.Errorf("close enabled management links: %w", err)
	}
	for index := range links {
		links[index].Endpoints, err = listEndpointsTx(ctx, tx, links[index].ID)
		if err != nil {
			return FabricSpec{}, nil, err
		}
		item := links[index]
		spec.Links = append(spec.Links, LinkSpec{
			ID: item.ID, SiteID: item.SiteID, VPSID: item.VPSID, Slot: item.Slot,
			InterfaceName: item.InterfaceName, ManagementSubnet: item.ManagementSubnet,
			LocalAddress: item.LocalAddress, RemoteAddress: item.RemoteAddress,
			LocalPrivateKeySecretRef: item.privateKeySecretRef, LocalPublicKey: item.LocalPublicKey,
			RemotePublicKey: item.RemotePublicKey, UplinkPolicy: item.UplinkPolicy,
			PinnedUplinkID: item.PinnedUplinkID, PersistentKeepalive: item.PersistentKeepalive,
			Endpoints: endpointSpecs(item.Endpoints),
		})
	}

	adminRows, err := tx.QueryContext(ctx, `
SELECT a.id,p.vps_id,p.assigned_address,p.trust_mode
FROM management_admin_vps_peers AS p
JOIN management_admins AS a ON a.id=p.admin_id
JOIN vps_nodes AS v ON v.id=p.vps_id
WHERE a.enabled=1 AND a.state='ACTIVE' AND p.state IN ('CONFIGURED','ACTIVE')
  AND v.enabled=1 AND v.state!='REVOKED'
ORDER BY p.id`)
	if err != nil {
		return FabricSpec{}, nil, fmt.Errorf("read management administrators: %w", err)
	}
	for adminRows.Next() {
		var item AdminSpec
		if err := adminRows.Scan(&item.ID, &item.VPSID, &item.AssignedAddress, &item.TrustMode); err != nil {
			adminRows.Close()
			return FabricSpec{}, nil, fmt.Errorf("scan management administrator: %w", err)
		}
		spec.Admins = append(spec.Admins, item)
	}
	if err := adminRows.Close(); err != nil {
		return FabricSpec{}, nil, err
	}

	var contour AdminContourSpec
	contourErr := tx.QueryRowContext(ctx, `
SELECT interface_name,private_key_secret_ref,public_key,subnet,gateway_address,listen_port
FROM management_admin_contour
WHERE singleton_id=1 AND enabled=1 AND state!='DISABLED'`).Scan(
		&contour.InterfaceName, &contour.PrivateKeySecretRef, &contour.PublicKey,
		&contour.Subnet, &contour.GatewayAddress, &contour.ListenPort,
	)
	if contourErr != nil && !errors.Is(contourErr, sql.ErrNoRows) {
		return FabricSpec{}, nil, fmt.Errorf("read administrator contour: %w", contourErr)
	}
	if contourErr == nil {
		spec.AdminContour = &contour
		relayRows, relayErr := tx.QueryContext(ctx, `
SELECT relay.id,relay.link_id,relay.public_endpoint_host,relay.public_bind_address,
       relay.public_udp_port,relay.destination_port,relay.rate_limit_per_second,relay.burst_packets
FROM management_admin_relays AS relay
JOIN management_links AS link ON link.id=relay.link_id
JOIN vps_nodes AS vps ON vps.id=link.vps_id
WHERE relay.enabled=1 AND relay.state NOT IN ('DISABLED','CONFLICT','FAILED')
  AND link.enabled=1 AND link.state NOT IN ('DISABLED','REVOKED')
  AND vps.enabled=1 AND vps.state!='REVOKED'
ORDER BY relay.id`)
		if relayErr != nil {
			return FabricSpec{}, nil, fmt.Errorf("read administrator relays: %w", relayErr)
		}
		for relayRows.Next() {
			var item AdminRelaySpec
			if err := relayRows.Scan(&item.ID, &item.LinkID, &item.PublicEndpointHost, &item.PublicBindAddress,
				&item.PublicUDPPort, &item.DestinationPort, &item.RateLimitPerSecond, &item.BurstPackets); err != nil {
				relayRows.Close()
				return FabricSpec{}, nil, fmt.Errorf("scan administrator relay: %w", err)
			}
			spec.AdminRelays = append(spec.AdminRelays, item)
		}
		if err := relayRows.Close(); err != nil {
			return FabricSpec{}, nil, err
		}

		tunnelRows, tunnelErr := tx.QueryContext(ctx, `
SELECT tunnel.id,tunnel.admin_id,tunnel.relay_id,tunnel.public_key,tunnel.assigned_address
FROM management_admin_tunnels AS tunnel
JOIN management_admin_relays AS relay ON relay.id=tunnel.relay_id
JOIN management_links AS link ON link.id=relay.link_id
JOIN management_admin_vps_peers AS peer
  ON peer.admin_id=tunnel.admin_id AND peer.vps_id=link.vps_id
JOIN management_admins AS admin ON admin.id=tunnel.admin_id
WHERE tunnel.state IN ('CONFIGURED','ACTIVE')
  AND relay.enabled=1 AND relay.state NOT IN ('DISABLED','CONFLICT','FAILED')
  AND peer.state IN ('CONFIGURED','ACTIVE') AND peer.trust_mode='END_TO_END_RELAY'
  AND admin.enabled=1 AND admin.state='ACTIVE'
ORDER BY tunnel.id`)
		if tunnelErr != nil {
			return FabricSpec{}, nil, fmt.Errorf("read administrator tunnels: %w", tunnelErr)
		}
		for tunnelRows.Next() {
			var item AdminTunnelSpec
			if err := tunnelRows.Scan(&item.ID, &item.AdminID, &item.RelayID, &item.PublicKey, &item.AssignedAddress); err != nil {
				tunnelRows.Close()
				return FabricSpec{}, nil, fmt.Errorf("scan administrator tunnel: %w", err)
			}
			spec.AdminTunnels = append(spec.AdminTunnels, item)
		}
		if err := tunnelRows.Close(); err != nil {
			return FabricSpec{}, nil, err
		}
	}

	resourceRows, err := tx.QueryContext(ctx, `
SELECT r.id,r.site_id,r.resource_kind,r.access_profile,r.local_destination,r.advanced_scope_acknowledged
FROM management_resources AS r JOIN management_sites AS s ON s.id=r.site_id
WHERE r.enabled=1 AND s.is_local=1 AND s.identity_state='ACTIVE' ORDER BY r.id`)
	if err != nil {
		return FabricSpec{}, nil, fmt.Errorf("read management resources: %w", err)
	}
	for resourceRows.Next() {
		var item ResourceSpec
		var acknowledged int
		if err := resourceRows.Scan(&item.ID, &item.SiteID, &item.Kind, &item.AccessProfile, &item.LocalDestination, &acknowledged); err != nil {
			resourceRows.Close()
			return FabricSpec{}, nil, fmt.Errorf("scan management resource: %w", err)
		}
		item.AdvancedScopeAcknowledged = acknowledged != 0
		spec.Resources = append(spec.Resources, item)
	}
	if err := resourceRows.Close(); err != nil {
		return FabricSpec{}, nil, err
	}

	publicationRows, err := tx.QueryContext(ctx, `
SELECT p.id,p.resource_id,p.link_id,r.local_destination,p.published_alias
FROM management_resource_publications AS p
JOIN management_resources AS r ON r.id=p.resource_id
JOIN management_links AS l ON l.id=p.link_id
JOIN vps_nodes AS v ON v.id=l.vps_id
JOIN management_sites AS s ON s.id=l.site_id
WHERE r.enabled=1 AND l.enabled=1
  AND p.state NOT IN ('DISABLED','CONFLICT')
  AND l.state NOT IN ('DISABLED','REVOKED') AND v.enabled=1 AND v.state!='REVOKED'
  AND s.is_local=1 AND s.identity_state='ACTIVE'
ORDER BY p.id`)
	if err != nil {
		return FabricSpec{}, nil, fmt.Errorf("read management resource publications: %w", err)
	}
	for publicationRows.Next() {
		var item PublicationSpec
		if err := publicationRows.Scan(&item.ID, &item.ResourceID, &item.LinkID, &item.LocalDestination, &item.PublishedAlias); err != nil {
			publicationRows.Close()
			return FabricSpec{}, nil, fmt.Errorf("scan management resource publication: %w", err)
		}
		spec.Publications = append(spec.Publications, item)
	}
	if err := publicationRows.Close(); err != nil {
		return FabricSpec{}, nil, err
	}

	aclRows, err := tx.QueryContext(ctx, `
SELECT a.id,a.admin_id,a.resource_id,a.protocol,a.port_start,a.port_end
FROM management_resource_acl AS a
WHERE a.enabled=1 AND EXISTS (
    SELECT 1
    FROM management_admin_vps_peers AS ap
    JOIN management_resource_publications AS p ON p.resource_id=a.resource_id
    JOIN management_links AS l ON l.id=p.link_id AND l.vps_id=ap.vps_id
    JOIN management_resources AS r ON r.id=p.resource_id
    JOIN vps_nodes AS v ON v.id=l.vps_id
    WHERE ap.admin_id=a.admin_id AND ap.state IN ('CONFIGURED','ACTIVE')
      AND r.enabled=1 AND l.enabled=1 AND l.state NOT IN ('DISABLED','REVOKED')
      AND p.state NOT IN ('DISABLED','CONFLICT') AND v.enabled=1 AND v.state!='REVOKED'
)
ORDER BY a.id`)
	if err != nil {
		return FabricSpec{}, nil, fmt.Errorf("read management resource ACL: %w", err)
	}
	for aclRows.Next() {
		var item ACLSpec
		if err := aclRows.Scan(&item.ID, &item.AdminID, &item.ResourceID, &item.Protocol, &item.PortStart, &item.PortEnd); err != nil {
			aclRows.Close()
			return FabricSpec{}, nil, fmt.Errorf("scan management resource ACL: %w", err)
		}
		spec.ACL = append(spec.ACL, item)
	}
	if err := aclRows.Close(); err != nil {
		return FabricSpec{}, nil, err
	}
	return spec, links, nil
}

func listEndpointsTx(ctx context.Context, tx *sql.Tx, linkID string) ([]Endpoint, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id,link_id,priority,endpoint_host,endpoint_port,
       COALESCE(resolved_address,''),COALESCE(resolved_expires_at,''),state,last_error_code
FROM management_link_endpoints WHERE link_id=? ORDER BY priority,id`, linkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Endpoint
	for rows.Next() {
		var item Endpoint
		if err := rows.Scan(&item.ID, &item.LinkID, &item.Priority, &item.Host, &item.Port, &item.ResolvedAddress, &item.ResolvedExpiresAt, &item.State, &item.LastErrorCode); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func readyHostUplinks(ctx context.Context, tx *sql.Tx) ([]hostUplink, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT u.id,COALESCE(n.current_ifname,''),u.gateway,u.priority,u.display_number,
       u.routing_table_id,u.fwmark,u.route_generation
FROM uplinks AS u LEFT JOIN network_interfaces AS n ON n.id=u.network_interface_id
WHERE u.enabled=1 AND u.state='UPLINK_READY'
ORDER BY u.priority,u.display_number,u.id`)
	if err != nil {
		return nil, fmt.Errorf("read ready management uplinks: %w", err)
	}
	defer rows.Close()
	var result []hostUplink
	for rows.Next() {
		var item hostUplink
		if err := rows.Scan(&item.id, &item.ifname, &item.gateway, &item.priority, &item.number, &item.table, &item.mark, &item.generation); err != nil {
			return nil, fmt.Errorf("scan ready management uplink: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func selectHostUplink(link Link, ready []hostUplink) (hostUplink, error) {
	byID := make(map[string]hostUplink, len(ready))
	for _, item := range ready {
		byID[item.id] = item
	}
	if link.UplinkPolicy == UplinkPinnedOnly {
		if item, exists := byID[link.PinnedUplinkID]; exists {
			return item, nil
		}
		return hostUplink{}, fmt.Errorf("management link %s pinned uplink is not ready", link.ID)
	}
	if link.UplinkPolicy == UplinkPinnedWithFallback {
		if item, exists := byID[link.PinnedUplinkID]; exists {
			return item, nil
		}
	}
	if item, exists := byID[link.SelectedUplinkID]; exists {
		return item, nil
	}
	if len(ready) == 0 {
		return hostUplink{}, fmt.Errorf("management link %s has no ready uplink", link.ID)
	}
	return ready[0], nil
}

func selectHostEndpoint(endpoints []Endpoint, now time.Time) (string, error) {
	for _, endpoint := range endpoints {
		if address, err := netip.ParseAddr(strings.TrimSpace(endpoint.Host)); err == nil && usableEndpointAddress(address) {
			return address.Unmap().String(), nil
		}
		address, err := netip.ParseAddr(strings.TrimSpace(endpoint.ResolvedAddress))
		expires, expiryErr := time.Parse(time.RFC3339Nano, endpoint.ResolvedExpiresAt)
		if err == nil && usableEndpointAddress(address) && expiryErr == nil && expires.After(now) {
			return address.Unmap().String(), nil
		}
	}
	return "", errors.New("no literal or fresh resolved IPv4 endpoint is available")
}

func linkEndpointPort(endpoints []Endpoint, selected string, now time.Time) int {
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.Host) == selected {
			return endpoint.Port
		}
		if strings.TrimSpace(endpoint.ResolvedAddress) == selected {
			if expires, err := time.Parse(time.RFC3339Nano, endpoint.ResolvedExpiresAt); err == nil && expires.After(now) {
				return endpoint.Port
			}
		}
	}
	return 0
}

func usableEndpointAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is4() && address.IsGlobalUnicast() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func endpointSpecs(items []Endpoint) []EndpointSpec {
	result := make([]EndpointSpec, 0, len(items))
	for _, item := range items {
		result = append(result, EndpointSpec{Host: item.Host, Port: item.Port})
	}
	return result
}

func ValidateGatewayHostPlan(plan GatewayHostPlan) error {
	if plan.Generation <= 0 || plan.Generation > 0xffffffff || plan.RouteProtocol != OwnedRouteProtocol {
		return errors.New("Gateway host plan generation or route ownership is invalid")
	}
	seenInterfaces := make(map[string]struct{}, len(plan.Links))
	seenLinks := make(map[string]struct{}, len(plan.Links))
	for _, link := range plan.Links {
		if !safeIdentifier.MatchString(link.LinkID) || !safeIdentifier.MatchString(link.VPSID) || !validSecretReference(link.PrivateKeyRef) {
			return errors.New("Gateway host link identity or secret reference is invalid")
		}
		if link.InterfaceName != InterfaceNameForSlot(slotFromInterface(link.InterfaceName)) {
			return errors.New("Gateway host link interface is invalid")
		}
		if _, exists := seenLinks[link.LinkID]; exists {
			return errors.New("Gateway host link is duplicated")
		}
		if _, exists := seenInterfaces[link.InterfaceName]; exists {
			return errors.New("Gateway host interface is duplicated")
		}
		seenLinks[link.LinkID], seenInterfaces[link.InterfaceName] = struct{}{}, struct{}{}
		local, localErr := netip.ParsePrefix(link.LocalAddress)
		remote, remoteErr := netip.ParsePrefix(link.RemoteAddress)
		subnet, subnetErr := netip.ParsePrefix(link.ManagementSubnet)
		endpoint, endpointErr := netip.ParseAddr(link.EndpointAddress)
		gateway, gatewayErr := netip.ParseAddr(link.UplinkGateway)
		if localErr != nil || remoteErr != nil || subnetErr != nil || endpointErr != nil || gatewayErr != nil ||
			local.Bits() != 32 || remote.Bits() != 32 || !subnet.Addr().Is4() || subnet.Bits() < 16 || subnet.Bits() > 30 ||
			!subnet.Contains(local.Addr()) || !subnet.Contains(remote.Addr()) || local.Addr() == remote.Addr() ||
			!usableEndpointAddress(endpoint) || !gateway.Is4() || gateway.IsUnspecified() || gateway.IsMulticast() {
			return fmt.Errorf("Gateway host link %s address context is invalid", link.LinkID)
		}
		if !wgingress.ValidKey(link.LocalPublicKey) || !wgingress.ValidKey(link.RemotePublicKey) || link.LocalPublicKey == link.RemotePublicKey ||
			link.EndpointPort < 1 || link.EndpointPort > 65535 || link.PersistentKeepalive < 10 || link.PersistentKeepalive > 60 ||
			!safeIdentifier.MatchString(link.UplinkID) || !validLinuxInterface(link.UplinkInterface) || link.UplinkTable < 256 || link.UplinkTable > 0x7fffffff || link.UplinkMark <= 0 || link.UplinkMark > 0xffffffff || link.UplinkGeneration <= 0 {
			return fmt.Errorf("Gateway host link %s key, endpoint, or uplink context is invalid", link.LinkID)
		}
		if len(link.AllowedIPs) == 0 || len(link.AllowedIPs) > 4097 {
			return fmt.Errorf("Gateway host link %s AllowedIPs cardinality is invalid", link.LinkID)
		}
		for _, raw := range link.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.Addr().IsUnspecified() {
				return fmt.Errorf("Gateway host link %s contains a wildcard AllowedIP", link.LinkID)
			}
		}
		for _, route := range link.Routes {
			if route.LinkID != link.LinkID || route.InterfaceName != link.InterfaceName || route.Protocol != OwnedRouteProtocol || route.Owner != "gateway-vpn" {
				return fmt.Errorf("Gateway host link %s route ownership is invalid", link.LinkID)
			}
			prefix, err := netip.ParsePrefix(route.Destination)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix.Masked() != prefix ||
				(route.Purpose != "MANAGEMENT_LINK" && route.Purpose != "VPS_RESOURCE_ALIAS" && route.Purpose != "ADMIN_PEER") {
				return fmt.Errorf("Gateway host link %s route destination is invalid", link.LinkID)
			}
		}
	}
	adminPeers := make(map[string]RenderedAdminPeer)
	adminRelays := make(map[string]RenderedAdminRelayIngress)
	if plan.AdminContour != nil {
		contour := plan.AdminContour
		if contour.InterfaceName != AdminInterfaceName || !validSecretReference(contour.PrivateKeySecretRef) ||
			!wgingress.ValidKey(contour.PublicKey) || contour.ListenPort != AdminListenPort {
			return errors.New("Gateway administrator contour identity is invalid")
		}
		if _, exists := seenInterfaces[contour.InterfaceName]; exists {
			return errors.New("Gateway administrator contour interface is duplicated")
		}
		seenInterfaces[contour.InterfaceName] = struct{}{}
		subnet, subnetErr := netip.ParsePrefix(contour.Subnet)
		gateway, gatewayErr := netip.ParsePrefix(contour.GatewayAddress)
		if subnetErr != nil || gatewayErr != nil || !subnet.Addr().Is4() || !subnet.Addr().IsPrivate() ||
			subnet.Bits() < 16 || subnet.Bits() > 30 || gateway.Bits() != 32 || !subnet.Contains(gateway.Addr()) {
			return errors.New("Gateway administrator contour address is invalid")
		}
		for _, relay := range contour.Relays {
			link, exists := seenLinks[relay.LinkID]
			_ = link
			outerSource, sourceErr := netip.ParsePrefix(relay.OuterSource)
			outerDestination, destinationErr := netip.ParsePrefix(relay.OuterDestination)
			bind, bindErr := netip.ParseAddr(relay.PublicBindAddress)
			if !exists || !safeIdentifier.MatchString(relay.RelayID) || relay.InputInterface == "" ||
				sourceErr != nil || destinationErr != nil || outerSource.Bits() != 32 || outerDestination.Bits() != 32 ||
				bindErr != nil || !bind.Is4() || !bind.IsGlobalUnicast() || relay.PublicUDPPort < 1 || relay.PublicUDPPort > 65535 ||
				relay.DestinationPort != contour.ListenPort || relay.RateLimitPerSecond < 1 || relay.RateLimitPerSecond > 10000 ||
				relay.BurstPackets < 1 || relay.BurstPackets > 10000 || !validEndpointHost(relay.PublicEndpointHost) {
				return errors.New("Gateway administrator relay projection is invalid")
			}
			var hostLink *GatewayHostLink
			for index := range plan.Links {
				if plan.Links[index].LinkID == relay.LinkID {
					hostLink = &plan.Links[index]
					break
				}
			}
			if hostLink == nil || relay.InputInterface != hostLink.InterfaceName || relay.OuterSource != hostLink.RemoteAddress || relay.OuterDestination != hostLink.LocalAddress {
				return errors.New("Gateway administrator relay escaped its outer link")
			}
			if _, exists := adminRelays[relay.RelayID]; exists {
				return errors.New("Gateway administrator relay is duplicated")
			}
			adminRelays[relay.RelayID] = relay
		}
		for _, peer := range contour.Peers {
			address, addressErr := netip.ParsePrefix(peer.AssignedAddress)
			relay, relayExists := adminRelays[peer.RelayID]
			if !safeIdentifier.MatchString(peer.TunnelID) || !safeIdentifier.MatchString(peer.AdminID) || !relayExists ||
				peer.LinkID != relay.LinkID || !wgingress.ValidKey(peer.PublicKey) || addressErr != nil || address.Bits() != 32 ||
				!subnet.Contains(address.Addr()) || address.Addr() == gateway.Addr() {
				return errors.New("Gateway administrator peer projection is invalid")
			}
			if _, exists := adminPeers[peer.TunnelID]; exists {
				return errors.New("Gateway administrator tunnel is duplicated")
			}
			adminPeers[peer.TunnelID] = peer
		}
	}
	aliases := make(map[string]RenderedAlias, len(plan.Aliases))
	for _, alias := range plan.Aliases {
		if !safeIdentifier.MatchString(alias.PublicationID) || !safeIdentifier.MatchString(alias.ResourceID) ||
			!safeIdentifier.MatchString(alias.LinkID) || !validLinuxInterface(alias.InterfaceName) ||
			!validResourceKind(alias.ResourceKind) || !validAccessProfile(alias.AccessProfile) {
			return errors.New("Gateway host alias identity is invalid")
		}
		if _, exists := seenLinks[alias.LinkID]; !exists {
			return errors.New("Gateway host alias references an unavailable link")
		}
		published, publishedErr := netip.ParsePrefix(alias.PublishedAlias)
		local, localErr := netip.ParsePrefix(alias.LocalDestination)
		if localErr != nil {
			if address, err := netip.ParseAddr(alias.LocalDestination); err == nil {
				local = netip.PrefixFrom(address, 32)
				localErr = nil
			}
		}
		if publishedErr != nil || localErr != nil || !published.Addr().Is4() || !local.Addr().Is4() ||
			published.Bits() == 0 || published.Masked() != published || local.Masked() != local ||
			published.Bits() != local.Bits() || !published.Addr().IsPrivate() || !local.Addr().IsPrivate() {
			return errors.New("Gateway host alias translation is invalid")
		}
		aliases[alias.PublicationID] = alias
	}
	for _, rule := range plan.ACL {
		alias, exists := aliases[rule.PublicationID]
		source, sourceErr := netip.ParsePrefix(rule.Source)
		if !exists || !safeIdentifier.MatchString(rule.RuleID) || !safeIdentifier.MatchString(rule.AdminID) ||
			rule.LinkID != alias.LinkID ||
			rule.ResourceKind != alias.ResourceKind || rule.AccessProfile != alias.AccessProfile ||
			rule.PublishedAlias != alias.PublishedAlias || rule.LocalDestination != alias.LocalDestination ||
			sourceErr != nil || !source.Addr().Is4() || source.Bits() != 32 || source.Addr().IsUnspecified() ||
			validateProtocolPorts(rule.Protocol, rule.PortStart, rule.PortEnd) != nil {
			return errors.New("Gateway host ACL rule is invalid")
		}
		switch rule.TrustMode {
		case TrustRoutedHub:
			if rule.InputInterface != alias.InterfaceName || rule.TunnelID != "" || rule.RelayID != "" {
				return errors.New("Gateway routed-hub ACL binding is invalid")
			}
		case TrustEndToEndRelay:
			peer, peerExists := adminPeers[rule.TunnelID]
			if plan.AdminContour == nil || !peerExists || rule.InputInterface != AdminInterfaceName ||
				rule.RelayID != peer.RelayID || rule.LinkID != peer.LinkID || rule.AdminID != peer.AdminID || rule.Source != peer.AssignedAddress {
				return errors.New("Gateway end-to-end ACL binding is invalid")
			}
		default:
			return errors.New("Gateway host ACL trust mode is invalid")
		}
	}
	return nil
}

func validLinuxInterface(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}
