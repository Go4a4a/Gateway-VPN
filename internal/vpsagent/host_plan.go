package vpsagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"gateway-vpn/internal/wgingress"
)

const (
	VPSManagementInterface = "wg-mgmt"
	VPSManagementPort      = 51821
	VPSOwnedRouteProtocol  = 186
)

// VPSHostPlan is a mutation-free, typed projection for the later privileged
// reconciler. It deliberately cannot carry commands, arbitrary interfaces,
// wildcard routes, foreign nftables objects, or private key material.
type VPSHostPlan struct {
	Generation         int64            `json:"generation"`
	InterfaceName      string           `json:"interface_name"`
	ListenPort         int              `json:"listen_port"`
	RouteProtocol      int              `json:"route_protocol"`
	InterfaceAddresses []string         `json:"interface_addresses"`
	Peers              []VPSHostPeer    `json:"peers"`
	ResourceRoutes     []VPSHostRoute   `json:"resource_routes"`
	ACL                []VPSHostACLRule `json:"acl"`
	HubAdminSources    []string         `json:"hub_admin_sources"`
}

type VPSHostPeer struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

type VPSHostRoute struct {
	PublicationID string `json:"publication_id"`
	GatewayPeerID string `json:"gateway_peer_id"`
	Destination   string `json:"destination"`
	Protocol      int    `json:"protocol"`
}

type VPSHostACLRule struct {
	ID            string `json:"id"`
	AdminPeerID   string `json:"admin_peer_id"`
	GatewayPeerID string `json:"gateway_peer_id"`
	PublicationID string `json:"publication_id"`
	Source        string `json:"source"`
	Destination   string `json:"destination"`
	Protocol      string `json:"protocol"`
	PortStart     int    `json:"port_start"`
	PortEnd       int    `json:"port_end"`
}

func (repository HubRepository) RenderHostPlan(ctx context.Context) (VPSHostPlan, error) {
	if repository.Database == nil {
		return VPSHostPlan{}, errors.New("VPS Agent database is required")
	}
	if err := Verify(ctx, repository.Database); err != nil {
		return VPSHostPlan{}, err
	}
	generation, err := repository.fabricGeneration(ctx)
	if err != nil {
		return VPSHostPlan{}, err
	}
	plan := VPSHostPlan{
		Generation: generation, InterfaceName: VPSManagementInterface, ListenPort: VPSManagementPort,
		RouteProtocol: VPSOwnedRouteProtocol,
	}
	gatewayRows, err := repository.Database.QueryContext(ctx, `
SELECT id,public_key,assigned_subnet,assigned_address,remote_address
FROM gateway_peers WHERE state!='REVOKED' ORDER BY id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	gatewayPrefixes := map[string][]string{}
	for gatewayRows.Next() {
		var id, publicKey, subnetText, gatewayText, vpsText string
		if err := gatewayRows.Scan(&id, &publicKey, &subnetText, &gatewayText, &vpsText); err != nil {
			gatewayRows.Close()
			return VPSHostPlan{}, err
		}
		subnet, subnetErr := netip.ParsePrefix(subnetText)
		gatewayAddress, gatewayErr := netip.ParseAddr(gatewayText)
		vpsAddress, vpsErr := netip.ParseAddr(vpsText)
		if subnetErr != nil || gatewayErr != nil || vpsErr != nil || !wgingress.ValidKey(publicKey) || subnet.Bits() < 16 || subnet.Bits() > 30 || !subnet.Contains(gatewayAddress) || !subnet.Contains(vpsAddress) || gatewayAddress == vpsAddress {
			gatewayRows.Close()
			return VPSHostPlan{}, errors.New("stored Gateway host projection is invalid")
		}
		plan.InterfaceAddresses = append(plan.InterfaceAddresses, netip.PrefixFrom(vpsAddress, subnet.Bits()).String())
		gatewayPrefixes[id] = []string{netip.PrefixFrom(gatewayAddress, 32).String()}
		plan.Peers = append(plan.Peers, VPSHostPeer{ID: id, Kind: "GATEWAY", PublicKey: publicKey})
	}
	if err := gatewayRows.Close(); err != nil {
		return VPSHostPlan{}, err
	}
	publicationRows, err := repository.Database.QueryContext(ctx, `
SELECT id,gateway_peer_id,published_alias
FROM resource_publications
WHERE enabled=1 AND state!='DISABLED'
ORDER BY id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	for publicationRows.Next() {
		var publicationID, gatewayID, alias string
		if err := publicationRows.Scan(&publicationID, &gatewayID, &alias); err != nil {
			publicationRows.Close()
			return VPSHostPlan{}, err
		}
		prefix, err := hostPlanPrefix(alias)
		if err != nil {
			publicationRows.Close()
			return VPSHostPlan{}, err
		}
		if _, exists := gatewayPrefixes[gatewayID]; !exists {
			publicationRows.Close()
			return VPSHostPlan{}, errors.New("resource publication has no active Gateway host peer")
		}
		gatewayPrefixes[gatewayID] = append(gatewayPrefixes[gatewayID], prefix.String())
		plan.ResourceRoutes = append(plan.ResourceRoutes, VPSHostRoute{PublicationID: publicationID, GatewayPeerID: gatewayID, Destination: prefix.String(), Protocol: VPSOwnedRouteProtocol})
	}
	if err := publicationRows.Close(); err != nil {
		return VPSHostPlan{}, err
	}
	for index := range plan.Peers {
		plan.Peers[index].AllowedIPs = uniqueSorted(gatewayPrefixes[plan.Peers[index].ID])
	}
	adminRows, err := repository.Database.QueryContext(ctx, `
SELECT id,public_key,assigned_address FROM admin_peers WHERE state!='REVOKED' ORDER BY id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	for adminRows.Next() {
		var id, publicKey, addressText string
		if err := adminRows.Scan(&id, &publicKey, &addressText); err != nil {
			adminRows.Close()
			return VPSHostPlan{}, err
		}
		address, err := canonicalPrivateAddress(addressText)
		if err != nil || !wgingress.ValidKey(publicKey) {
			adminRows.Close()
			return VPSHostPlan{}, errors.New("stored administrator host projection is invalid")
		}
		prefix := netip.PrefixFrom(address, 32).String()
		plan.Peers = append(plan.Peers, VPSHostPeer{ID: id, Kind: "ADMIN", PublicKey: publicKey, AllowedIPs: []string{prefix}})
		plan.HubAdminSources = append(plan.HubAdminSources, prefix)
	}
	if err := adminRows.Close(); err != nil {
		return VPSHostPlan{}, err
	}
	aclRows, err := repository.Database.QueryContext(ctx, `
SELECT grant.id,grant.admin_peer_id,publication.gateway_peer_id,publication.id,
       admin.assigned_address,publication.published_alias,grant.protocol,grant.port_start,grant.port_end
FROM acl_grants AS grant
JOIN admin_peers AS admin ON admin.id=grant.admin_peer_id AND admin.state!='REVOKED'
JOIN resource_publications AS publication ON publication.id=grant.publication_id
    AND publication.enabled=1 AND publication.state!='DISABLED'
JOIN gateway_peers AS gateway ON gateway.id=publication.gateway_peer_id AND gateway.state!='REVOKED'
ORDER BY grant.id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	for aclRows.Next() {
		var rule VPSHostACLRule
		var sourceAddress, destination string
		if err := aclRows.Scan(&rule.ID, &rule.AdminPeerID, &rule.GatewayPeerID, &rule.PublicationID, &sourceAddress, &destination, &rule.Protocol, &rule.PortStart, &rule.PortEnd); err != nil {
			aclRows.Close()
			return VPSHostPlan{}, err
		}
		source, err := canonicalPrivateAddress(sourceAddress)
		if err != nil {
			aclRows.Close()
			return VPSHostPlan{}, err
		}
		destinationPrefix, err := hostPlanPrefix(destination)
		if err != nil || !validPorts(rule.Protocol, rule.PortStart, rule.PortEnd) {
			aclRows.Close()
			return VPSHostPlan{}, errors.New("stored ACL host projection is invalid")
		}
		rule.Source = netip.PrefixFrom(source, 32).String()
		rule.Destination = destinationPrefix.String()
		plan.ACL = append(plan.ACL, rule)
	}
	if err := aclRows.Close(); err != nil {
		return VPSHostPlan{}, err
	}
	sort.Slice(plan.Peers, func(i, j int) bool {
		return plan.Peers[i].Kind+"\x00"+plan.Peers[i].ID < plan.Peers[j].Kind+"\x00"+plan.Peers[j].ID
	})
	sort.Slice(plan.ResourceRoutes, func(i, j int) bool {
		return plan.ResourceRoutes[i].PublicationID < plan.ResourceRoutes[j].PublicationID
	})
	sort.Slice(plan.ACL, func(i, j int) bool { return plan.ACL[i].ID < plan.ACL[j].ID })
	plan.InterfaceAddresses = uniqueSorted(plan.InterfaceAddresses)
	plan.HubAdminSources = uniqueSorted(plan.HubAdminSources)
	if err := validateVPSHostPlan(plan); err != nil {
		return VPSHostPlan{}, err
	}
	return plan, nil
}

func (repository HubRepository) fabricGeneration(ctx context.Context) (int64, error) {
	var raw string
	if err := repository.Database.QueryRowContext(ctx, "SELECT value_json FROM vps_settings WHERE key='fabric'").Scan(&raw); err != nil {
		return 0, err
	}
	var value struct {
		Desired int64 `json:"desired_generation"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil || value.Desired < 1 {
		return 0, errors.New("VPS fabric desired generation is invalid")
	}
	return value.Desired, nil
}

func hostPlanPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		address, addressErr := netip.ParseAddr(value)
		if addressErr != nil {
			return netip.Prefix{}, errors.New("canonical private IPv4 host-plan destination is required")
		}
		prefix = netip.PrefixFrom(address, 32)
	}
	if !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 16 {
		return netip.Prefix{}, errors.New("safe private IPv4 host-plan destination is required")
	}
	return prefix, nil
}

func validateVPSHostPlan(plan VPSHostPlan) error {
	if plan.Generation < 1 || plan.InterfaceName != VPSManagementInterface || plan.ListenPort != VPSManagementPort || plan.RouteProtocol != VPSOwnedRouteProtocol {
		return errors.New("VPS host-plan ownership contract is invalid")
	}
	keys := map[string]struct{}{}
	peerIDs := map[string]struct{}{}
	for _, peer := range plan.Peers {
		if !hubIdentifierPattern.MatchString(peer.ID) || peer.Kind != "GATEWAY" && peer.Kind != "ADMIN" || !wgingress.ValidKey(peer.PublicKey) || len(peer.AllowedIPs) == 0 {
			return errors.New("VPS host-plan peer is invalid")
		}
		if _, exists := keys[peer.PublicKey]; exists {
			return errors.New("VPS host-plan peer public key is duplicated")
		}
		keys[peer.PublicKey] = struct{}{}
		peerIDs[peer.ID] = struct{}{}
		for _, raw := range peer.AllowedIPs {
			prefix, err := hostPlanPrefix(raw)
			if err != nil || prefix.Bits() == 0 {
				return errors.New("VPS host-plan peer contains an unsafe AllowedIPs value")
			}
		}
	}
	for _, route := range plan.ResourceRoutes {
		if route.Protocol != VPSOwnedRouteProtocol {
			return errors.New("VPS host-plan route ownership changed")
		}
		if _, exists := peerIDs[route.GatewayPeerID]; !exists {
			return errors.New("VPS host-plan route has no peer")
		}
		if _, err := hostPlanPrefix(route.Destination); err != nil {
			return err
		}
	}
	for _, rule := range plan.ACL {
		if _, exists := peerIDs[rule.AdminPeerID]; !exists {
			return errors.New("VPS host-plan ACL has no administrator peer")
		}
		if _, exists := peerIDs[rule.GatewayPeerID]; !exists {
			return errors.New("VPS host-plan ACL has no Gateway peer")
		}
		if _, err := hostPlanPrefix(rule.Source); err != nil {
			return err
		}
		if _, err := hostPlanPrefix(rule.Destination); err != nil || !validPorts(rule.Protocol, rule.PortStart, rule.PortEnd) {
			return errors.New("VPS host-plan ACL is invalid")
		}
	}
	return nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
