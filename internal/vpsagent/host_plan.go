package vpsagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"gateway-vpn/internal/wgingress"
)

const (
	VPSManagementInterface = "wg-mgmt"
	VPSManagementPort      = 51821
	VPSOwnedRouteProtocol  = 186
	VPSHubAddressPrefix    = "10.80.0.1/24"
	VPSHubAddress          = "10.80.0.1"
	VPSDefaultWebUIPort    = 8443
)

// VPSHostPlan is a mutation-free, typed projection for the later privileged
// reconciler. It deliberately cannot carry commands, arbitrary interfaces,
// wildcard routes, foreign nftables objects, or private key material.
type VPSHostPlan struct {
	Generation         int64               `json:"generation"`
	InterfaceName      string              `json:"interface_name"`
	ListenPort         int                 `json:"listen_port"`
	RouteProtocol      int                 `json:"route_protocol"`
	InterfaceAddresses []string            `json:"interface_addresses"`
	Peers              []VPSHostPeer       `json:"peers"`
	ResourceRoutes     []VPSHostRoute      `json:"resource_routes"`
	ACL                []VPSHostACLRule    `json:"acl"`
	HubAdminSources    []string            `json:"hub_admin_sources"`
	AdminRelays        []VPSHostAdminRelay `json:"admin_relays"`
}

type VPSHostAdminRelay struct {
	ID                 string `json:"id"`
	GatewayPeerID      string `json:"gateway_peer_id"`
	PublicEndpointHost string `json:"public_endpoint_host"`
	PublicBindAddress  string `json:"public_bind_address"`
	PublicUDPPort      int    `json:"public_udp_port"`
	GatewayAddress     string `json:"gateway_address"`
	VPSSourceAddress   string `json:"vps_source_address"`
	DestinationPort    int    `json:"destination_port"`
	RateLimitPerSecond int    `json:"rate_limit_per_second"`
	BurstPackets       int    `json:"burst_packets"`
}

type VPSHostPeer struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	PublicKey  string   `json:"public_key"`
	Address    string   `json:"address"`
	WebUIPort  int      `json:"webui_port,omitempty"`
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
		RouteProtocol: VPSOwnedRouteProtocol, InterfaceAddresses: []string{VPSHubAddressPrefix},
	}
	gatewayRows, err := repository.Database.QueryContext(ctx, `
SELECT id,public_key,assigned_subnet,assigned_address,remote_address,webui_url
FROM gateway_peers WHERE state!='REVOKED' ORDER BY id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	gatewayPrefixes := map[string][]string{}
	for gatewayRows.Next() {
		var id, publicKey, subnetText, gatewayText, vpsText, webUIURL string
		if err := gatewayRows.Scan(&id, &publicKey, &subnetText, &gatewayText, &vpsText, &webUIURL); err != nil {
			gatewayRows.Close()
			return VPSHostPlan{}, err
		}
		subnet, subnetErr := netip.ParsePrefix(subnetText)
		gatewayAddress, gatewayErr := netip.ParseAddr(gatewayText)
		vpsAddress, vpsErr := netip.ParseAddr(vpsText)
		webUIPort, portErr := gatewayWebUIPort(webUIURL)
		if subnetErr != nil || gatewayErr != nil || vpsErr != nil || portErr != nil || !wgingress.ValidKey(publicKey) || subnet.Bits() < 16 || subnet.Bits() > 30 || !subnet.Contains(gatewayAddress) || !subnet.Contains(vpsAddress) || gatewayAddress == vpsAddress {
			gatewayRows.Close()
			return VPSHostPlan{}, errors.New("stored Gateway host projection is invalid")
		}
		plan.InterfaceAddresses = append(plan.InterfaceAddresses, netip.PrefixFrom(vpsAddress, subnet.Bits()).String())
		gatewayPrefixes[id] = []string{netip.PrefixFrom(gatewayAddress, 32).String()}
		plan.Peers = append(plan.Peers, VPSHostPeer{ID: id, Kind: "GATEWAY", PublicKey: publicKey, Address: netip.PrefixFrom(gatewayAddress, 32).String(), WebUIPort: webUIPort})
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
SELECT id,public_key,assigned_address,trust_mode FROM admin_peers WHERE state!='REVOKED' ORDER BY id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	for adminRows.Next() {
		var id, publicKey, addressText, trustMode string
		if err := adminRows.Scan(&id, &publicKey, &addressText, &trustMode); err != nil {
			adminRows.Close()
			return VPSHostPlan{}, err
		}
		address, err := canonicalPrivateAddress(addressText)
		if err != nil || !wgingress.ValidKey(publicKey) {
			adminRows.Close()
			return VPSHostPlan{}, errors.New("stored administrator host projection is invalid")
		}
		if trustMode == TrustRoutedHub {
			prefix := netip.PrefixFrom(address, 32).String()
			plan.Peers = append(plan.Peers, VPSHostPeer{ID: id, Kind: "ADMIN", PublicKey: publicKey, Address: prefix, AllowedIPs: []string{prefix}})
			plan.HubAdminSources = append(plan.HubAdminSources, prefix)
		} else if trustMode != TrustEndToEndRelay {
			adminRows.Close()
			return VPSHostPlan{}, errors.New("stored administrator trust mode is invalid")
		}
	}
	if err := adminRows.Close(); err != nil {
		return VPSHostPlan{}, err
	}
	aclRows, err := repository.Database.QueryContext(ctx, `
SELECT grant.id,grant.admin_peer_id,publication.gateway_peer_id,publication.id,
       admin.assigned_address,publication.published_alias,grant.protocol,grant.port_start,grant.port_end
FROM acl_grants AS grant
JOIN admin_peers AS admin ON admin.id=grant.admin_peer_id AND admin.state!='REVOKED'
    AND admin.trust_mode='ROUTED_HUB'
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
	relayRows, err := repository.Database.QueryContext(ctx, `
SELECT relay.id,relay.gateway_peer_id,relay.public_endpoint_host,relay.public_bind_address,
       relay.public_udp_port,gateway.assigned_address,gateway.remote_address,
       relay.destination_port,relay.rate_limit_per_second,relay.burst_packets
FROM admin_relays AS relay
JOIN gateway_peers AS gateway ON gateway.id=relay.gateway_peer_id AND gateway.state!='REVOKED'
WHERE relay.enabled=1 AND relay.state NOT IN ('DISABLED','CONFLICT','FAILED')
ORDER BY relay.id`)
	if err != nil {
		return VPSHostPlan{}, err
	}
	for relayRows.Next() {
		var item VPSHostAdminRelay
		if err := relayRows.Scan(&item.ID, &item.GatewayPeerID, &item.PublicEndpointHost,
			&item.PublicBindAddress, &item.PublicUDPPort, &item.GatewayAddress,
			&item.VPSSourceAddress, &item.DestinationPort, &item.RateLimitPerSecond,
			&item.BurstPackets); err != nil {
			relayRows.Close()
			return VPSHostPlan{}, err
		}
		plan.AdminRelays = append(plan.AdminRelays, item)
	}
	if err := relayRows.Close(); err != nil {
		return VPSHostPlan{}, err
	}
	sort.Slice(plan.Peers, func(i, j int) bool {
		return plan.Peers[i].Kind+"\x00"+plan.Peers[i].ID < plan.Peers[j].Kind+"\x00"+plan.Peers[j].ID
	})
	sort.Slice(plan.ResourceRoutes, func(i, j int) bool {
		return plan.ResourceRoutes[i].PublicationID < plan.ResourceRoutes[j].PublicationID
	})
	sort.Slice(plan.ACL, func(i, j int) bool { return plan.ACL[i].ID < plan.ACL[j].ID })
	sort.Slice(plan.AdminRelays, func(i, j int) bool { return plan.AdminRelays[i].ID < plan.AdminRelays[j].ID })
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
	if len(plan.InterfaceAddresses) == 0 || len(plan.InterfaceAddresses) > maximumGateways+1 || !containsString(plan.InterfaceAddresses, VPSHubAddressPrefix) {
		return errors.New("VPS host-plan interface addresses are invalid")
	}
	interfaceNetworks := make([]netip.Prefix, 0, len(plan.InterfaceAddresses))
	interfaceSources := make(map[string]string, len(plan.InterfaceAddresses))
	previousInterface := ""
	for _, raw := range plan.InterfaceAddresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 16 || prefix.Bits() > 30 || prefix.Addr().IsUnspecified() || prefix.String() != raw || raw <= previousInterface {
			return errors.New("VPS host-plan contains an unsafe interface address")
		}
		previousInterface = raw
		network := prefix.Masked()
		for _, current := range interfaceNetworks {
			if current.Overlaps(network) {
				return errors.New("VPS host-plan interface subnets overlap")
			}
		}
		interfaceNetworks = append(interfaceNetworks, network)
		interfaceSources[network.String()] = prefix.Addr().String()
	}
	keys := map[string]struct{}{}
	peerIDs := map[string]struct{}{}
	peerKinds := map[string]string{}
	adminAddresses := map[string]struct{}{}
	previousPeer := ""
	for _, peer := range plan.Peers {
		peerOrder := peer.Kind + "\x00" + peer.ID
		address, addressErr := hostPlanPrefix(peer.Address)
		validPort := peer.Kind == "GATEWAY" && peer.WebUIPort >= 1 && peer.WebUIPort <= 65535 || peer.Kind == "ADMIN" && peer.WebUIPort == 0
		if !hubIdentifierPattern.MatchString(peer.ID) || peer.Kind != "GATEWAY" && peer.Kind != "ADMIN" || !wgingress.ValidKey(peer.PublicKey) || len(peer.AllowedIPs) == 0 || addressErr != nil || address.Bits() != 32 || !validPort || peerOrder <= previousPeer {
			return errors.New("VPS host-plan peer is invalid")
		}
		previousPeer = peerOrder
		if _, exists := keys[peer.PublicKey]; exists {
			return errors.New("VPS host-plan peer public key is duplicated")
		}
		if _, exists := peerIDs[peer.ID]; exists {
			return errors.New("VPS host-plan peer id is duplicated")
		}
		keys[peer.PublicKey] = struct{}{}
		peerIDs[peer.ID] = struct{}{}
		peerKinds[peer.ID] = peer.Kind
		if peer.Kind == "ADMIN" {
			adminAddresses[address.String()] = struct{}{}
		}
		if peer.Kind == "GATEWAY" {
			contained := false
			for _, network := range interfaceNetworks {
				contained = contained || network.Contains(address.Addr())
			}
			if !contained {
				return errors.New("VPS Gateway peer is outside every owned interface subnet")
			}
		}
		previousAllowed := ""
		for _, raw := range peer.AllowedIPs {
			prefix, err := hostPlanPrefix(raw)
			if err != nil || prefix.Bits() == 0 || raw <= previousAllowed {
				return errors.New("VPS host-plan peer contains an unsafe AllowedIPs value")
			}
			previousAllowed = raw
		}
		if !containsString(peer.AllowedIPs, address.String()) {
			return errors.New("VPS host-plan peer address is missing from AllowedIPs")
		}
	}
	previousRoute := ""
	for _, route := range plan.ResourceRoutes {
		if route.Protocol != VPSOwnedRouteProtocol {
			return errors.New("VPS host-plan route ownership changed")
		}
		if peerKinds[route.GatewayPeerID] != "GATEWAY" || route.PublicationID <= previousRoute {
			return errors.New("VPS host-plan route has no peer")
		}
		previousRoute = route.PublicationID
		if _, err := hostPlanPrefix(route.Destination); err != nil {
			return err
		}
	}
	previousACL := ""
	for _, rule := range plan.ACL {
		if peerKinds[rule.AdminPeerID] != "ADMIN" || rule.ID <= previousACL {
			return errors.New("VPS host-plan ACL has no administrator peer")
		}
		previousACL = rule.ID
		if peerKinds[rule.GatewayPeerID] != "GATEWAY" {
			return errors.New("VPS host-plan ACL has no Gateway peer")
		}
		if _, err := hostPlanPrefix(rule.Source); err != nil {
			return err
		}
		if _, err := hostPlanPrefix(rule.Destination); err != nil || !validPorts(rule.Protocol, rule.PortStart, rule.PortEnd) {
			return errors.New("VPS host-plan ACL is invalid")
		}
	}
	previousSource := ""
	for _, source := range plan.HubAdminSources {
		if _, exists := adminAddresses[source]; !exists || source <= previousSource {
			return errors.New("VPS host-plan Hub administrator source is invalid")
		}
		previousSource = source
	}
	previousRelay := ""
	relayPorts := map[string]struct{}{}
	for _, relay := range plan.AdminRelays {
		gateway := netip.Prefix{}
		vpsSource := netip.Prefix{}
		expectedVPSSource := ""
		for _, peer := range plan.Peers {
			if peer.Kind == "GATEWAY" && peer.ID == relay.GatewayPeerID {
				gateway, _ = hostPlanPrefix(peer.Address)
				for _, network := range interfaceNetworks {
					if network.Contains(gateway.Addr()) {
						expectedVPSSource = interfaceSources[network.String()]
						break
					}
				}
			}
		}
		var err error
		vpsSource, err = hostPlanPrefix(relay.VPSSourceAddress)
		bind, bindErr := netip.ParseAddr(relay.PublicBindAddress)
		portKey := relay.PublicBindAddress + "\x00" + strconv.Itoa(relay.PublicUDPPort)
		if !hubIdentifierPattern.MatchString(relay.ID) || relay.ID <= previousRelay || gateway.Bits() != 32 ||
			relay.GatewayAddress != gateway.Addr().String() || err != nil || vpsSource.Bits() != 32 || relay.VPSSourceAddress != expectedVPSSource ||
			bindErr != nil || !bind.Is4() || !bind.IsGlobalUnicast() || bind.IsUnspecified() || bind.IsLoopback() || bind.IsLinkLocalUnicast() ||
			!validRelayHost(relay.PublicEndpointHost) || relay.PublicUDPPort < 1 || relay.PublicUDPPort > 65535 || relay.PublicUDPPort == VPSManagementPort ||
			relay.DestinationPort != AdminRelayDestinationPort || relay.RateLimitPerSecond < 1 || relay.RateLimitPerSecond > 10000 || relay.BurstPackets < 1 || relay.BurstPackets > 10000 {
			return errors.New("VPS host-plan administrator relay is invalid")
		}
		if _, exists := relayPorts[portKey]; exists {
			return errors.New("VPS host-plan administrator relay port is duplicated")
		}
		relayPorts[portKey] = struct{}{}
		previousRelay = relay.ID
	}
	return nil
}

func gatewayWebUIPort(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return VPSDefaultWebUIPort, nil
	}
	canonical, err := canonicalWebUIURL(value)
	if err != nil {
		return 0, err
	}
	parsed, err := url.Parse(canonical)
	if err != nil {
		return 0, errors.New("stored Gateway WebUI URL is invalid")
	}
	if parsed.Port() == "" {
		return 443, nil
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("stored Gateway WebUI port is invalid")
	}
	return port, nil
}

// ValidateHostPlan exposes the same strict validation to the privileged VPS
// reconciler without expanding the plan into a generic command surface.
func ValidateHostPlan(plan VPSHostPlan) error { return validateVPSHostPlan(plan) }

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

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
