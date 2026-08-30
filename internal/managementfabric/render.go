package managementfabric

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

const OwnedRouteProtocol = 186

// RenderedFabric is a deterministic, mutation-free projection consumed by
// later root-only Gateway and VPS reconcilers. It cannot express arbitrary
// commands, nft syntax, wildcard routes, or foreign ownership.
type RenderedFabric struct {
	RouteProtocol int               `json:"route_protocol"`
	Peers         []RenderedPeer    `json:"peers"`
	Routes        []RenderedRoute   `json:"routes"`
	Aliases       []RenderedAlias   `json:"aliases"`
	ACL           []RenderedACLRule `json:"acl"`
}

type RenderedPeer struct {
	LinkID          string   `json:"link_id"`
	VPSID           string   `json:"vps_id"`
	InterfaceName   string   `json:"interface_name"`
	LocalAddress    string   `json:"local_address"`
	RemoteAddress   string   `json:"remote_address"`
	RemotePublicKey string   `json:"remote_public_key"`
	AllowedSources  []string `json:"allowed_sources"`
}

type RenderedRoute struct {
	Owner         string `json:"owner"`
	LinkID        string `json:"link_id"`
	InterfaceName string `json:"interface_name"`
	Destination   string `json:"destination"`
	Purpose       string `json:"purpose"`
	Protocol      int    `json:"protocol"`
}

type RenderedAlias struct {
	PublicationID    string `json:"publication_id"`
	ResourceID       string `json:"resource_id"`
	LinkID           string `json:"link_id"`
	InterfaceName    string `json:"interface_name"`
	PublishedAlias   string `json:"published_alias"`
	LocalDestination string `json:"local_destination"`
}

type RenderedACLRule struct {
	RuleID           string `json:"rule_id"`
	AdminID          string `json:"admin_id"`
	ResourceID       string `json:"resource_id"`
	PublicationID    string `json:"publication_id"`
	LinkID           string `json:"link_id"`
	InputInterface   string `json:"input_interface"`
	Source           string `json:"source"`
	PublishedAlias   string `json:"published_alias"`
	LocalDestination string `json:"local_destination"`
	Protocol         string `json:"protocol"`
	PortStart        int    `json:"port_start"`
	PortEnd          int    `json:"port_end"`
}

func RenderFabric(spec FabricSpec) (RenderedFabric, error) {
	if err := ValidateFabric(spec); err != nil {
		return RenderedFabric{}, err
	}
	links := make(map[string]LinkSpec, len(spec.Links))
	admins := make(map[string]AdminSpec, len(spec.Admins))
	publicationsByResource := make(map[string][]PublicationSpec)
	for _, link := range spec.Links {
		links[link.ID] = link
	}
	for _, admin := range spec.Admins {
		admins[admin.ID] = admin
	}
	for _, publication := range spec.Publications {
		publicationsByResource[publication.ResourceID] = append(publicationsByResource[publication.ResourceID], publication)
	}

	result := RenderedFabric{RouteProtocol: OwnedRouteProtocol}
	for _, link := range spec.Links {
		remote, _ := netip.ParseAddr(link.RemoteAddress)
		allowed := []string{netip.PrefixFrom(remote, 32).String()}
		for _, admin := range spec.Admins {
			if admin.VPSID == link.VPSID {
				address, _ := netip.ParseAddr(admin.AssignedAddress)
				allowed = append(allowed, netip.PrefixFrom(address, 32).String())
			}
		}
		sort.Strings(allowed)
		result.Peers = append(result.Peers, RenderedPeer{
			LinkID: link.ID, VPSID: link.VPSID, InterfaceName: link.InterfaceName,
			LocalAddress: link.LocalAddress + "/32", RemoteAddress: link.RemoteAddress + "/32",
			RemotePublicKey: link.RemotePublicKey, AllowedSources: allowed,
		})
		result.Routes = append(result.Routes, RenderedRoute{
			Owner: "gateway-vpn", LinkID: link.ID, InterfaceName: link.InterfaceName,
			Destination: link.ManagementSubnet, Purpose: "MANAGEMENT_LINK", Protocol: OwnedRouteProtocol,
		})
	}
	for _, publication := range spec.Publications {
		link := links[publication.LinkID]
		result.Aliases = append(result.Aliases, RenderedAlias{
			PublicationID: publication.ID, ResourceID: publication.ResourceID,
			LinkID: publication.LinkID, InterfaceName: link.InterfaceName,
			PublishedAlias: publication.PublishedAlias, LocalDestination: publication.LocalDestination,
		})
		result.Routes = append(result.Routes, RenderedRoute{
			Owner: "gateway-vpn", LinkID: link.ID, InterfaceName: link.InterfaceName,
			Destination: publication.PublishedAlias, Purpose: "VPS_RESOURCE_ALIAS", Protocol: OwnedRouteProtocol,
		})
	}
	for _, rule := range spec.ACL {
		admin := admins[rule.AdminID]
		for _, publication := range publicationsByResource[rule.ResourceID] {
			link := links[publication.LinkID]
			if link.VPSID != admin.VPSID {
				continue
			}
			result.ACL = append(result.ACL, RenderedACLRule{
				RuleID: rule.ID, AdminID: rule.AdminID, ResourceID: rule.ResourceID,
				PublicationID: publication.ID, LinkID: link.ID, InputInterface: link.InterfaceName,
				Source: admin.AssignedAddress + "/32", PublishedAlias: publication.PublishedAlias,
				LocalDestination: publication.LocalDestination, Protocol: rule.Protocol,
				PortStart: rule.PortStart, PortEnd: rule.PortEnd,
			})
		}
	}
	sort.Slice(result.Peers, func(i, j int) bool { return result.Peers[i].LinkID < result.Peers[j].LinkID })
	sort.Slice(result.Routes, func(i, j int) bool {
		left := fmt.Sprintf("%s\x00%s\x00%s", result.Routes[i].LinkID, result.Routes[i].Purpose, result.Routes[i].Destination)
		right := fmt.Sprintf("%s\x00%s\x00%s", result.Routes[j].LinkID, result.Routes[j].Purpose, result.Routes[j].Destination)
		return left < right
	})
	sort.Slice(result.Aliases, func(i, j int) bool { return result.Aliases[i].PublicationID < result.Aliases[j].PublicationID })
	sort.Slice(result.ACL, func(i, j int) bool {
		left := result.ACL[i].RuleID + "\x00" + result.ACL[i].PublicationID
		right := result.ACL[j].RuleID + "\x00" + result.ACL[j].PublicationID
		return left < right
	})
	if err := validateRenderedFabric(result); err != nil {
		return RenderedFabric{}, err
	}
	return result, nil
}

func validateRenderedFabric(plan RenderedFabric) error {
	if plan.RouteProtocol != OwnedRouteProtocol {
		return errors.New("management fabric route ownership changed")
	}
	for _, route := range plan.Routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix.Masked() != prefix || route.Protocol != OwnedRouteProtocol || route.Owner != "gateway-vpn" || route.InterfaceName != InterfaceNameForSlot(slotFromInterface(route.InterfaceName)) {
			return fmt.Errorf("rendered management route is unsafe: %+v", route)
		}
	}
	for _, peer := range plan.Peers {
		for _, raw := range peer.AllowedSources {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
				return errors.New("rendered WireGuard peer contains a wildcard AllowedIPs source")
			}
		}
	}
	return nil
}

func slotFromInterface(name string) int64 {
	if name == "wg-mgmt" {
		return 0
	}
	var slot int64 = -1
	if _, err := fmt.Sscanf(name, "gvm%d", &slot); err != nil {
		return -1
	}
	return slot
}
