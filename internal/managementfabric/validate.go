package managementfabric

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/wgingress"
)

var (
	safeIdentifier    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
	sha256Fingerprint = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

func ValidateVPSInput(input CreateVPSInput) error {
	if !safeIdentifier.MatchString(input.ID) {
		return errors.New("safe VPS id is required")
	}
	if name := strings.TrimSpace(input.Name); name == "" || len(name) > 128 {
		return errors.New("VPS name is required and must not exceed 128 bytes")
	}
	if !sha256Fingerprint.MatchString(strings.TrimSpace(input.VerifiedFingerprint)) {
		return errors.New("verified VPS SHA-256 fingerprint is required")
	}
	if !wgingress.ValidKey(input.PublicKey) {
		return errors.New("valid VPS WireGuard public key is required")
	}
	admin, err := canonicalPrivatePrefix(input.AdminAddressPool, 16, 30)
	if err != nil {
		return errors.New("VPS administrator address pool must be a canonical private IPv4 /16../30")
	}
	aliases, err := canonicalPrivatePrefix(input.ResourceAliasPool, 8, 30)
	if err != nil {
		return errors.New("VPS resource alias pool must be a canonical private IPv4 /8../30")
	}
	if admin.Overlaps(aliases) {
		return errors.New("VPS administrator and resource alias pools overlap")
	}
	return nil
}

func ValidateLinkInput(input CreateLinkInput, slot int64, interfaceName string) error {
	if !safeIdentifier.MatchString(input.ID) || !safeIdentifier.MatchString(input.SiteID) || !safeIdentifier.MatchString(input.VPSID) {
		return errors.New("safe link, site, and VPS ids are required")
	}
	if slot < 0 || slot >= MaximumLinks || interfaceName != InterfaceNameForSlot(slot) {
		return errors.New("management link slot and interface name do not match")
	}
	if input.AdoptLegacySlot0 != (slot == 0) {
		return errors.New("slot 0 is reserved for explicit legacy wg-mgmt adoption")
	}
	prefix, err := canonicalPrivatePrefix(input.ManagementSubnet, 16, 30)
	if err != nil {
		return errors.New("management subnet must be a canonical private IPv4 /16../30")
	}
	local, err := canonicalHostAddress(input.LocalAddress, prefix)
	if err != nil {
		return fmt.Errorf("management local address: %w", err)
	}
	remote, err := canonicalHostAddress(input.RemoteAddress, prefix)
	if err != nil {
		return fmt.Errorf("management remote address: %w", err)
	}
	if local == remote {
		return errors.New("management local and remote addresses must be distinct")
	}
	if !validSecretReference(input.LocalPrivateKeySecretRef) {
		return errors.New("management private key must use a fixed root-owned secret reference")
	}
	if !wgingress.ValidKey(input.LocalPublicKey) || !wgingress.ValidKey(input.RemotePublicKey) || input.LocalPublicKey == input.RemotePublicKey {
		return errors.New("distinct valid management WireGuard public keys are required")
	}
	if input.UplinkPolicy != UplinkAuto && input.UplinkPolicy != UplinkPinnedWithFallback && input.UplinkPolicy != UplinkPinnedOnly {
		return errors.New("management uplink policy is invalid")
	}
	if input.UplinkPolicy == UplinkAuto && strings.TrimSpace(input.PinnedUplinkID) != "" || input.UplinkPolicy != UplinkAuto && !safeIdentifier.MatchString(input.PinnedUplinkID) {
		return errors.New("pinned uplink does not match management uplink policy")
	}
	if input.PersistentKeepalive < 10 || input.PersistentKeepalive > 60 {
		return errors.New("management PersistentKeepalive must be 10..60 seconds")
	}
	return validateEndpoints(input.Endpoints)
}

func InterfaceNameForSlot(slot int64) string {
	if slot == 0 {
		return "wg-mgmt"
	}
	if slot > 0 && slot < MaximumLinks {
		return fmt.Sprintf("gvm%d", slot)
	}
	return ""
}

func ValidateFabric(spec FabricSpec) error {
	links := make(map[string]LinkSpec, len(spec.Links))
	linkSlots := make(map[int64]string, len(spec.Links))
	interfaces := make(map[string]string, len(spec.Links))
	localKeys := make(map[string]string, len(spec.Links))
	prefixes := make([]namedPrefix, 0, len(spec.ReservedPrefixes)+len(spec.Links)+len(spec.Publications))
	for _, reserved := range spec.ReservedPrefixes {
		prefix, err := canonicalPrefix(reserved.CIDR)
		if err != nil || prefix.Bits() == 0 {
			return fmt.Errorf("reserved prefix %q is invalid", reserved.Owner)
		}
		prefixes = append(prefixes, namedPrefix{owner: "reserved:" + reserved.Owner, prefix: prefix})
	}
	for _, link := range spec.Links {
		if !safeIdentifier.MatchString(link.ID) || !safeIdentifier.MatchString(link.SiteID) || !safeIdentifier.MatchString(link.VPSID) {
			return errors.New("fabric link contains an invalid id")
		}
		if _, exists := links[link.ID]; exists {
			return fmt.Errorf("management link %s is duplicated", link.ID)
		}
		if link.Slot < 0 || link.Slot >= MaximumLinks || link.InterfaceName != InterfaceNameForSlot(link.Slot) {
			return fmt.Errorf("management link %s has an invalid slot/interface", link.ID)
		}
		if previous, exists := linkSlots[link.Slot]; exists {
			return fmt.Errorf("management links %s and %s reuse slot %d", previous, link.ID, link.Slot)
		}
		if previous, exists := interfaces[link.InterfaceName]; exists {
			return fmt.Errorf("management links %s and %s reuse interface %s", previous, link.ID, link.InterfaceName)
		}
		if previous, exists := localKeys[link.LocalPublicKey]; exists || !wgingress.ValidKey(link.LocalPublicKey) || !wgingress.ValidKey(link.RemotePublicKey) || link.LocalPublicKey == link.RemotePublicKey {
			if exists {
				return fmt.Errorf("management links %s and %s reuse a local public key", previous, link.ID)
			}
			return fmt.Errorf("management link %s contains an invalid public key", link.ID)
		}
		if !validSecretReference(link.LocalPrivateKeySecretRef) {
			return fmt.Errorf("management link %s private key reference is invalid", link.ID)
		}
		if link.UplinkPolicy != UplinkAuto && link.UplinkPolicy != UplinkPinnedWithFallback && link.UplinkPolicy != UplinkPinnedOnly {
			return fmt.Errorf("management link %s uplink policy is invalid", link.ID)
		}
		if link.UplinkPolicy == UplinkAuto && link.PinnedUplinkID != "" || link.UplinkPolicy != UplinkAuto && !safeIdentifier.MatchString(link.PinnedUplinkID) {
			return fmt.Errorf("management link %s pinned uplink does not match its policy", link.ID)
		}
		if link.PersistentKeepalive < 10 || link.PersistentKeepalive > 60 || validateEndpoints(link.Endpoints) != nil {
			return fmt.Errorf("management link %s keepalive or endpoint list is invalid", link.ID)
		}
		prefix, err := canonicalPrivatePrefix(link.ManagementSubnet, 16, 30)
		if err != nil {
			return fmt.Errorf("management link %s subnet is invalid", link.ID)
		}
		if _, err := canonicalHostAddress(link.LocalAddress, prefix); err != nil {
			return fmt.Errorf("management link %s local address is invalid", link.ID)
		}
		if _, err := canonicalHostAddress(link.RemoteAddress, prefix); err != nil || link.LocalAddress == link.RemoteAddress {
			return fmt.Errorf("management link %s remote address is invalid", link.ID)
		}
		links[link.ID] = link
		linkSlots[link.Slot] = link.ID
		interfaces[link.InterfaceName] = link.ID
		localKeys[link.LocalPublicKey] = link.ID
		prefixes = append(prefixes, namedPrefix{owner: "link:" + link.ID, prefix: prefix})
	}

	admins := make(map[string][]AdminSpec, len(spec.Admins))
	adminAddresses := make(map[string]string, len(spec.Admins))
	adminPeers := make(map[string]struct{}, len(spec.Admins))
	linkAddresses := make(map[string]string, len(spec.Links)*2)
	for _, link := range spec.Links {
		linkAddresses[link.LocalAddress] = link.ID
		linkAddresses[link.RemoteAddress] = link.ID
	}
	for _, admin := range spec.Admins {
		if !safeIdentifier.MatchString(admin.ID) || !safeIdentifier.MatchString(admin.VPSID) {
			return errors.New("fabric administrator reference is invalid")
		}
		address, err := netip.ParseAddr(strings.TrimSpace(admin.AssignedAddress))
		if err != nil || !address.Is4() || !address.IsPrivate() || address.IsUnspecified() || address.IsMulticast() || address.String() != admin.AssignedAddress {
			return fmt.Errorf("administrator %s assigned address is invalid", admin.ID)
		}
		peerKey := admin.ID + "\x00" + admin.VPSID
		if _, exists := adminPeers[peerKey]; exists {
			return fmt.Errorf("administrator %s has duplicate peer on VPS %s", admin.ID, admin.VPSID)
		}
		addressKey := admin.VPSID + "\x00" + admin.AssignedAddress
		if previous, exists := adminAddresses[addressKey]; exists {
			return fmt.Errorf("administrators %s and %s reuse an address on VPS %s", previous, admin.ID, admin.VPSID)
		}
		if linkID, exists := linkAddresses[admin.AssignedAddress]; exists {
			return fmt.Errorf("administrator %s reuses an address from management link %s", admin.ID, linkID)
		}
		admins[admin.ID] = append(admins[admin.ID], admin)
		adminPeers[peerKey] = struct{}{}
		adminAddresses[addressKey] = admin.ID
	}

	resources := make(map[string]ResourceSpec, len(spec.Resources))
	resourcePrefixes := make(map[string]netip.Prefix, len(spec.Resources))
	for _, resource := range spec.Resources {
		prefix, err := validateResource(resource)
		if err != nil {
			return err
		}
		if _, exists := resources[resource.ID]; exists {
			return fmt.Errorf("management resource %s is duplicated", resource.ID)
		}
		resources[resource.ID] = resource
		resourcePrefixes[resource.ID] = prefix
	}

	type publicationBinding struct{ vpsID, siteID string }
	publications := make(map[string]PublicationSpec, len(spec.Publications))
	resourceBindings := make(map[string][]publicationBinding)
	for _, publication := range spec.Publications {
		if !safeIdentifier.MatchString(publication.ID) || !safeIdentifier.MatchString(publication.ResourceID) || !safeIdentifier.MatchString(publication.LinkID) {
			return errors.New("resource publication reference is invalid")
		}
		if _, exists := publications[publication.ID]; exists {
			return fmt.Errorf("resource publication %s is duplicated", publication.ID)
		}
		resource, resourceExists := resources[publication.ResourceID]
		link, linkExists := links[publication.LinkID]
		if !resourceExists || !linkExists || resource.SiteID != link.SiteID {
			return fmt.Errorf("publication %s must reference a resource and link from the same site", publication.ID)
		}
		local, err := parseResourceDestination(resource.Kind, publication.LocalDestination)
		if err != nil || local != resourcePrefixes[resource.ID] {
			return fmt.Errorf("publication %s local destination does not match its resource", publication.ID)
		}
		alias, err := canonicalPrivatePrefix(publication.PublishedAlias, 8, 32)
		if err != nil {
			return fmt.Errorf("publication %s alias is invalid", publication.ID)
		}
		if resource.Kind == ResourceLocalSubnet && alias.Bits() != local.Bits() || resource.Kind != ResourceLocalSubnet && alias.Bits() != 32 {
			return fmt.Errorf("publication %s alias size does not match its resource", publication.ID)
		}
		prefixes = append(prefixes, namedPrefix{owner: "alias:" + publication.ID, prefix: alias})
		publications[publication.ID] = publication
		resourceBindings[publication.ResourceID] = append(resourceBindings[publication.ResourceID], publicationBinding{vpsID: link.VPSID, siteID: link.SiteID})
	}
	if err := rejectOverlaps(prefixes); err != nil {
		return err
	}

	aclIDs := make(map[string]struct{}, len(spec.ACL))
	aclTuples := make(map[string]struct{}, len(spec.ACL))
	for _, rule := range spec.ACL {
		if !safeIdentifier.MatchString(rule.ID) {
			return errors.New("ACL rule id is invalid")
		}
		if _, exists := aclIDs[rule.ID]; exists {
			return fmt.Errorf("ACL rule %s is duplicated", rule.ID)
		}
		adminPeers, adminExists := admins[rule.AdminID]
		resource, resourceExists := resources[rule.ResourceID]
		if !adminExists || !resourceExists {
			return fmt.Errorf("ACL rule %s references an unknown administrator or resource", rule.ID)
		}
		if err := validateProtocolPorts(rule.Protocol, rule.PortStart, rule.PortEnd); err != nil {
			return fmt.Errorf("ACL rule %s: %w", rule.ID, err)
		}
		matchedVPS := false
		for _, admin := range adminPeers {
			for _, binding := range resourceBindings[resource.ID] {
				if binding.vpsID == admin.VPSID && binding.siteID == resource.SiteID {
					matchedVPS = true
					break
				}
			}
			if matchedVPS {
				break
			}
		}
		if !matchedVPS {
			return fmt.Errorf("ACL rule %s has no publication on administrator VPS", rule.ID)
		}
		tuple := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", rule.AdminID, rule.ResourceID, rule.Protocol, rule.PortStart, rule.PortEnd)
		if _, exists := aclTuples[tuple]; exists {
			return fmt.Errorf("ACL grant for administrator %s and resource %s is duplicated", rule.AdminID, rule.ResourceID)
		}
		aclIDs[rule.ID] = struct{}{}
		aclTuples[tuple] = struct{}{}
	}
	return nil
}

type namedPrefix struct {
	owner  string
	prefix netip.Prefix
}

func validateResource(resource ResourceSpec) (netip.Prefix, error) {
	if !safeIdentifier.MatchString(resource.ID) || !safeIdentifier.MatchString(resource.SiteID) {
		return netip.Prefix{}, errors.New("management resource id or site id is invalid")
	}
	if !validResourceKind(resource.Kind) || !validAccessProfile(resource.AccessProfile) {
		return netip.Prefix{}, fmt.Errorf("management resource %s kind or access profile is invalid", resource.ID)
	}
	if resource.Kind == ResourceLocalSubnet && !resource.AdvancedScopeAcknowledged {
		return netip.Prefix{}, fmt.Errorf("management resource %s requires explicit LOCAL_SUBNET acknowledgement", resource.ID)
	}
	prefix, err := parseResourceDestination(resource.Kind, resource.LocalDestination)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("management resource %s destination is invalid", resource.ID)
	}
	return prefix, nil
}

func validResourceKind(value string) bool {
	return value == ResourceGatewayService || value == ResourceKeeneticService || value == ResourceLocalHost || value == ResourceLocalSubnet || value == ResourceCustomService
}

func validAccessProfile(value string) bool {
	return value == ProfileGatewayOnly || value == ProfileKeeneticWAN || value == ProfileKeeneticWANRouted || value == ProfileWireGuardRouter || value == ProfileDedicatedLAN
}

func parseResourceDestination(kind, value string) (netip.Prefix, error) {
	if strings.TrimSpace(value) == "0.0.0.0/0" {
		return netip.Prefix{}, errors.New("default route is forbidden")
	}
	if kind == ResourceLocalSubnet {
		return canonicalPrivatePrefix(value, 8, 30)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is4() || !address.IsPrivate() || address.IsUnspecified() || address.IsMulticast() {
		return netip.Prefix{}, errors.New("private IPv4 host is required")
	}
	return netip.PrefixFrom(address.Unmap(), 32), nil
}

func validateProtocolPorts(protocol string, start, end int) error {
	if protocol == ProtocolICMP {
		if start != 0 || end != 0 {
			return errors.New("ICMP must not contain ports")
		}
		return nil
	}
	if protocol != ProtocolTCP && protocol != ProtocolUDP || start < 1 || end < start || end > 65535 {
		return errors.New("TCP/UDP requires a bounded non-empty port range")
	}
	return nil
}

func validateEndpoints(endpoints []EndpointSpec) error {
	if len(endpoints) == 0 || len(endpoints) > MaximumEndpoints {
		return fmt.Errorf("management link requires 1..%d endpoints", MaximumEndpoints)
	}
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(endpoint.Host), "."))
		if !validEndpointHost(host) || endpoint.Port < 1 || endpoint.Port > 65535 {
			return errors.New("management endpoint host or port is invalid")
		}
		key := net.JoinHostPort(host, fmt.Sprint(endpoint.Port))
		if _, exists := seen[key]; exists {
			return errors.New("management endpoint is duplicated")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validEndpointHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Is4() && address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
	}
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, " /\\\x00") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return strings.Contains(value, ".")
}

func validSecretReference(value string) bool {
	clean := path.Clean(strings.TrimSpace(value))
	return clean == value && strings.HasPrefix(clean, "/var/lib/gateway-vpn/secrets/") && strings.HasSuffix(clean, ".key") && !strings.Contains(clean, "\x00")
}

func canonicalPrivatePrefix(value string, minBits, maxBits int) (netip.Prefix, error) {
	prefix, err := canonicalPrefix(value)
	if err != nil || !prefix.Addr().IsPrivate() || prefix.Bits() < minBits || prefix.Bits() > maxBits {
		return netip.Prefix{}, errors.New("canonical private IPv4 prefix is required")
	}
	return prefix, nil
}

func canonicalPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix {
		return netip.Prefix{}, errors.New("canonical IPv4 prefix is required")
	}
	return prefix, nil
}

func canonicalHostAddress(value string, prefix netip.Prefix) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is4() || address.String() != strings.TrimSpace(value) || !netutil.IsUsableIPv4Host(prefix, address) {
		return netip.Addr{}, errors.New("usable canonical IPv4 host inside management subnet is required")
	}
	return address, nil
}

func rejectOverlaps(prefixes []namedPrefix) error {
	for left := 0; left < len(prefixes); left++ {
		for right := left + 1; right < len(prefixes); right++ {
			if prefixes[left].prefix.Overlaps(prefixes[right].prefix) {
				return fmt.Errorf("network prefixes %s (%s) and %s (%s) overlap", prefixes[left].owner, prefixes[left].prefix, prefixes[right].owner, prefixes[right].prefix)
			}
		}
	}
	return nil
}
