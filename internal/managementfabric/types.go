// Package managementfabric owns the durable, typed many-to-many management
// model.  It deliberately produces plans only; privileged host mutation lives
// behind later, separately tested root boundaries.
package managementfabric

import (
	"database/sql"
	"time"
)

const (
	UplinkAuto               = "AUTO"
	UplinkPinnedWithFallback = "PINNED_WITH_FALLBACK"
	UplinkPinnedOnly         = "PINNED_ONLY"

	TrustRoutedHub     = "ROUTED_HUB"
	TrustEndToEndRelay = "END_TO_END_RELAY"

	ResourceGatewayService  = "GATEWAY_SERVICE"
	ResourceKeeneticService = "KEENETIC_SERVICE"
	ResourceLocalHost       = "LOCAL_HOST"
	ResourceLocalSubnet     = "LOCAL_SUBNET"
	ResourceCustomService   = "CUSTOM_SERVICE"

	ProfileGatewayOnly       = "GATEWAY_ONLY"
	ProfileKeeneticWAN       = "KEENETIC_WAN"
	ProfileKeeneticWANRouted = "VIA_KEENETIC_WAN_ROUTED"
	ProfileWireGuardRouter   = "VIA_WG_ROUTER"
	ProfileDedicatedLAN      = "VIA_DEDICATED_LAN"

	ProtocolTCP  = "TCP"
	ProtocolUDP  = "UDP"
	ProtocolICMP = "ICMP"

	MaximumLinks     = 4096
	MaximumEndpoints = 8
)

type Site struct {
	ID            string `json:"id"`
	DisplayName   string `json:"display_name"`
	Local         bool   `json:"local"`
	IdentityState string `json:"identity_state"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type VPSNode struct {
	ID                  string `json:"id"`
	DisplayNumber       int64  `json:"number"`
	Name                string `json:"name"`
	Enabled             bool   `json:"enabled"`
	Priority            int64  `json:"priority"`
	VerifiedFingerprint string `json:"verified_fingerprint"`
	PublicKey           string `json:"public_key"`
	AdminAddressPool    string `json:"admin_address_pool"`
	ResourceAliasPool   string `json:"resource_alias_pool"`
	State               string `json:"state"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type Endpoint struct {
	ID                string `json:"id"`
	LinkID            string `json:"link_id"`
	Priority          int    `json:"priority"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	ResolvedAddress   string `json:"resolved_address,omitempty"`
	ResolvedExpiresAt string `json:"resolved_expires_at,omitempty"`
	State             string `json:"state"`
	LastErrorCode     string `json:"last_error_code,omitempty"`
}

type Link struct {
	ID                     string     `json:"id"`
	SiteID                 string     `json:"site_id"`
	VPSID                  string     `json:"vps_id"`
	Slot                   int64      `json:"slot"`
	InterfaceName          string     `json:"interface_name"`
	Enabled                bool       `json:"enabled"`
	ManagementSubnet       string     `json:"management_subnet"`
	LocalAddress           string     `json:"local_address"`
	RemoteAddress          string     `json:"remote_address"`
	LocalPublicKey         string     `json:"local_public_key"`
	RemotePublicKey        string     `json:"remote_public_key"`
	UplinkPolicy           string     `json:"uplink_policy"`
	PinnedUplinkID         string     `json:"pinned_uplink_id,omitempty"`
	SelectedUplinkID       string     `json:"selected_uplink_id,omitempty"`
	PersistentKeepalive    int        `json:"persistent_keepalive"`
	DesiredRouteGeneration int64      `json:"desired_route_generation"`
	AppliedRouteGeneration int64      `json:"applied_route_generation"`
	DesiredACLGeneration   int64      `json:"desired_acl_generation"`
	AppliedACLGeneration   int64      `json:"applied_acl_generation"`
	State                  string     `json:"state"`
	LastErrorCode          string     `json:"last_error_code,omitempty"`
	LastHandshakeAt        string     `json:"last_handshake_at,omitempty"`
	Endpoints              []Endpoint `json:"endpoints"`
	CreatedAt              string     `json:"created_at"`
	UpdatedAt              string     `json:"updated_at"`
	privateKeySecretRef    string
}

type ReservedPrefix struct {
	Owner string
	CIDR  string
}

type LinkSpec struct {
	ID                       string
	SiteID                   string
	VPSID                    string
	Slot                     int64
	InterfaceName            string
	ManagementSubnet         string
	LocalAddress             string
	RemoteAddress            string
	LocalPrivateKeySecretRef string
	LocalPublicKey           string
	RemotePublicKey          string
	UplinkPolicy             string
	PinnedUplinkID           string
	PersistentKeepalive      int
	Endpoints                []EndpointSpec
}

type EndpointSpec struct {
	Host string
	Port int
}

type PublicationSpec struct {
	ID               string
	ResourceID       string
	LinkID           string
	LocalDestination string
	PublishedAlias   string
}

type AdminSpec struct {
	ID              string
	VPSID           string
	AssignedAddress string
}

type ResourceSpec struct {
	ID                        string
	SiteID                    string
	Kind                      string
	AccessProfile             string
	LocalDestination          string
	AdvancedScopeAcknowledged bool
}

type ACLSpec struct {
	ID         string
	AdminID    string
	ResourceID string
	Protocol   string
	PortStart  int
	PortEnd    int
}

type FabricSpec struct {
	Links            []LinkSpec
	Publications     []PublicationSpec
	Admins           []AdminSpec
	Resources        []ResourceSpec
	ACL              []ACLSpec
	ReservedPrefixes []ReservedPrefix
}

type CreateVPSInput struct {
	ID                  string
	Name                string
	VerifiedFingerprint string
	PublicKey           string
	AdminAddressPool    string
	ResourceAliasPool   string
}

type CreateLinkInput struct {
	ID                       string
	SiteID                   string
	VPSID                    string
	Enabled                  bool
	ManagementSubnet         string
	LocalAddress             string
	RemoteAddress            string
	LocalPrivateKeySecretRef string
	LocalPublicKey           string
	RemotePublicKey          string
	UplinkPolicy             string
	PinnedUplinkID           string
	PersistentKeepalive      int
	Endpoints                []EndpointSpec
	// AdoptLegacySlot0 is used only for an already verified pre-successor
	// wg-mgmt contour. New links always allocate monotonically from slot 1.
	AdoptLegacySlot0 bool
}

// PairingBundle is the short-lived file/code created by the VPS. Token is
// accepted only at the boundary and is never persisted or returned by reads.
type PairingBundle struct {
	InvitationID        string `json:"invitation_id"`
	Token               string `json:"token"`
	VPSID               string `json:"vps_id"`
	VPSName             string `json:"vps_name"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	ExpectedPublicKey   string `json:"expected_public_key"`
	AdminAddressPool    string `json:"admin_address_pool"`
	ResourceAliasPool   string `json:"resource_alias_pool"`
	EndpointHost        string `json:"endpoint_host"`
	EndpointPort        int    `json:"endpoint_port"`
	AssignedSubnet      string `json:"assigned_subnet"`
	AssignedLocal       string `json:"assigned_local_address"`
	AssignedRemote      string `json:"assigned_remote_address"`
	ExpiresAt           string `json:"expires_at"`
}

type PairingInvitation struct {
	ID                  string `json:"id"`
	VPSID               string `json:"vps_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	ExpectedPublicKey   string `json:"expected_public_key"`
	EndpointHost        string `json:"endpoint_host"`
	EndpointPort        int    `json:"endpoint_port"`
	AssignedSubnet      string `json:"assigned_subnet"`
	AssignedLocal       string `json:"assigned_local_address"`
	AssignedRemote      string `json:"assigned_remote_address"`
	State               string `json:"state"`
	AttemptCount        int    `json:"attempt_count"`
	ExpiresAt           string `json:"expires_at"`
	ConsumedAt          string `json:"consumed_at,omitempty"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type PairingCompletion struct {
	LinkID                   string
	SiteID                   string
	LocalPrivateKeySecretRef string
	LocalPublicKey           string
	UplinkPolicy             string
	PinnedUplinkID           string
	PersistentKeepalive      int
}

type Repository struct {
	Database         *sql.DB
	ReservedPrefixes []ReservedPrefix
	Now              func() time.Time
}
