// Package uplink owns the canonical physical Internet-uplink inventory.
package uplink

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"

	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/store"
)

const (
	TypeHiLink   = "HILINK"
	TypeEthernet = "ETHERNET"

	AddressDHCP   = "DHCP"
	AddressStatic = "STATIC"

	StateConfiguredOffline = "UPLINK_CONFIGURED_OFFLINE"
	StateConfiguring       = "UPLINK_CONFIGURING"
	StateReady             = "UPLINK_READY"
	StateSubnetConflict    = "UPLINK_SUBNET_CONFLICT"
	StateDisabled          = "UPLINK_DISABLED"

	ManagedLANInterfaceID = "netif:managed:lan"
)

type Repository struct {
	database          *sql.DB
	routingTableStart int64
	fwmarkStart       int64
	now               func() time.Time
}

type InterfaceObservation struct {
	ID                 string
	StableIdentityKind string
	StableIdentityHash string
	PermanentMAC       string
	TopologyPath       string
	CurrentIfname      string
	Driver             string
	Vendor             string
	Model              string
	CarrierState       string
	Addresses          []string
}

type NetworkInterface struct {
	ID                 string
	StableIdentityKind string
	StableIdentityHash string
	PermanentMAC       string
	TopologyPath       string
	CurrentIfname      string
	Driver             string
	Vendor             string
	Model              string
	CarrierState       string
	AddressesJSON      string
	ObservedAt         string
	ReplacementForID   string
	CreatedAt          string
	UpdatedAt          string
}

// InterfaceRole is the non-secret assignment projected for inventory and UI.
// The stable identity hash remains internal to NetworkInterface persistence and
// must never be serialized by callers.
type InterfaceRole struct {
	Role               string
	UplinkID           string
	DesiredGeneration  int64
	ObservedGeneration int64
	State              string
}

type InterfaceInventory struct {
	NetworkInterface
	Roles []InterfaceRole
}

// InitialLANObservation is the minimum non-secret kernel topology used to
// import installer-owned LAN ports into the stable interface inventory.  The
// import is intentionally separate from ordinary observation: it is allowed
// only for the untouched topology generation and never guesses an uplink.
type InitialLANObservation struct {
	NetworkInterfaceID string
	CurrentIfname      string
	MasterIfname       string
}

type CreateEthernetInput struct {
	ID                 string
	Name               string
	NetworkInterfaceID string
	AddressMode        string
	IPv4CIDR           string
	Gateway            string
	DNS                []string
	MTU                int64
}

type UpdateEthernetInput struct {
	NetworkInterfaceID        string
	AddressMode               string
	IPv4CIDR                  string
	Gateway                   string
	DNS                       []string
	MTU                       int64
	ExpectedDesiredGeneration int64
}

type Uplink struct {
	ID                 string
	DisplayNumber      int64
	Type               string
	Name               string
	Enabled            bool
	Priority           int64
	NetworkInterfaceID string
	CurrentIfname      string
	AddressMode        string
	IPv4CIDR           string
	Gateway            string
	DNSJSON            string
	ConfiguredIPv4CIDR string
	ConfiguredGateway  string
	ConfiguredDNSJSON  string
	MTU                int64
	RoutingTableID     int64
	Fwmark             int64
	RouteGeneration    int64
	DesiredGeneration  int64
	ObservedGeneration int64
	State              string
	ReadinessReason    string
	LastSeenAt         string
	StableSince        string
	CreatedAt          string
	UpdatedAt          string
}

type EthernetRuntimeObservation struct {
	NetworkInterfaceID   string
	InterfaceName        string
	IPv4CIDR             string
	Gateway              string
	DNS                  []string
	State                string
	ReadinessReason      string
	ConfigurationSeen    bool
	RouteIdentityChanged bool
}

type EthernetRuntimeUpdate struct {
	RouteContextChanged bool
	RouteGeneration     int64
	PathsInvalidated    int64
}

type SetEthernetEnabledInput struct {
	Enabled                   bool
	ExpectedDesiredGeneration int64
}

type HiLinkDetails struct {
	Uplink
	OperatorLabel               string
	ObservedOperator            string
	IdentityKind                string
	MaskedSerial                string
	ModemState                  string
	TelemetryState              string
	ManagementReachabilityState string
	APISecretRef                string
}

type ReplacementResult struct {
	UplinkID             string
	PreviousInterfaceID  string
	ReplacementInterface string
	DesiredGeneration    int64
	RouteGeneration      int64
	InvalidatedVPNPaths  int64
	InvalidatedDirect    int64
}

func NewRepository(database *sql.DB, routingTableStart, fwmarkStart uint32) *Repository {
	return &Repository{
		database: database, routingTableStart: int64(routingTableStart),
		fwmarkStart: int64(fwmarkStart), now: time.Now,
	}
}

func (repository *Repository) ObserveInterface(ctx context.Context, input InterfaceObservation) (NetworkInterface, error) {
	if err := validateInterfaceObservation(input); err != nil {
		return NetworkInterface{}, err
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	addresses, err := json.Marshal(input.Addresses)
	if err != nil {
		return NetworkInterface{}, fmt.Errorf("encode interface addresses: %w", err)
	}
	result, err := repository.database.ExecContext(ctx, `
INSERT INTO network_interfaces (
    id, stable_identity_kind, stable_identity_hash, permanent_mac, topology_path,
    current_ifname, driver, vendor, model, carrier_state, addresses_json,
    observed_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    permanent_mac=excluded.permanent_mac,
    topology_path=excluded.topology_path,
    current_ifname=excluded.current_ifname,
    driver=excluded.driver,
    vendor=excluded.vendor,
    model=excluded.model,
    carrier_state=excluded.carrier_state,
    addresses_json=excluded.addresses_json,
    observed_at=excluded.observed_at,
    updated_at=excluded.updated_at
WHERE network_interfaces.stable_identity_kind=excluded.stable_identity_kind
  AND network_interfaces.stable_identity_hash=excluded.stable_identity_hash`,
		input.ID, input.StableIdentityKind, strings.ToLower(input.StableIdentityHash),
		nullIfEmpty(input.PermanentMAC), nullIfEmpty(input.TopologyPath), nullIfEmpty(input.CurrentIfname),
		nullIfEmpty(input.Driver), nullIfEmpty(input.Vendor), nullIfEmpty(input.Model), input.CarrierState,
		string(addresses), now, now, now)
	if err != nil {
		return NetworkInterface{}, fmt.Errorf("store interface observation: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return NetworkInterface{}, errors.New("interface id is already bound to a different stable identity")
	}
	return repository.GetInterface(ctx, input.ID)
}

// EnsureManagedLANInterface publishes the installer-owned virtual LAN bridge
// into the same read model as physical NICs. It is deliberately not observed
// by the physical Ethernet probe and cannot become an uplink. WireGuard
// ingress can therefore bind its local UDP listener to the actual L3 bridge
// seen by nftables instead of incorrectly binding to one bridge member.
func (repository *Repository) EnsureManagedLANInterface(ctx context.Context, ifname, address string) (NetworkInterface, error) {
	if repository == nil || repository.database == nil || !validIfname(ifname) {
		return NetworkInterface{}, errors.New("managed LAN repository and interface are required")
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(address))
	if err != nil || !prefix.Addr().Is4() {
		return NetworkInterface{}, errors.New("managed LAN IPv4 prefix is invalid")
	}
	digest := sha256.Sum256([]byte("gateway-vpn:managed-lan:" + ManagedLANInterfaceID))
	item, err := repository.ObserveInterface(ctx, InterfaceObservation{
		ID: ManagedLANInterfaceID, StableIdentityKind: "MANAGED_VIRTUAL",
		StableIdentityHash: hex.EncodeToString(digest[:]), CurrentIfname: ifname,
		CarrierState: "UNKNOWN", Addresses: []string{prefix.String()},
	})
	if err != nil {
		return NetworkInterface{}, err
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := repository.database.ExecContext(ctx, `
INSERT INTO interface_role_assignments(
    id, network_interface_id, role, desired_generation, observed_generation,
    state, created_at, updated_at
) VALUES('role:managed:lan:management', ?, 'MANAGEMENT', 1, 1, 'ACTIVE', ?, ?)
ON CONFLICT(id) DO UPDATE SET
    network_interface_id=excluded.network_interface_id,
    observed_generation=desired_generation,
    state='ACTIVE', updated_at=excluded.updated_at`, ManagedLANInterfaceID, now, now)
	if err != nil {
		return NetworkInterface{}, fmt.Errorf("publish managed LAN role: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return NetworkInterface{}, errors.New("managed LAN role was not published")
	}
	return item, nil
}

// SeedInitialLANRoles imports the physical LAN selected by the installer after
// the first sysfs observation.  Direct-interface installs match the configured
// L3 interface itself; bridge installs match only physical ports whose current
// kernel master is that bridge.  Once any physical topology role exists, or
// topology generation 1 is no longer untouched, this method is a no-op.
func (repository *Repository) SeedInitialLANRoles(ctx context.Context, configuredLANIfname string, observations []InitialLANObservation) ([]string, error) {
	if repository == nil || repository.database == nil || !validIfname(configuredLANIfname) {
		return nil, errors.New("initial LAN repository and configured interface are required")
	}
	if len(observations) > 64 {
		return nil, errors.New("initial LAN observation set is too large")
	}
	direct := make([]InitialLANObservation, 0, 1)
	bridged := make([]InitialLANObservation, 0, len(observations))
	seen := make(map[string]struct{}, len(observations))
	for _, item := range observations {
		if !validIdentifier(item.NetworkInterfaceID) || !validIfname(item.CurrentIfname) || item.MasterIfname != "" && !validIfname(item.MasterIfname) {
			return nil, errors.New("initial LAN observation is invalid")
		}
		if item.NetworkInterfaceID == ManagedLANInterfaceID {
			return nil, errors.New("managed virtual LAN cannot be imported as a physical member")
		}
		if _, duplicate := seen[item.NetworkInterfaceID]; duplicate {
			return nil, errors.New("initial LAN observation is duplicated")
		}
		seen[item.NetworkInterfaceID] = struct{}{}
		if item.CurrentIfname == configuredLANIfname {
			direct = append(direct, item)
		}
		if item.MasterIfname == configuredLANIfname {
			bridged = append(bridged, item)
		}
	}
	selected := bridged
	if len(direct) != 0 {
		selected = direct
	}
	if len(selected) == 0 {
		return nil, nil
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].NetworkInterfaceID < selected[j].NetworkInterfaceID })

	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin initial LAN role import: %w", err)
	}
	defer tx.Rollback()
	// This harmless conditional write obtains the SQLite writer lock before we
	// inspect roles, preventing a concurrent topology safe-apply from racing the
	// one-time import.
	locked, err := tx.ExecContext(ctx, `
UPDATE topology_profile_state SET updated_at=updated_at
WHERE singleton_id=1 AND desired_generation=1 AND applied_generation=1 AND state='ACTIVE'`)
	if err != nil {
		return nil, fmt.Errorf("lock initial topology generation: %w", err)
	}
	if count, countErr := locked.RowsAffected(); countErr != nil {
		return nil, countErr
	} else if count != 1 {
		return nil, nil
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM interface_role_assignments
WHERE network_interface_id<>? AND role IN ('LAN_MEMBER','MANAGEMENT','WG_ENDPOINT','SHARED_ONE_ARM')`, ManagedLANInterfaceID).Scan(&existing); err != nil {
		return nil, fmt.Errorf("inspect existing physical topology roles: %w", err)
	}
	if existing != 0 {
		return nil, nil
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	seeded := make([]string, 0, len(selected))
	for _, item := range selected {
		var storedIfname string
		if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(current_ifname,'') FROM network_interfaces
WHERE id=? AND stable_identity_kind<>'MANAGED_VIRTUAL'`, item.NetworkInterfaceID).Scan(&storedIfname); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, errors.New("initial LAN interface disappeared before role import")
			}
			return nil, err
		}
		if storedIfname != item.CurrentIfname {
			return nil, errors.New("initial LAN interface name changed before role import")
		}
		var conflicting int
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM interface_role_assignments
WHERE network_interface_id=? AND role IN ('ETHERNET_UPLINK','HILINK_UPLINK')`, item.NetworkInterfaceID).Scan(&conflicting); err != nil {
			return nil, err
		}
		if conflicting != 0 {
			return nil, errors.New("installer LAN interface is already assigned as an uplink")
		}
		for _, role := range []string{"LAN_MEMBER", "MANAGEMENT"} {
			digest := sha256.Sum256([]byte("initial:" + role + ":" + item.NetworkInterfaceID))
			roleID := "role:initial:" + strings.ToLower(role) + ":" + hex.EncodeToString(digest[:8])
			if _, err := tx.ExecContext(ctx, `
INSERT INTO interface_role_assignments(
 id,network_interface_id,role,desired_generation,observed_generation,state,created_at,updated_at
) VALUES(?,?,?,1,1,'ACTIVE',?,?)`, roleID, item.NetworkInterfaceID, role, now, now); err != nil {
				return nil, fmt.Errorf("import initial %s role: %w", role, err)
			}
		}
		seeded = append(seeded, item.NetworkInterfaceID)
	}
	details, err := json.Marshal(map[string]any{"configured_lan_interface": configuredLANIfname, "network_interface_ids": seeded})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO events(occurred_at,severity,type,details_json)
VALUES(?,'INFO','TOPOLOGY_INITIAL_LAN_ROLES_IMPORTED',?)`, now, string(details)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit initial LAN role import: %w", err)
	}
	return seeded, nil
}

func (repository *Repository) GetInterface(ctx context.Context, id string) (NetworkInterface, error) {
	item, err := scanInterface(repository.database.QueryRowContext(ctx, interfaceSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return NetworkInterface{}, store.ErrNotFound
	}
	if err != nil {
		return NetworkInterface{}, fmt.Errorf("get network interface: %w", err)
	}
	return item, nil
}

func (repository *Repository) ListInterfaces(ctx context.Context) ([]InterfaceInventory, error) {
	rows, err := repository.database.QueryContext(ctx, interfaceSelect+" ORDER BY COALESCE(current_ifname, ''), id")
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	defer rows.Close()
	result := make([]InterfaceInventory, 0)
	byID := make(map[string]int)
	for rows.Next() {
		item, err := scanInterface(rows)
		if err != nil {
			return nil, fmt.Errorf("scan network interface: %w", err)
		}
		byID[item.ID] = len(result)
		result = append(result, InterfaceInventory{NetworkInterface: item, Roles: []InterfaceRole{}})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network interfaces: %w", err)
	}
	roleRows, err := repository.database.QueryContext(ctx, `
SELECT network_interface_id, role, COALESCE(uplink_id, ''),
       desired_generation, observed_generation, state
FROM interface_role_assignments
ORDER BY network_interface_id, role, id`)
	if err != nil {
		return nil, fmt.Errorf("list network interface roles: %w", err)
	}
	defer roleRows.Close()
	for roleRows.Next() {
		var interfaceID string
		var role InterfaceRole
		if err := roleRows.Scan(&interfaceID, &role.Role, &role.UplinkID, &role.DesiredGeneration, &role.ObservedGeneration, &role.State); err != nil {
			return nil, fmt.Errorf("scan network interface role: %w", err)
		}
		index, exists := byID[interfaceID]
		if !exists {
			return nil, fmt.Errorf("network interface role references missing interface %s", interfaceID)
		}
		result[index].Roles = append(result[index].Roles, role)
	}
	if err := roleRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network interface roles: %w", err)
	}
	return result, nil
}

func (repository *Repository) CreateEthernet(ctx context.Context, input CreateEthernetInput) (Uplink, error) {
	return repository.createEthernet(ctx, input, false)
}

// ValidateEthernetInput exposes the same bounded validation used by the
// durable repository write. Topology manifests use it before entering a
// privileged network transaction; no database or host mutation occurs here.
func ValidateEthernetInput(input CreateEthernetInput) error {
	return validateEthernetInput(input)
}

// CreateInitialEthernet is used only by the verified first-install topology
// handoff. A one-arm profile starts from the temporary installer LAN, so the
// selected shared port may still carry the two generation-1 installer roles.
// This method permits exactly those role rows and removes them in the same
// SQLite transaction before publishing the durable Ethernet uplink.
func (repository *Repository) CreateInitialEthernet(ctx context.Context, input CreateEthernetInput) (Uplink, error) {
	return repository.createEthernet(ctx, input, true)
}

func (repository *Repository) createEthernet(ctx context.Context, input CreateEthernetInput, allowInitialLANRoles bool) (Uplink, error) {
	if err := validateEthernetInput(input); err != nil {
		return Uplink{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Uplink{}, fmt.Errorf("begin Ethernet uplink creation: %w", err)
	}
	defer transaction.Rollback()
	var interfaceCount, conflictingRoles int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM network_interfaces WHERE id=?", input.NetworkInterfaceID).Scan(&interfaceCount); err != nil {
		return Uplink{}, fmt.Errorf("read network interface: %w", err)
	}
	if interfaceCount != 1 {
		return Uplink{}, store.ErrNotFound
	}
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*) FROM interface_role_assignments
WHERE network_interface_id=? AND role NOT IN ('UNUSED', 'SHARED_ONE_ARM')`, input.NetworkInterfaceID).Scan(&conflictingRoles); err != nil {
		return Uplink{}, fmt.Errorf("read interface roles: %w", err)
	}
	if conflictingRoles != 0 {
		if !allowInitialLANRoles {
			return Uplink{}, errors.New("network interface already has an active role")
		}
		var invalidInitialRoles int
		if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*) FROM interface_role_assignments
WHERE network_interface_id=? AND role NOT IN ('LAN_MEMBER','MANAGEMENT')
   OR network_interface_id=? AND role IN ('LAN_MEMBER','MANAGEMENT') AND
      (desired_generation<>1 OR observed_generation<>1 OR state<>'ACTIVE' OR id NOT LIKE 'role:initial:%')`,
			input.NetworkInterfaceID, input.NetworkInterfaceID).Scan(&invalidInitialRoles); err != nil {
			return Uplink{}, fmt.Errorf("validate temporary initial Ethernet roles: %w", err)
		}
		if invalidInitialRoles != 0 {
			return Uplink{}, errors.New("network interface has non-initial active roles")
		}
		if _, err := transaction.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE network_interface_id=? AND role IN ('LAN_MEMBER','MANAGEMENT') AND id LIKE 'role:initial:%'`, input.NetworkInterfaceID); err != nil {
			return Uplink{}, fmt.Errorf("remove temporary initial LAN roles: %w", err)
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	displayNumber, err := store.AllocateCounter(ctx, transaction, "next_uplink_display_number", 1, now)
	if err != nil {
		return Uplink{}, err
	}
	routingTableID, err := store.AllocateCounter(ctx, transaction, "next_uplink_routing_table", repository.routingTableStart, now)
	if err != nil {
		return Uplink{}, err
	}
	fwmark, err := store.AllocateCounter(ctx, transaction, "next_uplink_fwmark", repository.fwmarkStart, now)
	if err != nil {
		return Uplink{}, err
	}
	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM uplinks WHERE enabled=1").Scan(&priority); err != nil {
		return Uplink{}, fmt.Errorf("allocate uplink priority: %w", err)
	}
	dnsJSON, err := json.Marshal(input.DNS)
	if err != nil {
		return Uplink{}, fmt.Errorf("encode uplink DNS: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE network_interface_id=? AND role='UNUSED'`, input.NetworkInterfaceID); err != nil {
		return Uplink{}, fmt.Errorf("clear unused interface role: %w", err)
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO uplinks (
    id, display_number, type, name, enabled, priority, network_interface_id,
    address_mode, ipv4_cidr, gateway, dns_json,
    configured_ipv4_cidr, configured_gateway, configured_dns_json,
    mtu, routing_table_id, fwmark,
    state, created_at, updated_at
) VALUES (?, ?, 'ETHERNET', ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'UPLINK_CONFIGURED_OFFLINE', ?, ?)`,
		input.ID, displayNumber, strings.TrimSpace(input.Name), priority, input.NetworkInterfaceID,
		input.AddressMode, nullIfEmpty(input.IPv4CIDR), nullIfEmpty(input.Gateway), string(dnsJSON),
		nullIfEmpty(input.IPv4CIDR), nullIfEmpty(input.Gateway), string(dnsJSON),
		nullIfZero(input.MTU), routingTableID, fwmark, now, now)
	if err != nil {
		return Uplink{}, fmt.Errorf("insert Ethernet uplink: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO interface_role_assignments (
    id, network_interface_id, role, uplink_id, created_at, updated_at
) VALUES (?, ?, 'ETHERNET_UPLINK', ?, ?, ?)`,
		"role:uplink:"+input.ID, input.NetworkInterfaceID, input.ID, now, now); err != nil {
		return Uplink{}, fmt.Errorf("assign Ethernet uplink role: %w", err)
	}
	if err := raiseLegacyCounterFloorsTx(ctx, transaction, displayNumber+1, routingTableID+1, fwmark+1, now); err != nil {
		return Uplink{}, err
	}
	if err := appendEventTx(ctx, transaction, now, "UPLINK_CREATED", input.ID, map[string]any{
		"type": TypeEthernet, "display_number": displayNumber, "network_interface_id": input.NetworkInterfaceID,
		"address_mode": input.AddressMode, "routing_table_id": routingTableID, "fwmark": fwmark,
	}); err != nil {
		return Uplink{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Uplink{}, fmt.Errorf("commit Ethernet uplink creation: %w", err)
	}
	return repository.Get(ctx, input.ID)
}

func (repository *Repository) Get(ctx context.Context, id string) (Uplink, error) {
	item, err := scanUplink(repository.database.QueryRowContext(ctx, uplinkSelect+" WHERE u.id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Uplink{}, store.ErrNotFound
	}
	if err != nil {
		return Uplink{}, fmt.Errorf("get uplink: %w", err)
	}
	return item, nil
}

func (repository *Repository) List(ctx context.Context) ([]Uplink, error) {
	rows, err := repository.database.QueryContext(ctx, uplinkSelect+" ORDER BY u.priority, u.display_number")
	if err != nil {
		return nil, fmt.Errorf("list uplinks: %w", err)
	}
	defer rows.Close()
	var result []Uplink
	for rows.Next() {
		item, err := scanUplink(rows)
		if err != nil {
			return nil, fmt.Errorf("scan uplink: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate uplinks: %w", err)
	}
	return result, nil
}

// ReorderEnabled applies one total priority order across HiLink and Ethernet.
// Legacy HiLink rows are updated through their compatibility source so both
// projections remain identical until the bounded legacy tables are removed.
func (repository *Repository) ReorderEnabled(ctx context.Context, orderedIDs []string) error {
	return repository.reorderEnabled(ctx, "", orderedIDs)
}

// ReorderEnabledType preserves positions occupied by other uplink types. It
// keeps the legacy modem endpoint safe while the primary WebUI uses the total
// generic order.
func (repository *Repository) ReorderEnabledType(ctx context.Context, uplinkType string, orderedIDs []string) error {
	if uplinkType != TypeHiLink && uplinkType != TypeEthernet {
		return errors.New("valid uplink type is required")
	}
	return repository.reorderEnabled(ctx, uplinkType, orderedIDs)
}

func (repository *Repository) reorderEnabled(ctx context.Context, typeFilter string, orderedIDs []string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin uplink reorder: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, "SELECT id, type FROM uplinks WHERE enabled=1 ORDER BY priority, display_number")
	if err != nil {
		return fmt.Errorf("list enabled uplinks for reorder: %w", err)
	}
	type typedID struct{ id, uplinkType string }
	var current []typedID
	for rows.Next() {
		var item typedID
		if err := rows.Scan(&item.id, &item.uplinkType); err != nil {
			rows.Close()
			return err
		}
		current = append(current, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	wanted := make(map[string]struct{}, len(orderedIDs))
	for _, id := range orderedIDs {
		if !validIdentifier(id) {
			return errors.New("uplink priority list contains an invalid id")
		}
		if _, duplicate := wanted[id]; duplicate {
			return store.ErrPrioritySetMismatch
		}
		wanted[id] = struct{}{}
	}
	var final []string
	if typeFilter == "" {
		if len(current) != len(orderedIDs) {
			return store.ErrPrioritySetMismatch
		}
		for _, item := range current {
			if _, exists := wanted[item.id]; !exists {
				return store.ErrPrioritySetMismatch
			}
		}
		final = append(final, orderedIDs...)
	} else {
		expected := 0
		for _, item := range current {
			if item.uplinkType == typeFilter {
				expected++
			}
		}
		if expected != len(orderedIDs) {
			return store.ErrPrioritySetMismatch
		}
		position := 0
		for _, item := range current {
			if item.uplinkType == typeFilter {
				id := orderedIDs[position]
				position++
				matched := false
				for _, candidate := range current {
					if candidate.id == id && candidate.uplinkType == typeFilter {
						matched = true
						break
					}
				}
				if !matched {
					return store.ErrPrioritySetMismatch
				}
				final = append(final, id)
			} else {
				final = append(final, item.id)
			}
		}
	}
	// Global display numbers are unique, so negative temporary priorities are
	// collision-free in both the legacy modem table and generic uplink table.
	if _, err := transaction.ExecContext(ctx, "UPDATE modems SET priority=-display_number WHERE enabled=1"); err != nil {
		return fmt.Errorf("clear legacy modem priorities: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE uplinks SET priority=-display_number WHERE enabled=1"); err != nil {
		return fmt.Errorf("clear generic uplink priorities: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for index, id := range final {
		priority := int64((index + 1) * 10)
		var uplinkType string
		if err := transaction.QueryRowContext(ctx, "SELECT type FROM uplinks WHERE id=? AND enabled=1", id).Scan(&uplinkType); err != nil {
			return store.ErrPrioritySetMismatch
		}
		var result sql.Result
		if uplinkType == TypeHiLink {
			result, err = transaction.ExecContext(ctx, "UPDATE modems SET priority=?, updated_at=? WHERE id=? AND enabled=1", priority, now, id)
		} else {
			result, err = transaction.ExecContext(ctx, "UPDATE uplinks SET priority=?, updated_at=? WHERE id=? AND enabled=1 AND type='ETHERNET'", priority, now, id)
		}
		if err != nil {
			return fmt.Errorf("set uplink priority: %w", err)
		}
		if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	if err := appendEventTx(ctx, transaction, now, "UPLINK_PRIORITY_REORDERED", "", map[string]any{"ordered_uplink_ids": final}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) SetEthernetEnabled(ctx context.Context, id string, input SetEthernetEnabledInput) (Uplink, error) {
	if !validIdentifier(id) || input.ExpectedDesiredGeneration < 1 {
		return Uplink{}, errors.New("Ethernet uplink and expected generation are required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Uplink{}, fmt.Errorf("begin Ethernet enabled update: %w", err)
	}
	defer transaction.Rollback()
	var uplinkType string
	var currentEnabled int
	var currentDesired, currentRoute, priority int64
	if err := transaction.QueryRowContext(ctx, `
SELECT type, enabled, desired_generation, route_generation, priority
FROM uplinks WHERE id=?`, id).Scan(&uplinkType, &currentEnabled, &currentDesired, &currentRoute, &priority); errors.Is(err, sql.ErrNoRows) {
		return Uplink{}, store.ErrNotFound
	} else if err != nil {
		return Uplink{}, err
	}
	if uplinkType != TypeEthernet {
		return Uplink{}, errors.New("only an Ethernet uplink can use generic enabled control")
	}
	if currentDesired != input.ExpectedDesiredGeneration {
		return Uplink{}, store.ErrStaleGeneration
	}
	if input.Enabled == (currentEnabled != 0) {
		return Uplink{}, errors.New("Ethernet enabled state is unchanged")
	}
	if !input.Enabled {
		var active int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM runtime_state WHERE singleton_id=1 AND active_uplink_id=?", id).Scan(&active); err != nil {
			return Uplink{}, err
		}
		if active != 0 {
			return Uplink{}, errors.New("active Ethernet uplink must be blocked before disabling")
		}
	} else if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority),0)+10 FROM uplinks WHERE enabled=1").Scan(&priority); err != nil {
		return Uplink{}, err
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	state, reason, pathState := StateDisabled, "DISABLED_BY_USER", "UPLINK_DISABLED"
	if input.Enabled {
		state, reason, pathState = StateConfiguredOffline, "NOT_OBSERVED", "UPLINK_OFFLINE"
	}
	nextDesired, nextRoute := currentDesired+1, currentRoute+1
	result, err := transaction.ExecContext(ctx, `
UPDATE uplinks
SET enabled=?, priority=?, desired_generation=?, observed_generation=0,
    route_generation=?, state=?, readiness_reason=?, stable_since=NULL,
    updated_at=?
WHERE id=? AND desired_generation=? AND type='ETHERNET'`,
		boolInt(input.Enabled), priority, nextDesired, nextRoute, state, reason, now, id, currentDesired)
	if err != nil {
		return Uplink{}, fmt.Errorf("update Ethernet enabled state: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return Uplink{}, store.ErrStaleGeneration
	}
	roleState := "OFFLINE"
	if input.Enabled {
		roleState = "CONFIGURED"
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE interface_role_assignments
SET desired_generation=desired_generation+1, observed_generation=0,
    state=?, updated_at=?
WHERE uplink_id=? AND role='ETHERNET_UPLINK'`, roleState, now, id); err != nil {
		return Uplink{}, err
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=?, state=?, transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, last_checked_at=NULL,
    expires_at=NULL, updated_at=? WHERE uplink_id=?`, nextRoute, pathState, now, id); err != nil {
		return Uplink{}, err
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=?, state=?, transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0,
    whitelist_targets_passed=0, last_checked_at=NULL, expires_at=NULL,
    updated_at=? WHERE uplink_id=?`, nextRoute, pathState, now, id); err != nil {
		return Uplink{}, err
	}
	if err := appendEventTx(ctx, transaction, now, "ETHERNET_ENABLED_CHANGED", id, map[string]any{
		"enabled": input.Enabled, "desired_generation": nextDesired, "route_generation": nextRoute,
	}); err != nil {
		return Uplink{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Uplink{}, err
	}
	return repository.Get(ctx, id)
}

// MarkUnseenEthernetInterfacesAbsent closes stale ifname ownership after a
// hot-unplug or rename. HiLink and virtual-role records are intentionally not
// touched by the generic Ethernet observer.
func (repository *Repository) MarkUnseenEthernetInterfacesAbsent(ctx context.Context, seen map[string]struct{}) error {
	rows, err := repository.database.QueryContext(ctx, `
SELECT id FROM network_interfaces
WHERE stable_identity_kind LIKE 'ETHERNET\_%' ESCAPE '\'`)
	if err != nil {
		return fmt.Errorf("list generic Ethernet interfaces: %w", err)
	}
	var missing []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan generic Ethernet interface: %w", err)
		}
		if _, present := seen[id]; !present {
			missing = append(missing, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate generic Ethernet interfaces: %w", err)
	}
	if len(missing) == 0 {
		return nil
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin absent Ethernet observation: %w", err)
	}
	defer transaction.Rollback()
	for _, id := range missing {
		if _, err := transaction.ExecContext(ctx, `
UPDATE network_interfaces
SET current_ifname=NULL, carrier_state='ABSENT', addresses_json='[]',
    observed_at=?, updated_at=?
WHERE id=? AND stable_identity_kind LIKE 'ETHERNET\_%' ESCAPE '\'`, now, now, id); err != nil {
			return fmt.Errorf("mark Ethernet interface absent: %w", err)
		}
	}
	return transaction.Commit()
}

// EthernetApplyInProgress prevents a temporary safe-apply candidate from
// becoming eligible before explicit confirmation. Candidate JSON is decoded
// in Go rather than interpolated into SQL.
func (repository *Repository) EthernetApplyInProgress(ctx context.Context, uplinkID string) (bool, error) {
	if !validIdentifier(uplinkID) {
		return false, errors.New("valid Ethernet uplink id is required")
	}
	rows, err := repository.database.QueryContext(ctx, `
SELECT candidate_json FROM network_apply_transactions
WHERE operation_kind='ETHERNET_UPLINK'
  AND state IN ('PREPARING','ARMED','APPLIED','CONFIRMING')`)
	if err != nil {
		return false, fmt.Errorf("list active Ethernet safe applies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return false, fmt.Errorf("scan active Ethernet safe apply: %w", err)
		}
		var candidate struct {
			UplinkID string `json:"uplink_id"`
		}
		if err := json.Unmarshal([]byte(payload), &candidate); err != nil {
			return false, errors.New("active Ethernet safe apply metadata is invalid")
		}
		if candidate.UplinkID == uplinkID {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ObserveEthernetRuntime is the sole transition from desired Ethernet
// configuration to observed eligibility. It invalidates only this uplink's
// evidence whenever the effective route context changes or becomes unusable.
func (repository *Repository) ObserveEthernetRuntime(ctx context.Context, id string, input EthernetRuntimeObservation) (EthernetRuntimeUpdate, error) {
	if !validIdentifier(id) || !validIdentifier(input.NetworkInterfaceID) || input.ReadinessReason == "" || len(input.ReadinessReason) > 128 {
		return EthernetRuntimeUpdate{}, errors.New("complete Ethernet runtime observation is required")
	}
	switch input.State {
	case StateReady, StateConfiguring, StateConfiguredOffline, StateSubnetConflict, StateDisabled:
	default:
		return EthernetRuntimeUpdate{}, errors.New("invalid Ethernet runtime state")
	}
	if input.InterfaceName != "" && !validIfname(input.InterfaceName) {
		return EthernetRuntimeUpdate{}, errors.New("invalid observed Ethernet interface name")
	}
	var prefix netip.Prefix
	var gateway netip.Addr
	var err error
	if input.State == StateReady || input.State == StateSubnetConflict {
		prefix, err = netip.ParsePrefix(input.IPv4CIDR)
		if err != nil || !netutil.IsUsableIPv4Host(prefix, prefix.Addr()) {
			return EthernetRuntimeUpdate{}, errors.New("ready Ethernet observation requires a usable IPv4 CIDR")
		}
		gateway, err = netip.ParseAddr(input.Gateway)
		if err != nil || !gateway.Is4() || !netutil.IsUsableIPv4Host(prefix, gateway) || gateway == prefix.Addr() {
			return EthernetRuntimeUpdate{}, errors.New("ready Ethernet observation requires a different gateway in the same subnet")
		}
	}
	dnsJSON, err := json.Marshal(input.DNS)
	if err != nil {
		return EthernetRuntimeUpdate{}, err
	}
	for _, raw := range input.DNS {
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !address.Is4() || address.IsUnspecified() {
			return EthernetRuntimeUpdate{}, fmt.Errorf("invalid observed Ethernet DNS address %q", raw)
		}
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return EthernetRuntimeUpdate{}, fmt.Errorf("begin Ethernet runtime observation: %w", err)
	}
	defer transaction.Rollback()
	var uplinkType, interfaceID, addressMode, currentCIDR, currentGateway, currentDNS, currentState, currentReason string
	var enabled int
	var desiredGeneration, observedGeneration, routeGeneration int64
	err = transaction.QueryRowContext(ctx, `
SELECT type, COALESCE(network_interface_id,''), address_mode,
       COALESCE(ipv4_cidr,''), COALESCE(gateway,''), dns_json, enabled,
       desired_generation, observed_generation, route_generation, state,
       readiness_reason
FROM uplinks WHERE id=?`, id).Scan(
		&uplinkType, &interfaceID, &addressMode, &currentCIDR, &currentGateway,
		&currentDNS, &enabled, &desiredGeneration, &observedGeneration,
		&routeGeneration, &currentState, &currentReason)
	if errors.Is(err, sql.ErrNoRows) {
		return EthernetRuntimeUpdate{}, store.ErrNotFound
	}
	if err != nil {
		return EthernetRuntimeUpdate{}, fmt.Errorf("read Ethernet runtime state: %w", err)
	}
	if uplinkType != TypeEthernet || interfaceID != input.NetworkInterfaceID {
		return EthernetRuntimeUpdate{}, errors.New("Ethernet observation does not match assigned stable interface")
	}
	if enabled == 0 && input.State != StateDisabled {
		return EthernetRuntimeUpdate{}, errors.New("disabled Ethernet uplink must remain disabled")
	}
	if enabled != 0 && input.State == StateDisabled {
		return EthernetRuntimeUpdate{}, errors.New("enabled Ethernet uplink cannot observe disabled state")
	}
	if addressMode == AddressStatic && (input.State == StateReady || input.State == StateSubnetConflict) && (currentCIDR != input.IPv4CIDR || currentGateway != input.Gateway) {
		return EthernetRuntimeUpdate{}, errors.New("observed static Ethernet route differs from desired configuration")
	}
	routeChanged := input.RouteIdentityChanged || currentState == StateReady && input.State != StateReady
	if input.State == StateReady || input.State == StateSubnetConflict {
		routeChanged = routeChanged || currentCIDR != input.IPv4CIDR || currentGateway != input.Gateway || currentDNS != string(dnsJSON)
	}
	nextRouteGeneration := routeGeneration
	if routeChanged {
		nextRouteGeneration++
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	stableSince := any(nil)
	if input.State == StateReady {
		if currentState == StateReady && !routeChanged {
			var existing sql.NullString
			if err := transaction.QueryRowContext(ctx, "SELECT stable_since FROM uplinks WHERE id=?", id).Scan(&existing); err != nil {
				return EthernetRuntimeUpdate{}, err
			}
			stableSince = nullIfEmpty(existing.String)
		} else {
			stableSince = now
		}
	}
	nextObserved := int64(0)
	if input.ConfigurationSeen {
		nextObserved = desiredGeneration
	}
	updateCIDR, updateGateway, updateDNS := currentCIDR, currentGateway, currentDNS
	if addressMode == AddressDHCP && (input.State == StateReady || input.State == StateSubnetConflict) {
		updateCIDR, updateGateway, updateDNS = input.IPv4CIDR, input.Gateway, string(dnsJSON)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE uplinks
SET ipv4_cidr=?, gateway=?, dns_json=?, observed_generation=?, state=?,
    readiness_reason=?, route_generation=?,
    last_seen_at=CASE WHEN ?<>'' THEN ? ELSE last_seen_at END,
    stable_since=?, updated_at=?
WHERE id=? AND network_interface_id=?`,
		nullIfEmpty(updateCIDR), nullIfEmpty(updateGateway), updateDNS,
		nextObserved, input.State, input.ReadinessReason, nextRouteGeneration,
		input.InterfaceName, now, stableSince, now, id, input.NetworkInterfaceID)
	if err != nil {
		return EthernetRuntimeUpdate{}, fmt.Errorf("store Ethernet runtime observation: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return EthernetRuntimeUpdate{}, store.ErrNotFound
	}
	roleState := "CONFIGURING"
	if input.State == StateReady {
		roleState = "APPLIED"
	} else if input.State == StateSubnetConflict {
		roleState = "CONFLICT"
	} else if input.State == StateConfiguredOffline || input.State == StateDisabled {
		roleState = "OFFLINE"
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE interface_role_assignments
SET observed_generation=?, state=?, updated_at=?
WHERE uplink_id=? AND network_interface_id=? AND role='ETHERNET_UPLINK'`,
		nextObserved, roleState, now, id, input.NetworkInterfaceID); err != nil {
		return EthernetRuntimeUpdate{}, fmt.Errorf("store Ethernet role observation: %w", err)
	}
	pathsInvalidated := int64(0)
	if routeChanged || input.State != StateReady {
		pathState := "UPLINK_OFFLINE"
		if input.State == StateDisabled {
			pathState = "UPLINK_DISABLED"
		} else if input.State == StateSubnetConflict {
			pathState = "SUBNET_CONFLICT"
		}
		vpnResult, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=?, state=?, transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, last_checked_at=NULL,
    expires_at=NULL, updated_at=?
WHERE uplink_id=?`, nextRouteGeneration, pathState, now, id)
		if err != nil {
			return EthernetRuntimeUpdate{}, fmt.Errorf("invalidate Ethernet VPN paths: %w", err)
		}
		directResult, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=?, state=?, transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0,
    whitelist_targets_passed=0, last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, nextRouteGeneration, pathState, now, id)
		if err != nil {
			return EthernetRuntimeUpdate{}, fmt.Errorf("invalidate Ethernet direct path: %w", err)
		}
		vpnCount, _ := vpnResult.RowsAffected()
		directCount, _ := directResult.RowsAffected()
		pathsInvalidated = vpnCount + directCount
	}
	if routeChanged || currentState != input.State || currentReason != input.ReadinessReason || observedGeneration != nextObserved {
		if err := appendEventTx(ctx, transaction, now, "ETHERNET_RUNTIME_OBSERVED", id, map[string]any{
			"state": input.State, "reason": input.ReadinessReason,
			"route_generation": nextRouteGeneration, "route_changed": routeChanged,
		}); err != nil {
			return EthernetRuntimeUpdate{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return EthernetRuntimeUpdate{}, fmt.Errorf("commit Ethernet runtime observation: %w", err)
	}
	return EthernetRuntimeUpdate{RouteContextChanged: routeChanged, RouteGeneration: nextRouteGeneration, PathsInvalidated: pathsInvalidated}, nil
}

func (repository *Repository) GetHiLink(ctx context.Context, id string) (HiLinkDetails, error) {
	var result HiLinkDetails
	var enabled int64
	var networkInterfaceID, currentIfname, ipv4CIDR, gateway, dnsJSON sql.NullString
	var configuredCIDR, configuredGateway sql.NullString
	var mtu sql.NullInt64
	var lastSeenAt, stableSince, operatorLabel, observedOperator, maskedSerial, apiSecretRef sql.NullString
	err := repository.database.QueryRowContext(ctx, `
SELECT u.id, u.display_number, u.type, u.name, u.enabled, u.priority,
       u.network_interface_id, n.current_ifname, u.address_mode, u.ipv4_cidr,
       u.gateway, u.dns_json, u.configured_ipv4_cidr, u.configured_gateway,
       u.configured_dns_json, u.mtu, u.routing_table_id, u.fwmark,
       u.route_generation, u.desired_generation, u.observed_generation, u.state,
       u.readiness_reason,
       u.last_seen_at, u.stable_since, u.created_at, u.updated_at,
       h.operator_label, h.observed_operator, h.identity_kind, h.masked_serial,
       h.modem_state, h.telemetry_state, h.management_reachability_state, h.api_secret_ref
FROM uplinks AS u
JOIN hilink_modems AS h ON h.uplink_id=u.id
LEFT JOIN network_interfaces AS n ON n.id=u.network_interface_id
WHERE u.id=? AND u.type='HILINK'`, id).Scan(
		&result.ID, &result.DisplayNumber, &result.Type, &result.Name, &enabled, &result.Priority,
		&networkInterfaceID, &currentIfname, &result.AddressMode, &ipv4CIDR, &gateway, &dnsJSON,
		&configuredCIDR, &configuredGateway, &result.ConfiguredDNSJSON,
		&mtu, &result.RoutingTableID, &result.Fwmark, &result.RouteGeneration,
		&result.DesiredGeneration, &result.ObservedGeneration, &result.State, &result.ReadinessReason,
		&lastSeenAt, &stableSince, &result.CreatedAt, &result.UpdatedAt,
		&operatorLabel, &observedOperator, &result.IdentityKind, &maskedSerial,
		&result.ModemState, &result.TelemetryState, &result.ManagementReachabilityState, &apiSecretRef)
	if errors.Is(err, sql.ErrNoRows) {
		return HiLinkDetails{}, store.ErrNotFound
	}
	if err != nil {
		return HiLinkDetails{}, fmt.Errorf("get HiLink uplink: %w", err)
	}
	result.Enabled = enabled != 0
	result.NetworkInterfaceID, result.CurrentIfname = networkInterfaceID.String, currentIfname.String
	result.IPv4CIDR, result.Gateway, result.DNSJSON = ipv4CIDR.String, gateway.String, dnsJSON.String
	result.ConfiguredIPv4CIDR, result.ConfiguredGateway = configuredCIDR.String, configuredGateway.String
	result.MTU, result.LastSeenAt, result.StableSince = mtu.Int64, lastSeenAt.String, stableSince.String
	result.OperatorLabel, result.ObservedOperator = operatorLabel.String, observedOperator.String
	result.MaskedSerial, result.APISecretRef = maskedSerial.String, apiSecretRef.String
	return result, nil
}

// ReplaceInterface changes only desired persistent state. The caller must wrap
// it in the network safe-apply transaction and confirm reachability separately.
func (repository *Repository) ReplaceInterface(ctx context.Context, uplinkID, replacementInterfaceID string, expectedDesiredGeneration int64) (ReplacementResult, error) {
	if strings.TrimSpace(uplinkID) == "" || strings.TrimSpace(replacementInterfaceID) == "" || expectedDesiredGeneration < 1 {
		return ReplacementResult{}, errors.New("uplink, replacement interface, and expected generation are required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return ReplacementResult{}, fmt.Errorf("begin interface replacement: %w", err)
	}
	defer transaction.Rollback()
	var uplinkType, previousInterfaceID string
	var currentDesired, currentRoute int64
	if err := transaction.QueryRowContext(ctx, `
SELECT type, COALESCE(network_interface_id, ''), desired_generation, route_generation
FROM uplinks WHERE id=?`, uplinkID).Scan(&uplinkType, &previousInterfaceID, &currentDesired, &currentRoute); errors.Is(err, sql.ErrNoRows) {
		return ReplacementResult{}, store.ErrNotFound
	} else if err != nil {
		return ReplacementResult{}, fmt.Errorf("read uplink replacement state: %w", err)
	}
	if uplinkType != TypeEthernet {
		return ReplacementResult{}, errors.New("only an Ethernet uplink can replace its physical NIC")
	}
	if currentDesired != expectedDesiredGeneration {
		return ReplacementResult{}, store.ErrStaleGeneration
	}
	if previousInterfaceID == replacementInterfaceID {
		return ReplacementResult{}, errors.New("replacement interface is already assigned to this uplink")
	}
	var interfaceCount, conflictingRoles int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM network_interfaces WHERE id=?", replacementInterfaceID).Scan(&interfaceCount); err != nil {
		return ReplacementResult{}, fmt.Errorf("read replacement interface: %w", err)
	}
	if interfaceCount != 1 {
		return ReplacementResult{}, store.ErrNotFound
	}
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*) FROM interface_role_assignments
WHERE network_interface_id=? AND role NOT IN ('UNUSED', 'SHARED_ONE_ARM')`, replacementInterfaceID).Scan(&conflictingRoles); err != nil {
		return ReplacementResult{}, fmt.Errorf("read replacement roles: %w", err)
	}
	if conflictingRoles != 0 {
		return ReplacementResult{}, errors.New("replacement interface already has an active role")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE network_interface_id=? AND role='UNUSED'`, replacementInterfaceID); err != nil {
		return ReplacementResult{}, fmt.Errorf("clear replacement unused role: %w", err)
	}
	roleResult, err := transaction.ExecContext(ctx, `
UPDATE interface_role_assignments
SET network_interface_id=?, desired_generation=desired_generation+1,
    observed_generation=0, state='CONFIGURED', updated_at=?
WHERE uplink_id=? AND role='ETHERNET_UPLINK'`, replacementInterfaceID, now, uplinkID)
	if err != nil {
		return ReplacementResult{}, fmt.Errorf("move Ethernet role: %w", err)
	}
	if count, err := roleResult.RowsAffected(); err != nil || count != 1 {
		return ReplacementResult{}, errors.New("Ethernet uplink role assignment is missing or ambiguous")
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE uplinks
SET network_interface_id=?, desired_generation=desired_generation+1,
    observed_generation=0, route_generation=route_generation+1,
    state='UPLINK_CONFIGURING', last_seen_at=NULL, stable_since=NULL, updated_at=?
WHERE id=? AND desired_generation=?`, replacementInterfaceID, now, uplinkID, expectedDesiredGeneration)
	if err != nil {
		return ReplacementResult{}, fmt.Errorf("replace uplink interface: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ReplacementResult{}, store.ErrStaleGeneration
	}
	if previousInterfaceID != "" {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO interface_role_assignments (
    id, network_interface_id, role, created_at, updated_at
) VALUES (?, ?, 'UNUSED', ?, ?)
ON CONFLICT(network_interface_id, role) DO UPDATE SET updated_at=excluded.updated_at`,
			"role:unused:"+previousInterfaceID, previousInterfaceID, now, now); err != nil {
			return ReplacementResult{}, fmt.Errorf("mark previous interface unused: %w", err)
		}
	}
	vpnResult, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=?, state='STALE', transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, last_checked_at=NULL,
    expires_at=NULL, updated_at=?
WHERE uplink_id=?`, currentRoute+1, now, uplinkID)
	if err != nil {
		return ReplacementResult{}, fmt.Errorf("invalidate replaced uplink VPN paths: %w", err)
	}
	directResult, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=?, state='STALE', transport_state='UNKNOWN',
    quality_class='UNKNOWN', functional_score=0, required_targets_passed=0,
    optional_targets_passed=0, whitelist_targets_passed=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, currentRoute+1, now, uplinkID)
	if err != nil {
		return ReplacementResult{}, fmt.Errorf("invalidate replaced uplink direct path: %w", err)
	}
	vpnCount, _ := vpnResult.RowsAffected()
	directCount, _ := directResult.RowsAffected()
	if err := appendEventTx(ctx, transaction, now, "UPLINK_INTERFACE_REPLACED", uplinkID, map[string]any{
		"previous_interface_id": previousInterfaceID, "replacement_interface_id": replacementInterfaceID,
		"desired_generation": currentDesired + 1, "route_generation": currentRoute + 1,
	}); err != nil {
		return ReplacementResult{}, err
	}
	if err := transaction.Commit(); err != nil {
		return ReplacementResult{}, fmt.Errorf("commit interface replacement: %w", err)
	}
	return ReplacementResult{
		UplinkID: uplinkID, PreviousInterfaceID: previousInterfaceID,
		ReplacementInterface: replacementInterfaceID, DesiredGeneration: currentDesired + 1,
		RouteGeneration: currentRoute + 1, InvalidatedVPNPaths: vpnCount, InvalidatedDirect: directCount,
	}, nil
}

// UpdateEthernetConfiguration changes only canonical desired state. Host
// networkd mutation and confirmation are owned by the network safe-apply
// transaction; direct Web/API callers must not invoke this method.
func (repository *Repository) UpdateEthernetConfiguration(ctx context.Context, uplinkID string, input UpdateEthernetInput) (Uplink, error) {
	if input.ExpectedDesiredGeneration < 1 {
		return Uplink{}, errors.New("expected Ethernet desired generation is required")
	}
	if err := validateEthernetInput(CreateEthernetInput{
		ID: uplinkID, Name: "validated", NetworkInterfaceID: input.NetworkInterfaceID,
		AddressMode: input.AddressMode, IPv4CIDR: input.IPv4CIDR, Gateway: input.Gateway,
		DNS: input.DNS, MTU: input.MTU,
	}); err != nil {
		return Uplink{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Uplink{}, fmt.Errorf("begin Ethernet configuration update: %w", err)
	}
	defer transaction.Rollback()
	var uplinkType, currentInterfaceID, currentAddressMode, configuredCIDR, configuredGateway, configuredDNS string
	var currentMTU sql.NullInt64
	var currentDesired, currentRoute int64
	err = transaction.QueryRowContext(ctx, `
SELECT type, COALESCE(network_interface_id, ''), address_mode,
       COALESCE(configured_ipv4_cidr, ''), COALESCE(configured_gateway, ''),
       configured_dns_json, mtu,
       desired_generation, route_generation
FROM uplinks WHERE id=?`, uplinkID).Scan(
		&uplinkType, &currentInterfaceID, &currentAddressMode, &configuredCIDR,
		&configuredGateway, &configuredDNS, &currentMTU, &currentDesired, &currentRoute)
	if errors.Is(err, sql.ErrNoRows) {
		return Uplink{}, store.ErrNotFound
	}
	if err != nil {
		return Uplink{}, fmt.Errorf("read Ethernet configuration: %w", err)
	}
	if uplinkType != TypeEthernet {
		return Uplink{}, errors.New("only an Ethernet uplink configuration can be updated")
	}
	if currentDesired != input.ExpectedDesiredGeneration {
		return Uplink{}, store.ErrStaleGeneration
	}
	if currentInterfaceID != input.NetworkInterfaceID {
		return Uplink{}, errors.New("Ethernet interface changed before configuration update")
	}
	dnsJSON, err := json.Marshal(input.DNS)
	if err != nil {
		return Uplink{}, fmt.Errorf("encode Ethernet DNS: %w", err)
	}
	if currentAddressMode == input.AddressMode && configuredCIDR == input.IPv4CIDR && configuredGateway == input.Gateway && configuredDNS == string(dnsJSON) && currentMTU.Int64 == input.MTU {
		return Uplink{}, errors.New("Ethernet configuration is unchanged")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE uplinks
SET address_mode=?, ipv4_cidr=?, gateway=?, dns_json=?,
    configured_ipv4_cidr=?, configured_gateway=?, configured_dns_json=?, mtu=?,
    desired_generation=desired_generation+1, observed_generation=0,
    route_generation=route_generation+1, state='UPLINK_CONFIGURING',
    last_seen_at=NULL, stable_since=NULL, updated_at=?
WHERE id=? AND desired_generation=? AND network_interface_id=?`,
		input.AddressMode, nullIfEmpty(input.IPv4CIDR), nullIfEmpty(input.Gateway),
		string(dnsJSON), nullIfEmpty(input.IPv4CIDR), nullIfEmpty(input.Gateway),
		string(dnsJSON), nullIfZero(input.MTU), now, uplinkID,
		input.ExpectedDesiredGeneration, input.NetworkInterfaceID)
	if err != nil {
		return Uplink{}, fmt.Errorf("update Ethernet configuration: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return Uplink{}, store.ErrStaleGeneration
	}
	if err := invalidateUplinkPathsTx(ctx, transaction, uplinkID, currentRoute+1, now); err != nil {
		return Uplink{}, err
	}
	if err := appendEventTx(ctx, transaction, now, "UPLINK_CONFIGURATION_UPDATED", uplinkID, map[string]any{
		"address_mode": input.AddressMode, "desired_generation": currentDesired + 1,
		"route_generation": currentRoute + 1,
	}); err != nil {
		return Uplink{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Uplink{}, fmt.Errorf("commit Ethernet configuration update: %w", err)
	}
	return repository.Get(ctx, uplinkID)
}

func invalidateUplinkPathsTx(ctx context.Context, transaction *sql.Tx, uplinkID string, routeGeneration int64, now string) error {
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=?, state='STALE', transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, last_checked_at=NULL,
    expires_at=NULL, updated_at=?
WHERE uplink_id=?`, routeGeneration, now, uplinkID); err != nil {
		return fmt.Errorf("invalidate Ethernet VPN paths: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=?, state='STALE', transport_state='UNKNOWN',
    quality_class='UNKNOWN', functional_score=0, required_targets_passed=0,
    optional_targets_passed=0, whitelist_targets_passed=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, routeGeneration, now, uplinkID); err != nil {
		return fmt.Errorf("invalidate Ethernet direct path: %w", err)
	}
	return nil
}

func validateInterfaceObservation(input InterfaceObservation) error {
	if !validIdentifier(input.ID) || !validIdentifier(input.StableIdentityKind) {
		return errors.New("interface id and identity kind are required and must be safe identifiers")
	}
	digest, err := hex.DecodeString(strings.ToLower(input.StableIdentityHash))
	if err != nil || len(digest) != 32 {
		return errors.New("stable interface identity hash must be a SHA-256 hex value")
	}
	if input.CurrentIfname != "" && !validIfname(input.CurrentIfname) {
		return errors.New("current interface name is invalid")
	}
	if input.CarrierState != "UNKNOWN" && input.CarrierState != "UP" && input.CarrierState != "DOWN" && input.CarrierState != "ABSENT" {
		return errors.New("interface carrier state is invalid")
	}
	for _, raw := range input.Addresses {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("invalid observed interface address %q", raw)
		}
	}
	return nil
}

func validateEthernetInput(input CreateEthernetInput) error {
	if !validIdentifier(input.ID) || strings.TrimSpace(input.Name) == "" || len([]rune(strings.TrimSpace(input.Name))) > 128 {
		return errors.New("uplink id and a name up to 128 characters are required")
	}
	if !validIdentifier(input.NetworkInterfaceID) {
		return errors.New("network interface id is required")
	}
	if input.AddressMode != AddressDHCP && input.AddressMode != AddressStatic {
		return errors.New("Ethernet address mode must be DHCP or STATIC")
	}
	if input.MTU != 0 && (input.MTU < 576 || input.MTU > 9216) {
		return errors.New("Ethernet MTU must be between 576 and 9216")
	}
	var prefix netip.Prefix
	var err error
	if input.IPv4CIDR != "" {
		prefix, err = netip.ParsePrefix(input.IPv4CIDR)
		if err != nil || !netutil.IsUsableIPv4Host(prefix, prefix.Addr()) {
			return errors.New("Ethernet IPv4 CIDR is invalid")
		}
	}
	var gateway netip.Addr
	if input.Gateway != "" {
		gateway, err = netip.ParseAddr(input.Gateway)
		if err != nil || !gateway.Is4() {
			return errors.New("Ethernet gateway must be an IPv4 address")
		}
	}
	if input.AddressMode == AddressStatic {
		if !prefix.IsValid() || !gateway.IsValid() || !netutil.IsUsableIPv4Host(prefix, gateway) || prefix.Addr() == gateway {
			return errors.New("static Ethernet mode requires an IPv4 CIDR and a different gateway inside that subnet")
		}
	} else if prefix.IsValid() || gateway.IsValid() {
		return errors.New("DHCP Ethernet mode cannot also contain static IPv4 CIDR or gateway")
	}
	for _, raw := range input.DNS {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.IsUnspecified() {
			return fmt.Errorf("invalid Ethernet DNS IPv4 address %q", raw)
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || strings.ContainsRune("-_:.", character) {
			continue
		}
		return false
	}
	return true
}

func validIfname(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func appendEventTx(ctx context.Context, transaction *sql.Tx, now, eventType, uplinkID string, details map[string]any) error {
	details["uplink_id"] = uplinkID
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode uplink event: %w", err)
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'INFO', ?, ?)`, now, eventType, string(payload))
	if err != nil {
		return fmt.Errorf("append uplink event %s: %w", eventType, err)
	}
	return nil
}

func raiseLegacyCounterFloorsTx(ctx context.Context, transaction *sql.Tx, displayNumber, routingTableID, fwmark int64, now string) error {
	for _, item := range []struct {
		key   string
		value int64
	}{
		{key: "next_modem_display_number", value: displayNumber},
		{key: "next_modem_routing_table", value: routingTableID},
		{key: "next_modem_fwmark", value: fwmark},
	} {
		_, err := transaction.ExecContext(ctx, `
INSERT INTO settings(key, value_json, updated_at) VALUES (?, CAST(? AS TEXT), ?)
ON CONFLICT(key) DO UPDATE SET
    value_json=CAST(MAX(CAST(settings.value_json AS INTEGER), ?) AS TEXT),
    updated_at=excluded.updated_at`, item.key, item.value, now, item.value)
		if err != nil {
			return fmt.Errorf("raise compatibility counter %s: %w", item.key, err)
		}
	}
	return nil
}

const uplinkSelect = `
SELECT u.id, u.display_number, u.type, u.name, u.enabled, u.priority,
       u.network_interface_id, n.current_ifname, u.address_mode, u.ipv4_cidr,
       u.gateway, u.dns_json, u.configured_ipv4_cidr, u.configured_gateway,
       u.configured_dns_json, u.mtu, u.routing_table_id, u.fwmark,
       u.route_generation, u.desired_generation, u.observed_generation, u.state,
       u.readiness_reason,
       u.last_seen_at, u.stable_since, u.created_at, u.updated_at
FROM uplinks AS u
LEFT JOIN network_interfaces AS n ON n.id=u.network_interface_id`

const interfaceSelect = `
SELECT id, stable_identity_kind, stable_identity_hash, permanent_mac, topology_path,
       current_ifname, driver, vendor, model, carrier_state, addresses_json,
       observed_at, replacement_for_interface_id, created_at, updated_at
FROM network_interfaces`

type scanner interface{ Scan(...any) error }

func scanUplink(row scanner) (Uplink, error) {
	var item Uplink
	var enabled int64
	var networkInterfaceID, currentIfname, ipv4CIDR, gateway, configuredCIDR, configuredGateway sql.NullString
	var mtu sql.NullInt64
	var lastSeenAt, stableSince sql.NullString
	err := row.Scan(
		&item.ID, &item.DisplayNumber, &item.Type, &item.Name, &enabled, &item.Priority,
		&networkInterfaceID, &currentIfname, &item.AddressMode, &ipv4CIDR, &gateway,
		&item.DNSJSON, &configuredCIDR, &configuredGateway, &item.ConfiguredDNSJSON,
		&mtu, &item.RoutingTableID, &item.Fwmark, &item.RouteGeneration,
		&item.DesiredGeneration, &item.ObservedGeneration, &item.State, &item.ReadinessReason,
		&lastSeenAt, &stableSince, &item.CreatedAt, &item.UpdatedAt)
	item.Enabled = enabled != 0
	item.NetworkInterfaceID, item.CurrentIfname = networkInterfaceID.String, currentIfname.String
	item.IPv4CIDR, item.Gateway, item.MTU = ipv4CIDR.String, gateway.String, mtu.Int64
	item.ConfiguredIPv4CIDR, item.ConfiguredGateway = configuredCIDR.String, configuredGateway.String
	item.LastSeenAt, item.StableSince = lastSeenAt.String, stableSince.String
	return item, err
}

func scanInterface(row scanner) (NetworkInterface, error) {
	var item NetworkInterface
	var permanentMAC, topologyPath, currentIfname, driver, vendor, model sql.NullString
	var observedAt, replacementForID sql.NullString
	err := row.Scan(
		&item.ID, &item.StableIdentityKind, &item.StableIdentityHash, &permanentMAC,
		&topologyPath, &currentIfname, &driver, &vendor, &model, &item.CarrierState,
		&item.AddressesJSON, &observedAt, &replacementForID, &item.CreatedAt, &item.UpdatedAt)
	item.PermanentMAC, item.TopologyPath, item.CurrentIfname = permanentMAC.String, topologyPath.String, currentIfname.String
	item.Driver, item.Vendor, item.Model = driver.String, vendor.String, model.String
	item.ObservedAt, item.ReplacementForID = observedAt.String, replacementForID.String
	return item, err
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func nullIfZero(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
