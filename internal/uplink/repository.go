// Package uplink owns the canonical physical Internet-uplink inventory.
package uplink

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"gateway-vpn/internal/store"
)

const (
	TypeHiLink   = "HILINK"
	TypeEthernet = "ETHERNET"

	AddressDHCP   = "DHCP"
	AddressStatic = "STATIC"

	StateConfiguredOffline = "UPLINK_CONFIGURED_OFFLINE"
	StateConfiguring       = "UPLINK_CONFIGURING"
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
	MTU                int64
	RoutingTableID     int64
	Fwmark             int64
	RouteGeneration    int64
	DesiredGeneration  int64
	ObservedGeneration int64
	State              string
	LastSeenAt         string
	StableSince        string
	CreatedAt          string
	UpdatedAt          string
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

func (repository *Repository) CreateEthernet(ctx context.Context, input CreateEthernetInput) (Uplink, error) {
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
WHERE network_interface_id=? AND role<>'UNUSED'`, input.NetworkInterfaceID).Scan(&conflictingRoles); err != nil {
		return Uplink{}, fmt.Errorf("read interface roles: %w", err)
	}
	if conflictingRoles != 0 {
		return Uplink{}, errors.New("network interface already has an active role")
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
    address_mode, ipv4_cidr, gateway, dns_json, mtu, routing_table_id, fwmark,
    state, created_at, updated_at
) VALUES (?, ?, 'ETHERNET', ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'UPLINK_CONFIGURED_OFFLINE', ?, ?)`,
		input.ID, displayNumber, strings.TrimSpace(input.Name), priority, input.NetworkInterfaceID,
		input.AddressMode, nullIfEmpty(input.IPv4CIDR), nullIfEmpty(input.Gateway), string(dnsJSON),
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

func (repository *Repository) GetHiLink(ctx context.Context, id string) (HiLinkDetails, error) {
	var result HiLinkDetails
	var enabled int64
	var networkInterfaceID, currentIfname, ipv4CIDR, gateway, dnsJSON sql.NullString
	var mtu sql.NullInt64
	var lastSeenAt, stableSince, operatorLabel, observedOperator, maskedSerial, apiSecretRef sql.NullString
	err := repository.database.QueryRowContext(ctx, `
SELECT u.id, u.display_number, u.type, u.name, u.enabled, u.priority,
       u.network_interface_id, n.current_ifname, u.address_mode, u.ipv4_cidr,
       u.gateway, u.dns_json, u.mtu, u.routing_table_id, u.fwmark,
       u.route_generation, u.desired_generation, u.observed_generation, u.state,
       u.last_seen_at, u.stable_since, u.created_at, u.updated_at,
       h.operator_label, h.observed_operator, h.identity_kind, h.masked_serial,
       h.modem_state, h.telemetry_state, h.management_reachability_state, h.api_secret_ref
FROM uplinks AS u
JOIN hilink_modems AS h ON h.uplink_id=u.id
LEFT JOIN network_interfaces AS n ON n.id=u.network_interface_id
WHERE u.id=? AND u.type='HILINK'`, id).Scan(
		&result.ID, &result.DisplayNumber, &result.Type, &result.Name, &enabled, &result.Priority,
		&networkInterfaceID, &currentIfname, &result.AddressMode, &ipv4CIDR, &gateway, &dnsJSON,
		&mtu, &result.RoutingTableID, &result.Fwmark, &result.RouteGeneration,
		&result.DesiredGeneration, &result.ObservedGeneration, &result.State,
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
WHERE network_interface_id=? AND role<>'UNUSED'`, replacementInterfaceID).Scan(&conflictingRoles); err != nil {
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
		if err != nil || !prefix.Addr().Is4() {
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
		if !prefix.IsValid() || !gateway.IsValid() || !prefix.Contains(gateway) || prefix.Addr() == gateway {
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
       u.gateway, u.dns_json, u.mtu, u.routing_table_id, u.fwmark,
       u.route_generation, u.desired_generation, u.observed_generation, u.state,
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
	var networkInterfaceID, currentIfname, ipv4CIDR, gateway sql.NullString
	var mtu sql.NullInt64
	var lastSeenAt, stableSince sql.NullString
	err := row.Scan(
		&item.ID, &item.DisplayNumber, &item.Type, &item.Name, &enabled, &item.Priority,
		&networkInterfaceID, &currentIfname, &item.AddressMode, &ipv4CIDR, &gateway,
		&item.DNSJSON, &mtu, &item.RoutingTableID, &item.Fwmark, &item.RouteGeneration,
		&item.DesiredGeneration, &item.ObservedGeneration, &item.State,
		&lastSeenAt, &stableSince, &item.CreatedAt, &item.UpdatedAt)
	item.Enabled = enabled != 0
	item.NetworkInterfaceID, item.CurrentIfname = networkInterfaceID.String, currentIfname.String
	item.IPv4CIDR, item.Gateway, item.MTU = ipv4CIDR.String, gateway.String, mtu.Int64
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
