package networkapply

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/uplink"
)

type ethernetRoleSnapshot struct {
	ID                 string `json:"id"`
	NetworkInterfaceID string `json:"network_interface_id"`
	Role               string `json:"role"`
	UplinkID           string `json:"uplink_id,omitempty"`
	DesiredGeneration  int64  `json:"desired_generation"`
	ObservedGeneration int64  `json:"observed_generation"`
	State              string `json:"state"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type ethernetSnapshot struct {
	Uplink              *uplink.Uplink         `json:"uplink,omitempty"`
	Roles               []ethernetRoleSnapshot `json:"roles"`
	PreviousInterfaceID string                 `json:"previous_interface_id,omitempty"`
	PreviousIfname      string                 `json:"previous_ifname,omitempty"`
	TargetIfname        string                 `json:"target_ifname"`
	OwnedFileExisted    bool                   `json:"owned_file_existed"`
	OwnedFileSHA256     string                 `json:"owned_file_sha256,omitempty"`
}

type ethernetContext struct {
	TargetIfname string
	Existing     *uplink.Uplink
}

func (backend UbuntuBackend) snapshotEthernet(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateEthernetBackend(); err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	current, err := backend.validateEthernetProtectedState(ctx, manifest)
	if err != nil {
		return err
	}
	snapshotDirectory, candidateDirectory, err := prepareBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	_ = candidateDirectory
	roles, err := backend.snapshotEthernetRoles(ctx, manifest, current)
	if err != nil {
		return err
	}
	snapshot := ethernetSnapshot{Roles: roles, TargetIfname: current.TargetIfname}
	if current.Existing != nil {
		copy := *current.Existing
		snapshot.Uplink = &copy
		snapshot.PreviousInterfaceID = copy.NetworkInterfaceID
		snapshot.PreviousIfname = copy.CurrentIfname
	}
	ownedPath := backend.ethernetOwnedPath(manifest.Ethernet.UplinkID)
	exists, content, err := readOptionalRegular(ownedPath, 1<<20)
	if err != nil {
		return fmt.Errorf("snapshot owned Ethernet networkd file: %w", err)
	}
	snapshot.OwnedFileExisted = exists
	if exists {
		digest := sha256.Sum256(content)
		snapshot.OwnedFileSHA256 = hex.EncodeToString(digest[:])
		if err := atomicWrite(filepath.Join(snapshotDirectory, "ethernet.network"), content, 0o600); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode Ethernet snapshot: %w", err)
	}
	if err := atomicWrite(filepath.Join(snapshotDirectory, "ethernet-state.json"), payload, 0o600); err != nil {
		return err
	}
	return syncDirectory(transactionDirectory)
}

func (backend UbuntuBackend) applyEthernet(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateEthernetBackend(); err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	_, candidateDirectory, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	protected, err := backend.validateEthernetProtectedState(ctx, manifest)
	if err != nil {
		return err
	}
	repository := uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)
	mutation := *manifest.Ethernet
	if mutation.Operation == EthernetDelete {
		ownedPath := backend.ethernetOwnedPath(mutation.UplinkID)
		if err := os.Remove(ownedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove owned Ethernet networkd configuration: %w", err)
		}
		if err := backend.networkctlReload(ctx); err != nil {
			return err
		}
		if validInterfaceName(protected.TargetIfname) {
			if err := backend.networkctlReconfigure(ctx, protected.TargetIfname); err != nil {
				return err
			}
		}
		return nil
	}
	switch mutation.Operation {
	case EthernetCreate:
		_, err = repository.CreateEthernet(ctx, uplink.CreateEthernetInput{
			ID: mutation.UplinkID, Name: mutation.Name, NetworkInterfaceID: mutation.TargetInterfaceID,
			AddressMode: mutation.AddressMode, IPv4CIDR: mutation.IPv4CIDR, Gateway: mutation.Gateway,
			DNS: mutation.DNS, MTU: mutation.MTU,
		})
	case EthernetReplaceInterface:
		_, err = repository.ReplaceInterface(ctx, mutation.UplinkID, mutation.TargetInterfaceID, mutation.ExpectedDesiredGeneration)
	case EthernetUpdateAddress:
		_, err = repository.UpdateEthernetConfiguration(ctx, mutation.UplinkID, uplink.UpdateEthernetInput{
			NetworkInterfaceID: mutation.TargetInterfaceID, AddressMode: mutation.AddressMode,
			IPv4CIDR: mutation.IPv4CIDR, Gateway: mutation.Gateway, DNS: mutation.DNS,
			MTU: mutation.MTU, ExpectedDesiredGeneration: mutation.ExpectedDesiredGeneration,
		})
	default:
		return errors.New("unsupported Ethernet safe-apply operation")
	}
	if err != nil {
		return fmt.Errorf("apply canonical Ethernet desired state: %w", err)
	}
	configured, err := repository.Get(ctx, mutation.UplinkID)
	if err != nil {
		return err
	}
	if configured.NetworkInterfaceID != mutation.TargetInterfaceID || !validInterfaceName(configured.CurrentIfname) {
		return errors.New("canonical Ethernet interface does not match protected inventory")
	}
	candidate, err := renderEthernetNetwork(configured)
	if err != nil {
		return err
	}
	candidatePath := filepath.Join(candidateDirectory, "ethernet.network")
	if err := atomicWrite(candidatePath, []byte(candidate), 0o600); err != nil {
		return err
	}
	if err := installRegular(candidatePath, backend.ethernetOwnedPath(mutation.UplinkID), 0o644, -1); err != nil {
		return err
	}
	if err := backend.networkctlReload(ctx); err != nil {
		return err
	}
	if err := backend.networkctlReconfigure(ctx, configured.CurrentIfname); err != nil {
		return err
	}
	return nil
}

func (backend UbuntuBackend) commitEthernet(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateEthernetBackend(); err != nil {
		return err
	}
	if manifest.Ethernet.Operation == EthernetDelete {
		snapshotDirectory, _, err := existingBackendDirectories(transactionDirectory)
		if err != nil {
			return err
		}
		snapshot, err := readEthernetSnapshot(snapshotDirectory, manifest)
		if err != nil || snapshot.Uplink == nil || snapshot.Uplink.Enabled || snapshot.Uplink.DesiredGeneration != manifest.Ethernet.ExpectedDesiredGeneration {
			return errors.New("Ethernet delete snapshot is invalid")
		}
		if _, err := os.Lstat(backend.ethernetOwnedPath(manifest.Ethernet.UplinkID)); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("owned Ethernet networkd configuration still exists before delete confirmation")
		}
		repository := uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)
		configured, err := repository.Get(ctx, manifest.Ethernet.UplinkID)
		if errors.Is(err, store.ErrNotFound) {
			// A crash after the atomic delete but before the confirmed phase is
			// recovered by replaying this idempotent commit.
			return nil
		}
		if err != nil {
			return err
		}
		if configured.Type != uplink.TypeEthernet || configured.Enabled ||
			configured.DesiredGeneration != manifest.Ethernet.ExpectedDesiredGeneration ||
			configured.NetworkInterfaceID != manifest.Ethernet.TargetInterfaceID {
			return errors.New("Ethernet uplink changed before delete confirmation")
		}
		transaction, err := backend.Database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		var active int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM runtime_state WHERE singleton_id=1 AND active_uplink_id=?", configured.ID).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return errors.New("active Ethernet uplink cannot be deleted")
		}
		result, err := transaction.ExecContext(ctx, `
DELETE FROM uplinks
WHERE id=? AND type='ETHERNET' AND enabled=0 AND desired_generation=? AND network_interface_id=?`,
			configured.ID, configured.DesiredGeneration, configured.NetworkInterfaceID)
		if err != nil {
			return fmt.Errorf("delete confirmed Ethernet uplink: %w", err)
		}
		if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
			return store.ErrStaleGeneration
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		details, _ := json.Marshal(map[string]any{"uplink_id": configured.ID, "display_number": configured.DisplayNumber})
		if _, err := transaction.ExecContext(ctx, "INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?,'INFO','ETHERNET_DELETED',?)", now, string(details)); err != nil {
			return err
		}
		return transaction.Commit()
	}
	repository := uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)
	configured, err := repository.Get(ctx, manifest.Ethernet.UplinkID)
	if err != nil {
		return fmt.Errorf("read Ethernet candidate before commit: %w", err)
	}
	wantGeneration := manifest.Ethernet.ExpectedDesiredGeneration + 1
	if manifest.Ethernet.Operation == EthernetCreate {
		wantGeneration = 1
	}
	if configured.Type != uplink.TypeEthernet || configured.DesiredGeneration != wantGeneration || configured.NetworkInterfaceID != manifest.Ethernet.TargetInterfaceID {
		return errors.New("Ethernet desired generation changed before confirmation")
	}
	want, err := renderEthernetNetwork(configured)
	if err != nil {
		return err
	}
	current, err := readBoundedRegular(backend.ethernetOwnedPath(configured.ID), 1<<20)
	if err != nil || string(current) != want {
		return errors.New("owned Ethernet networkd configuration changed before confirmation")
	}
	return nil
}

func (backend UbuntuBackend) rollbackEthernet(ctx context.Context, manifest Manifest, transactionDirectory string) error {
	if err := backend.validateEthernetBackend(); err != nil {
		return err
	}
	snapshotDirectory, _, err := existingBackendDirectories(transactionDirectory)
	if err != nil {
		return err
	}
	snapshot, err := readEthernetSnapshot(snapshotDirectory, manifest)
	if err != nil {
		return err
	}
	var failures []error
	if manifest.Ethernet.Operation == EthernetDelete {
		repository := uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)
		current, currentErr := repository.Get(ctx, manifest.Ethernet.UplinkID)
		if currentErr != nil || snapshot.Uplink == nil || current.Enabled ||
			current.DesiredGeneration != snapshot.Uplink.DesiredGeneration ||
			current.NetworkInterfaceID != snapshot.Uplink.NetworkInterfaceID {
			failures = append(failures, errors.New("Ethernet delete rollback canonical state changed"))
		}
	} else if err := backend.restoreEthernetDatabase(ctx, manifest, snapshot); err != nil {
		failures = append(failures, err)
	}
	ownedPath := backend.ethernetOwnedPath(manifest.Ethernet.UplinkID)
	if snapshot.OwnedFileExisted {
		content, readErr := readBoundedRegular(filepath.Join(snapshotDirectory, "ethernet.network"), 1<<20)
		if readErr != nil {
			failures = append(failures, readErr)
		} else {
			digest := sha256.Sum256(content)
			if hex.EncodeToString(digest[:]) != snapshot.OwnedFileSHA256 {
				failures = append(failures, errors.New("Ethernet networkd snapshot checksum mismatch"))
			} else if installErr := installRegular(filepath.Join(snapshotDirectory, "ethernet.network"), ownedPath, 0o644, -1); installErr != nil {
				failures = append(failures, installErr)
			}
		}
	} else if removeErr := os.Remove(ownedPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		failures = append(failures, fmt.Errorf("remove candidate Ethernet networkd file: %w", removeErr))
	}
	if err := backend.networkctlReload(ctx); err != nil {
		failures = append(failures, err)
	}
	for _, ifname := range uniqueIfnames(snapshot.PreviousIfname, snapshot.TargetIfname) {
		if err := backend.networkctlReconfigure(ctx, ifname); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (backend UbuntuBackend) validateEthernetBackend() error {
	if err := backend.validate(); err != nil {
		return err
	}
	if backend.Database == nil || backend.RoutingTableStart < 1 || backend.FwmarkStart < 1 || !filepath.IsAbs(backend.Paths.EthernetNetworkDir) {
		return errors.New("Ethernet safe-apply requires protected SQLite and allocation floors")
	}
	return nil
}

func (backend UbuntuBackend) validateEthernetProtectedState(ctx context.Context, manifest Manifest) (ethernetContext, error) {
	mutation := manifest.Ethernet
	configuration, err := config.Load(backend.Paths.ConfigFile)
	if err != nil {
		return ethernetContext{}, fmt.Errorf("load protected Gateway configuration: %w", err)
	}
	management, err := netip.ParsePrefix(configuration.Network.LANAddress)
	destination, destinationErr := netip.ParseAddr(manifest.NewDestinationIP)
	if err != nil || destinationErr != nil || destination.String() != management.Addr().String() && destination.String() != "10.80.0.2" {
		return ethernetContext{}, errors.New("Ethernet confirmation destination is not a protected LAN or WireGuard address")
	}
	managementURL, err := url.Parse(manifest.NewURL)
	if err != nil || managementURL.Port() == "" {
		return ethernetContext{}, errors.New("Ethernet confirmation URL is invalid")
	}
	wantListen := net.JoinHostPort(destination.String(), managementURL.Port())
	foundListen := false
	for _, listen := range configuration.API.Listen {
		if listen == wantListen {
			foundListen = true
		}
	}
	if !foundListen {
		return ethernetContext{}, errors.New("Ethernet confirmation URL is not a protected API listener")
	}
	repository := uplink.NewRepository(backend.Database, backend.RoutingTableStart, backend.FwmarkStart)
	existing, getErr := repository.Get(ctx, mutation.UplinkID)
	context := ethernetContext{}
	if getErr == nil {
		context.Existing = &existing
	} else if !errors.Is(getErr, store.ErrNotFound) {
		return ethernetContext{}, getErr
	}
	var ifname, carrier string
	err = backend.Database.QueryRowContext(ctx, `
SELECT COALESCE(current_ifname, ''), carrier_state
FROM network_interfaces WHERE id=?`, mutation.TargetInterfaceID).Scan(&ifname, &carrier)
	if errors.Is(err, sql.ErrNoRows) {
		return ethernetContext{}, store.ErrNotFound
	}
	if err != nil {
		return ethernetContext{}, fmt.Errorf("read protected target interface: %w", err)
	}
	context.TargetIfname = ifname
	if mutation.Operation != EthernetDelete && (!validInterfaceName(ifname) || carrier == "ABSENT") {
		return ethernetContext{}, errors.New("target Ethernet interface is absent or has no current kernel name")
	}
	switch mutation.Operation {
	case EthernetCreate:
		if context.Existing != nil {
			return ethernetContext{}, errors.New("Ethernet uplink id already exists")
		}
		if err := backend.requireInterfaceRoleFree(ctx, mutation.TargetInterfaceID); err != nil {
			return ethernetContext{}, err
		}
	case EthernetReplaceInterface:
		if context.Existing == nil || context.Existing.Type != uplink.TypeEthernet || context.Existing.DesiredGeneration != mutation.ExpectedDesiredGeneration {
			return ethernetContext{}, store.ErrStaleGeneration
		}
		if context.Existing.NetworkInterfaceID == mutation.TargetInterfaceID {
			return ethernetContext{}, errors.New("replacement interface is already assigned")
		}
		if err := backend.requireInterfaceRoleFree(ctx, mutation.TargetInterfaceID); err != nil {
			return ethernetContext{}, err
		}
		if !sameEthernetAddressConfiguration(*context.Existing, *mutation) {
			return ethernetContext{}, errors.New("interface replacement cannot also change Ethernet address settings")
		}
	case EthernetUpdateAddress:
		if context.Existing == nil || context.Existing.Type != uplink.TypeEthernet || context.Existing.DesiredGeneration != mutation.ExpectedDesiredGeneration {
			return ethernetContext{}, store.ErrStaleGeneration
		}
		if context.Existing.NetworkInterfaceID != mutation.TargetInterfaceID {
			return ethernetContext{}, errors.New("Ethernet interface changed before address update")
		}
	case EthernetDelete:
		if context.Existing == nil || context.Existing.Type != uplink.TypeEthernet || context.Existing.DesiredGeneration != mutation.ExpectedDesiredGeneration {
			return ethernetContext{}, store.ErrStaleGeneration
		}
		if context.Existing.NetworkInterfaceID != mutation.TargetInterfaceID {
			return ethernetContext{}, errors.New("Ethernet interface changed before delete")
		}
		if context.Existing.Enabled {
			return ethernetContext{}, errors.New("Ethernet uplink must be disabled before delete")
		}
		var active int
		if err := backend.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM runtime_state WHERE singleton_id=1 AND active_uplink_id=?", mutation.UplinkID).Scan(&active); err != nil {
			return ethernetContext{}, err
		}
		if active != 0 {
			return ethernetContext{}, errors.New("active Ethernet uplink cannot be deleted")
		}
	default:
		return ethernetContext{}, errors.New("unsupported Ethernet operation")
	}
	if mutation.Operation != EthernetDelete {
		if err := backend.validateEthernetSubnetConflicts(ctx, configuration, manifest); err != nil {
			return ethernetContext{}, err
		}
	}
	return context, nil
}

func (backend UbuntuBackend) requireInterfaceRoleFree(ctx context.Context, interfaceID string) error {
	var conflicts int
	if err := backend.Database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM interface_role_assignments
WHERE network_interface_id=? AND role NOT IN ('UNUSED', 'SHARED_ONE_ARM')`, interfaceID).Scan(&conflicts); err != nil {
		return fmt.Errorf("read protected interface roles: %w", err)
	}
	if conflicts != 0 {
		return errors.New("target interface already has an active role")
	}
	return nil
}

func (backend UbuntuBackend) validateEthernetSubnetConflicts(ctx context.Context, configuration config.Config, manifest Manifest) error {
	mutation := manifest.Ethernet
	if mutation.Operation == EthernetDelete || mutation.AddressMode != uplink.AddressStatic {
		return nil
	}
	candidate, _ := netip.ParsePrefix(mutation.IPv4CIDR)
	candidate = candidate.Masked()
	lan, err := netip.ParsePrefix(configuration.Network.LANAddress)
	if err != nil || candidate.Overlaps(lan.Masked()) || candidate.Overlaps(netip.MustParsePrefix("10.80.0.0/24")) {
		return errors.New("static Ethernet subnet overlaps LAN or WireGuard management")
	}
	rows, err := backend.Database.QueryContext(ctx, `
SELECT id, ipv4_cidr FROM uplinks
WHERE id<>? AND ipv4_cidr IS NOT NULL AND ipv4_cidr<>''`, mutation.UplinkID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		other, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("stored uplink %s has an invalid IPv4 prefix", id)
		}
		if candidate.Overlaps(other.Masked()) {
			return fmt.Errorf("static Ethernet subnet overlaps uplink %s", id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	interfaceRows, err := backend.Database.QueryContext(ctx, `
SELECT id, addresses_json FROM network_interfaces
WHERE id<>?
  AND id<>COALESCE((SELECT network_interface_id FROM uplinks WHERE id=?), '')`,
		mutation.TargetInterfaceID, mutation.UplinkID)
	if err != nil {
		return err
	}
	defer interfaceRows.Close()
	for interfaceRows.Next() {
		var interfaceID, encoded string
		if err := interfaceRows.Scan(&interfaceID, &encoded); err != nil {
			return err
		}
		var addresses []string
		if err := json.Unmarshal([]byte(encoded), &addresses); err != nil {
			return fmt.Errorf("stored interface %s has invalid observed addresses", interfaceID)
		}
		for _, raw := range addresses {
			observed, err := netip.ParsePrefix(raw)
			if err != nil {
				return fmt.Errorf("stored interface %s has an invalid observed prefix", interfaceID)
			}
			if observed.Addr().Is4() && candidate.Overlaps(observed.Masked()) {
				return fmt.Errorf("static Ethernet subnet overlaps observed interface %s", interfaceID)
			}
		}
	}
	if err := interfaceRows.Err(); err != nil {
		return err
	}
	return nil
}

func (backend UbuntuBackend) snapshotEthernetRoles(ctx context.Context, manifest Manifest, current ethernetContext) ([]ethernetRoleSnapshot, error) {
	ids := []string{manifest.Ethernet.TargetInterfaceID}
	if current.Existing != nil && current.Existing.NetworkInterfaceID != manifest.Ethernet.TargetInterfaceID {
		ids = append(ids, current.Existing.NetworkInterfaceID)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for index := range ids {
		args[index] = ids[index]
	}
	rows, err := backend.Database.QueryContext(ctx, `
SELECT id, network_interface_id, role, COALESCE(uplink_id, ''),
       desired_generation, observed_generation, state, created_at, updated_at
FROM interface_role_assignments WHERE network_interface_id IN (`+placeholders+`)
ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ethernetRoleSnapshot, 0)
	for rows.Next() {
		var item ethernetRoleSnapshot
		if err := rows.Scan(&item.ID, &item.NetworkInterfaceID, &item.Role, &item.UplinkID, &item.DesiredGeneration, &item.ObservedGeneration, &item.State, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (backend UbuntuBackend) restoreEthernetDatabase(ctx context.Context, manifest Manifest, snapshot ethernetSnapshot) error {
	transaction, err := backend.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	mutation := manifest.Ethernet
	restoredRoleGeneration := int64(0)
	if snapshot.Uplink == nil {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM uplinks WHERE id=? AND type='ETHERNET'", mutation.UplinkID); err != nil {
			return fmt.Errorf("remove rolled-back Ethernet uplink: %w", err)
		}
	} else {
		var currentDesired, currentRoute int64
		if err := transaction.QueryRowContext(ctx, `
SELECT desired_generation, route_generation FROM uplinks WHERE id=? AND type='ETHERNET'`, mutation.UplinkID).Scan(&currentDesired, &currentRoute); err != nil {
			return fmt.Errorf("read rollback Ethernet generations: %w", err)
		}
		nextDesired := maxInt64(currentDesired+1, snapshot.Uplink.DesiredGeneration+1)
		nextRoute := maxInt64(currentRoute+1, snapshot.Uplink.RouteGeneration+1)
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := transaction.ExecContext(ctx, `
UPDATE uplinks SET
    name=?, enabled=?, priority=?, network_interface_id=?, address_mode=?, ipv4_cidr=?,
    gateway=?, dns_json=?, configured_ipv4_cidr=?, configured_gateway=?,
    configured_dns_json=?, mtu=?, route_generation=?, desired_generation=?,
    observed_generation=0, state='UPLINK_CONFIGURING', last_seen_at=NULL,
    readiness_reason='SAFE_APPLY_ROLLED_BACK', stable_since=NULL, updated_at=?
WHERE id=? AND type='ETHERNET'`,
			snapshot.Uplink.Name, boolInt(snapshot.Uplink.Enabled), snapshot.Uplink.Priority,
			snapshot.Uplink.NetworkInterfaceID, snapshot.Uplink.AddressMode,
			nullIfBlank(snapshot.Uplink.IPv4CIDR), nullIfBlank(snapshot.Uplink.Gateway),
			snapshot.Uplink.DNSJSON, nullIfBlank(snapshot.Uplink.ConfiguredIPv4CIDR),
			nullIfBlank(snapshot.Uplink.ConfiguredGateway), snapshot.Uplink.ConfiguredDNSJSON,
			nullIfZeroInt(snapshot.Uplink.MTU), nextRoute,
			nextDesired, now, mutation.UplinkID)
		if err != nil {
			return fmt.Errorf("restore Ethernet uplink snapshot: %w", err)
		}
		restoredRoleGeneration = nextDesired
		if err := invalidateEthernetPathsTx(ctx, transaction, mutation.UplinkID, nextRoute, now); err != nil {
			return err
		}
	}
	interfaceIDs := []string{mutation.TargetInterfaceID}
	if snapshot.PreviousInterfaceID != "" && snapshot.PreviousInterfaceID != mutation.TargetInterfaceID {
		interfaceIDs = append(interfaceIDs, snapshot.PreviousInterfaceID)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(interfaceIDs)), ",")
	args := make([]any, len(interfaceIDs))
	for index := range interfaceIDs {
		args[index] = interfaceIDs[index]
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM interface_role_assignments WHERE network_interface_id IN (`+placeholders+`)`, args...); err != nil {
		return fmt.Errorf("clear candidate Ethernet roles: %w", err)
	}
	for _, role := range snapshot.Roles {
		uplinkID := any(nil)
		if role.UplinkID != "" {
			uplinkID = role.UplinkID
		}
		desired := role.DesiredGeneration
		observed := role.ObservedGeneration
		if role.UplinkID == mutation.UplinkID && role.Role == "ETHERNET_UPLINK" {
			if restoredRoleGeneration > desired {
				desired = restoredRoleGeneration
			} else {
				desired++
			}
			observed = 0
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO interface_role_assignments(
    id, network_interface_id, role, uplink_id, desired_generation,
    observed_generation, state, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			role.ID, role.NetworkInterfaceID, role.Role, uplinkID, desired,
			observed, role.State, role.CreatedAt, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("restore Ethernet interface role: %w", err)
		}
	}
	return transaction.Commit()
}

func invalidateEthernetPathsTx(ctx context.Context, transaction *sql.Tx, uplinkID string, routeGeneration int64, now string) error {
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths SET route_generation=?, state='STALE',
transport_state='UNKNOWN', selected_node_id=NULL, qualified_nodes=0,
required_targets_passed=0, optional_targets_passed=0, quality_class='UNKNOWN',
functional_score=0, last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, routeGeneration, now, uplinkID); err != nil {
		return err
	}
	_, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths SET route_generation=?, state='STALE',
transport_state='UNKNOWN', quality_class='UNKNOWN', functional_score=0,
required_targets_passed=0, optional_targets_passed=0, whitelist_targets_passed=0,
last_checked_at=NULL, expires_at=NULL, updated_at=? WHERE uplink_id=?`,
		routeGeneration, now, uplinkID)
	return err
}

func readEthernetSnapshot(snapshotDirectory string, manifest Manifest) (ethernetSnapshot, error) {
	payload, err := readBoundedRegular(filepath.Join(snapshotDirectory, "ethernet-state.json"), 1<<20)
	if err != nil {
		return ethernetSnapshot{}, err
	}
	var snapshot ethernetSnapshot
	if err := decodeStrictJSON(payload, &snapshot); err != nil {
		return ethernetSnapshot{}, errors.New("decode Ethernet safe-apply snapshot failed")
	}
	if manifest.Ethernet.Operation != EthernetDelete && !validInterfaceName(snapshot.TargetIfname) ||
		snapshot.TargetIfname != "" && !validInterfaceName(snapshot.TargetIfname) ||
		snapshot.Uplink != nil && snapshot.Uplink.ID != manifest.Ethernet.UplinkID {
		return ethernetSnapshot{}, errors.New("Ethernet safe-apply snapshot does not match manifest")
	}
	return snapshot, nil
}

func (backend UbuntuBackend) ethernetOwnedPath(uplinkID string) string {
	digest := sha256.Sum256([]byte(uplinkID))
	return filepath.Join(backend.Paths.EthernetNetworkDir, "15-gateway-vpn-ethernet-"+hex.EncodeToString(digest[:8])+".network")
}

func renderEthernetNetwork(item uplink.Uplink) (string, error) {
	if item.Type != uplink.TypeEthernet || !validInterfaceName(item.CurrentIfname) || item.RoutingTableID < 1 {
		return "", errors.New("complete protected Ethernet uplink is required")
	}
	var builder strings.Builder
	builder.WriteString("# Managed by Gateway VPN; edit through WebUI safe apply.\n[Match]\nName=")
	builder.WriteString(item.CurrentIfname)
	builder.WriteString("\n\n[Link]\nRequiredForOnline=no\n")
	if item.MTU != 0 {
		builder.WriteString("MTUBytes=" + strconv.FormatInt(item.MTU, 10) + "\n")
	}
	builder.WriteString("\n[Network]\nIPv6AcceptRA=no\nLinkLocalAddressing=no\nDNSDefaultRoute=no\n")
	var dns []string
	if err := json.Unmarshal([]byte(item.ConfiguredDNSJSON), &dns); err != nil || len(dns) > 8 {
		return "", errors.New("stored Ethernet DNS is invalid")
	}
	for _, raw := range dns {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() {
			return "", errors.New("stored Ethernet DNS contains an invalid address")
		}
		builder.WriteString("DNS=" + address.String() + "\n")
	}
	if item.AddressMode == uplink.AddressDHCP {
		builder.WriteString("DHCP=ipv4\n\n[DHCPv4]\nRouteTable=" + strconv.FormatInt(item.RoutingTableID, 10) + "\nUseRoutes=yes\nUseGateway=yes\n")
		if len(dns) != 0 {
			builder.WriteString("UseDNS=no\n")
		}
		return builder.String(), nil
	}
	prefix, err := netip.ParsePrefix(item.ConfiguredIPv4CIDR)
	if err != nil || !prefix.Addr().Is4() {
		return "", errors.New("stored static Ethernet address is invalid")
	}
	gateway, err := netip.ParseAddr(item.ConfiguredGateway)
	if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
		return "", errors.New("stored static Ethernet gateway is invalid")
	}
	builder.WriteString("Address=" + prefix.String() + "\n\n[Route]\nGateway=" + gateway.String() + "\nTable=" + strconv.FormatInt(item.RoutingTableID, 10) + "\n")
	return builder.String(), nil
}

func (backend UbuntuBackend) networkctlReconfigure(ctx context.Context, ifname string) error {
	if !validInterfaceName(ifname) {
		return errors.New("protected Ethernet interface name is invalid")
	}
	_, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Paths.Networkctl, Arguments: []string{"reconfigure", ifname}})
	if err != nil {
		return fmt.Errorf("reconfigure protected Ethernet interface: %w", err)
	}
	return nil
}

func sameEthernetAddressConfiguration(item uplink.Uplink, mutation EthernetMutation) bool {
	var currentDNS []string
	if err := json.Unmarshal([]byte(item.ConfiguredDNSJSON), &currentDNS); err != nil {
		return false
	}
	if len(currentDNS) != len(mutation.DNS) {
		return false
	}
	for index := range currentDNS {
		if currentDNS[index] != mutation.DNS[index] {
			return false
		}
	}
	return item.AddressMode == mutation.AddressMode && item.ConfiguredIPv4CIDR == mutation.IPv4CIDR &&
		item.ConfiguredGateway == mutation.Gateway && item.MTU == mutation.MTU
}

func uniqueIfnames(values ...string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validInterfaceName(value) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullIfBlank(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullIfZeroInt(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}
