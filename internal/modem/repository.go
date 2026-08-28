// Package modem owns adopted HiLink modem identity and allocation records.
package modem

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

	"gateway-vpn/internal/store"
)

const (
	StateConfiguredOffline = "MODEM_CONFIGURED_OFFLINE"
	StateDisabled          = "MODEM_DISABLED"
	StateDiscovered        = "MODEM_DISCOVERED"
	StateLinkUp            = "MODEM_LINK_UP"
	StateConfiguring       = "MODEM_CONFIGURING"
	StateRegistering       = "MODEM_REGISTERING"
	StateRestricted        = "MODEM_RESTRICTED"
	StateReady             = "MODEM_READY"
	StateRecovering        = "MODEM_RECOVERING"
	StateSubnetConflict    = "MODEM_SUBNET_CONFLICT"
	StateError             = "MODEM_ERROR"
)

type Repository struct {
	database          *sql.DB
	routingTableStart uint32
	fwmarkStart       uint32
	now               func() time.Time
}

type AdoptInput struct {
	ID            string
	Name          string
	OperatorLabel string
	IdentityKind  string
	IdentityHash  string
	MaskedSerial  string
}

type UpdateInput struct {
	Name          string
	OperatorLabel string
}

type ReplaceIdentityInput struct {
	IdentityKind string
	IdentityHash string
	MaskedSerial string
}

type Modem struct {
	ID                          string
	DisplayNumber               int64
	Name                        string
	OperatorLabel               string
	ObservedOperator            string
	IdentityKind                string
	IdentityHash                string
	MaskedSerial                string
	Enabled                     bool
	Priority                    int64
	InterfaceName               string
	ManagementCIDR              string
	Gateway                     string
	DNSJSON                     string
	MTU                         int64
	RoutingTableID              uint32
	Fwmark                      uint32
	RouteGeneration             int64
	State                       string
	TelemetryState              string
	ManagementReachabilityState string
	LastSeenAt                  string
	StableSince                 string
	APISecretRef                string
	CreatedAt                   string
	UpdatedAt                   string
}

type LeaseInput struct {
	InterfaceName  string
	ManagementCIDR string
	Gateway        string
	DNS            []string
	MTU            int64
	State          string
}

type LeaseUpdate struct {
	RouteContextChanged bool
	PathsInvalidated    int64
}

func NewRepository(database *sql.DB, routingTableStart, fwmarkStart uint32) *Repository {
	return &Repository{
		database:          database,
		routingTableStart: routingTableStart,
		fwmarkStart:       fwmarkStart,
		now:               time.Now,
	}
}

func (repository *Repository) Adopt(ctx context.Context, input AdoptInput) (Modem, error) {
	if err := validateAdoptInput(input); err != nil {
		return Modem{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Modem{}, fmt.Errorf("begin modem adoption: %w", err)
	}
	defer transaction.Rollback()

	now := repository.now().UTC().Format(time.RFC3339Nano)
	displayNumber, err := store.AllocateCounter(ctx, transaction, "next_modem_display_number", 1, now)
	if err != nil {
		return Modem{}, err
	}
	routingTableID, err := store.AllocateCounter(ctx, transaction, "next_modem_routing_table", int64(repository.routingTableStart), now)
	if err != nil {
		return Modem{}, err
	}
	fwmark, err := store.AllocateCounter(ctx, transaction, "next_modem_fwmark", int64(repository.fwmarkStart), now)
	if err != nil {
		return Modem{}, err
	}
	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM modems WHERE enabled=1").Scan(&priority); err != nil {
		return Modem{}, fmt.Errorf("allocate modem priority: %w", err)
	}

	_, err = transaction.ExecContext(ctx, `
INSERT INTO modems (
    id, display_number, name, operator_label, identity_kind, identity_hash,
    masked_serial, enabled, priority, routing_table_id, fwmark, state,
    telemetry_state, management_reachability_state, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'UNKNOWN', 'UNTESTED', ?, ?)`,
		input.ID,
		displayNumber,
		strings.TrimSpace(input.Name),
		nullIfEmpty(input.OperatorLabel),
		input.IdentityKind,
		strings.ToLower(input.IdentityHash),
		nullIfEmpty(input.MaskedSerial),
		priority,
		routingTableID,
		fwmark,
		StateConfiguredOffline,
		now,
		now,
	)
	if err != nil {
		return Modem{}, fmt.Errorf("insert adopted modem: %w", err)
	}
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_ADOPTED", input.ID, map[string]any{
		"display_number": displayNumber, "name": strings.TrimSpace(input.Name),
		"operator_label": strings.TrimSpace(input.OperatorLabel), "identity_kind": input.IdentityKind,
		"routing_table_id": routingTableID, "fwmark": fwmark,
	}); err != nil {
		return Modem{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Modem{}, fmt.Errorf("commit modem adoption: %w", err)
	}
	return repository.Get(ctx, input.ID)
}

func (repository *Repository) Get(ctx context.Context, id string) (Modem, error) {
	row := repository.database.QueryRowContext(ctx, modemSelect+" WHERE id=?", id)
	item, err := scanModem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Modem{}, store.ErrNotFound
	}
	if err != nil {
		return Modem{}, fmt.Errorf("get modem: %w", err)
	}
	return item, nil
}

func (repository *Repository) List(ctx context.Context) ([]Modem, error) {
	rows, err := repository.database.QueryContext(ctx, modemSelect+" ORDER BY enabled DESC, priority, display_number")
	if err != nil {
		return nil, fmt.Errorf("list modems: %w", err)
	}
	defer rows.Close()

	var result []Modem
	for rows.Next() {
		item, err := scanModem(rows)
		if err != nil {
			return nil, fmt.Errorf("scan modem: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate modems: %w", err)
	}
	return result, nil
}

func (repository *Repository) ReorderEnabled(ctx context.Context, orderedIDs []string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem reorder: %w", err)
	}
	defer transaction.Rollback()

	if err := validateEnabledSet(ctx, transaction, orderedIDs); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE modems SET priority=-display_number WHERE enabled=1"); err != nil {
		return fmt.Errorf("temporarily clear modem priorities: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for index, id := range orderedIDs {
		result, err := transaction.ExecContext(ctx, "UPDATE modems SET priority=?, updated_at=? WHERE id=? AND enabled=1", (index+1)*10, now, id)
		if err != nil {
			return fmt.Errorf("set modem priority: %w", err)
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_PRIORITY_REORDERED", "", map[string]any{"ordered_modem_ids": orderedIDs}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit modem reorder: %w", err)
	}
	return nil
}

func (repository *Repository) Update(ctx context.Context, id string, input UpdateInput) error {
	name := strings.TrimSpace(input.Name)
	operator := strings.TrimSpace(input.OperatorLabel)
	if id == "" || name == "" || len(name) > 128 || len(operator) > 128 {
		return errors.New("modem name is required and labels are limited to 128 characters")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem update: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, "UPDATE modems SET name=?, operator_label=?, updated_at=? WHERE id=?", name, nullIfEmpty(operator), now, id)
	if err != nil {
		return fmt.Errorf("update modem metadata: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_UPDATED", id, map[string]any{"name": name, "operator_label": operator}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) ApplyLease(ctx context.Context, id string, input LeaseInput) (LeaseUpdate, error) {
	if err := validateLeaseInput(input); err != nil {
		return LeaseUpdate{}, err
	}
	dnsJSON, err := json.Marshal(input.DNS)
	if err != nil {
		return LeaseUpdate{}, fmt.Errorf("encode modem DNS: %w", err)
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return LeaseUpdate{}, fmt.Errorf("begin modem lease update: %w", err)
	}
	defer transaction.Rollback()
	var currentInterface, currentCIDR, currentGateway string
	var currentMTU int64
	var currentState string
	var enabled int
	err = transaction.QueryRowContext(ctx, `
SELECT COALESCE(interface_name, ''), COALESCE(management_cidr, ''), COALESCE(gateway, ''),
       COALESCE(mtu, 0), state, enabled
FROM modems WHERE id=?`, id).Scan(&currentInterface, &currentCIDR, &currentGateway, &currentMTU, &currentState, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return LeaseUpdate{}, store.ErrNotFound
	}
	if err != nil {
		return LeaseUpdate{}, fmt.Errorf("read modem before lease update: %w", err)
	}
	routeChanged := currentInterface != input.InterfaceName || currentCIDR != input.ManagementCIDR || currentGateway != input.Gateway || currentMTU != input.MTU
	now := repository.now().UTC().Format(time.RFC3339Nano)
	state := input.State
	if enabled == 0 {
		state = StateDisabled
	}
	stableSince := any(nil)
	if state == StateReady {
		if currentState == StateReady && !routeChanged {
			var existing sql.NullString
			if err := transaction.QueryRowContext(ctx, "SELECT stable_since FROM modems WHERE id=?", id).Scan(&existing); err != nil {
				return LeaseUpdate{}, err
			}
			stableSince = nullIfEmpty(existing.String)
		} else {
			stableSince = now
		}
	}
	_, err = transaction.ExecContext(ctx, `
UPDATE modems
SET interface_name=?, management_cidr=?, gateway=?, dns_json=?, mtu=?, state=?,
    last_seen_at=?, stable_since=?, updated_at=?
WHERE id=?`, input.InterfaceName, input.ManagementCIDR, input.Gateway, string(dnsJSON), input.MTU, state, now, stableSince, now, id)
	if err != nil {
		return LeaseUpdate{}, fmt.Errorf("update modem lease: %w", err)
	}
	if routeChanged {
		if _, err := transaction.ExecContext(ctx, "UPDATE modems SET management_reachability_state='STALE' WHERE id=?", id); err != nil {
			return LeaseUpdate{}, fmt.Errorf("stale management reachability after lease change: %w", err)
		}
	}
	update := LeaseUpdate{RouteContextChanged: routeChanged}
	if routeChanged {
		if _, err := transaction.ExecContext(ctx, "UPDATE modems SET route_generation=route_generation+1 WHERE id=?", id); err != nil {
			return LeaseUpdate{}, fmt.Errorf("advance modem route generation after lease change: %w", err)
		}
		result, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state='STALE', transport_state='UNKNOWN',
    selected_node_id=NULL, qualified_nodes=0, required_targets_passed=0,
    optional_targets_passed=0, quality_class='UNKNOWN', functional_score=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, id, now, id)
		if err != nil {
			return LeaseUpdate{}, fmt.Errorf("invalidate modem paths after lease change: %w", err)
		}
		update.PathsInvalidated, err = result.RowsAffected()
		if err != nil {
			return LeaseUpdate{}, fmt.Errorf("count invalidated modem paths: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state='STALE', transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0, whitelist_targets_passed=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, id, now, id); err != nil {
			return LeaseUpdate{}, fmt.Errorf("invalidate direct path after lease change: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return LeaseUpdate{}, fmt.Errorf("commit modem lease update: %w", err)
	}
	return update, nil
}

func (repository *Repository) MarkOffline(ctx context.Context, id string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem offline transition: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE modems
SET interface_name=NULL, state=CASE WHEN enabled=1 THEN ? ELSE ? END,
    management_reachability_state='STALE', stable_since=NULL,
    route_generation=route_generation+1, updated_at=?
WHERE id=?`, StateConfiguredOffline, StateDisabled, now, id)
	if err != nil {
		return fmt.Errorf("mark modem offline: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state='UPLINK_OFFLINE', transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, id, now, id); err != nil {
		return fmt.Errorf("mark modem paths offline: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state='UPLINK_OFFLINE', transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0, whitelist_targets_passed=0,
    expires_at=NULL, updated_at=?
WHERE uplink_id=?`, id, now, id); err != nil {
		return fmt.Errorf("mark direct modem path offline: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit modem offline transition: %w", err)
	}
	return nil
}

func (repository *Repository) SetEnabled(ctx context.Context, id string, enabled bool) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem enabled update: %w", err)
	}
	defer transaction.Rollback()
	var currentEnabled int
	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT enabled, priority FROM modems WHERE id=?", id).Scan(&currentEnabled, &priority); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if enabled == (currentEnabled != 0) {
		return transaction.Commit()
	}
	if enabled {
		if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM modems WHERE enabled=1").Scan(&priority); err != nil {
			return err
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	state := StateDisabled
	if enabled {
		state = StateConfiguredOffline
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE modems
SET enabled=?, priority=?, state=?, stable_since=NULL,
    interface_name=CASE WHEN ?=0 THEN NULL ELSE interface_name END,
    management_reachability_state='STALE', route_generation=route_generation+1,
    updated_at=?
WHERE id=?`, boolInt(enabled), priority, state, boolInt(enabled), now, id); err != nil {
		return fmt.Errorf("update modem enabled state: %w", err)
	}
	pathState := "UPLINK_DISABLED"
	if enabled {
		pathState = "UPLINK_OFFLINE"
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state=?, transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, id, pathState, now, id); err != nil {
		return fmt.Errorf("update modem path enabled state: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state=?, transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0, whitelist_targets_passed=0,
    expires_at=NULL, updated_at=?
WHERE uplink_id=?`, id, pathState, now, id); err != nil {
		return fmt.Errorf("update direct modem path enabled state: %w", err)
	}
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_ENABLED_CHANGED", id, map[string]any{"enabled": enabled, "priority": priority}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit modem enabled update: %w", err)
	}
	return nil
}

func (repository *Repository) SetRecovering(ctx context.Context, id string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem recovery: %w", err)
	}
	defer transaction.Rollback()
	var enabled int
	if err := transaction.QueryRowContext(ctx, "SELECT enabled FROM modems WHERE id=?", id).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if enabled == 0 {
		return errors.New("disabled modem cannot be recovered")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE modems
SET state=?, stable_since=NULL, management_reachability_state='STALE', updated_at=?
WHERE id=? AND enabled=1`, StateRecovering, now, id)
	if err != nil {
		return fmt.Errorf("mark modem recovering: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET state='STALE', transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, now, id); err != nil {
		return fmt.Errorf("invalidate paths for modem recovery: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET state='STALE', transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0, whitelist_targets_passed=0,
    expires_at=NULL, updated_at=?
WHERE uplink_id=?`, now, id); err != nil {
		return fmt.Errorf("invalidate direct path for modem recovery: %w", err)
	}
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_RECOVERY_REQUESTED", id, nil); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) ReplaceIdentity(ctx context.Context, id string, input ReplaceIdentityInput) error {
	if err := validateIdentity(input.IdentityKind, input.IdentityHash, input.MaskedSerial); err != nil {
		return err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem identity replacement: %w", err)
	}
	defer transaction.Rollback()
	var currentState, currentInterface string
	if err := transaction.QueryRowContext(ctx, "SELECT state, COALESCE(interface_name, '') FROM modems WHERE id=?", id).Scan(&currentState, &currentInterface); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if currentInterface != "" || (currentState != StateConfiguredOffline && currentState != StateDisabled) {
		return errors.New("modem identity can be replaced only while the configured modem is offline")
	}
	var identityConflict int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM modems WHERE identity_kind=? AND identity_hash=? AND id<>?", input.IdentityKind, strings.ToLower(input.IdentityHash), id).Scan(&identityConflict); err != nil {
		return err
	}
	if identityConflict != 0 {
		return errors.New("modem identity is already adopted")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE modems
SET identity_kind=?, identity_hash=?, masked_serial=?, management_reachability_state='UNTESTED', updated_at=?
WHERE id=?`, input.IdentityKind, strings.ToLower(input.IdentityHash), nullIfEmpty(input.MaskedSerial), now, id); err != nil {
		return fmt.Errorf("replace modem identity: %w", err)
	}
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_IDENTITY_REPLACED", id, map[string]any{"identity_kind": input.IdentityKind, "masked_serial": strings.TrimSpace(input.MaskedSerial)}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) Forget(ctx context.Context, id string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem forget: %w", err)
	}
	defer transaction.Rollback()
	var currentState, currentInterface string
	if err := transaction.QueryRowContext(ctx, "SELECT state, COALESCE(interface_name, '') FROM modems WHERE id=?", id).Scan(&currentState, &currentInterface); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if currentInterface != "" || (currentState != StateConfiguredOffline && currentState != StateDisabled) {
		return errors.New("only an offline modem can be forgotten")
	}
	var activeID, managementID sql.NullString
	if err := transaction.QueryRowContext(ctx, "SELECT active_modem_id, management_modem_id FROM runtime_state WHERE singleton_id=1").Scan(&activeID, &managementID); err != nil {
		return err
	}
	if activeID.String == id || managementID.String == id {
		return errors.New("active data or management modem cannot be forgotten")
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM modems WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("forget modem: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if err := appendModemEventTx(ctx, transaction, now, "MODEM_FORGOTTEN", id, nil); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) SetObservedState(ctx context.Context, id, observedState string) error {
	if !validObservedState(observedState) && observedState != StateConfiguredOffline && observedState != StateDisabled {
		return errors.New("invalid modem observed state")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := repository.database.ExecContext(ctx, `
UPDATE modems
SET state=CASE WHEN enabled=1 THEN ? ELSE ? END,
    stable_since=CASE WHEN ?=? THEN stable_since ELSE NULL END,
    last_seen_at=CASE WHEN ?=? THEN last_seen_at ELSE ? END,
    updated_at=?
WHERE id=?`, observedState, StateDisabled, observedState, StateReady, observedState, StateConfiguredOffline, now, now, id)
	if err != nil {
		return fmt.Errorf("update modem observed state: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (repository *Repository) UpdateTelemetry(ctx context.Context, id, telemetryState, observedOperator string) error {
	if telemetryState != "AVAILABLE" && telemetryState != "UNAVAILABLE" && telemetryState != "UNKNOWN" {
		return errors.New("invalid modem telemetry state")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := repository.database.ExecContext(ctx, "UPDATE modems SET telemetry_state=?, observed_operator=?, updated_at=? WHERE id=?", telemetryState, nullIfEmpty(observedOperator), now, id)
	if err != nil {
		return fmt.Errorf("update modem telemetry: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (repository *Repository) SetManagementReachability(ctx context.Context, id, reachability string) error {
	if reachability != "UNTESTED" && reachability != "PROBING" && reachability != "REACHABLE" && reachability != "BLOCKED" && reachability != "STALE" {
		return errors.New("invalid modem management reachability state")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := repository.database.ExecContext(ctx, "UPDATE modems SET management_reachability_state=?, updated_at=? WHERE id=?", reachability, now, id)
	if err != nil {
		return fmt.Errorf("update modem management reachability: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	return nil
}

func validateAdoptInput(input AdoptInput) error {
	if strings.TrimSpace(input.ID) == "" {
		return errors.New("modem id is required")
	}
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 || len(strings.TrimSpace(input.OperatorLabel)) > 128 {
		return errors.New("modem name is required")
	}
	return validateIdentity(input.IdentityKind, input.IdentityHash, input.MaskedSerial)
}

func validateIdentity(kind, hash, maskedSerial string) error {
	if !oneOf(kind, "hilink_serial_hash", "usb_serial_hash", "mac_hash", "usb_topology_hash") {
		return errors.New("unsupported modem identity kind")
	}
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != sha256Bytes {
		return errors.New("modem identity hash must be a 64-character SHA-256 hex value")
	}
	if len(strings.TrimSpace(maskedSerial)) > 128 {
		return errors.New("masked modem serial is too long")
	}
	return nil
}

func appendModemEventTx(ctx context.Context, transaction *sql.Tx, now, eventType, modemID string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	content, err := json.Marshal(details)
	if err != nil {
		return errors.New("encode modem audit event failed")
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, modem_id, details_json)
VALUES (?, 'INFO', ?, ?, ?)`, now, eventType, nullIfEmpty(modemID), string(content)); err != nil {
		return fmt.Errorf("append modem audit event: %w", err)
	}
	return nil
}

func validateLeaseInput(input LeaseInput) error {
	if !validInterfaceName(input.InterfaceName) {
		return errors.New("modem lease has invalid interface name")
	}
	prefix, err := netip.ParsePrefix(input.ManagementCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return errors.New("modem management CIDR must be a masked IPv4 prefix /8..30")
	}
	gateway, err := netip.ParseAddr(input.Gateway)
	if err != nil || !gateway.Is4() || !prefix.Contains(gateway) || gateway.IsUnspecified() || gateway.IsMulticast() {
		return errors.New("modem gateway must be usable IPv4 inside management CIDR")
	}
	for _, raw := range input.DNS {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return errors.New("modem DNS must contain usable IPv4 addresses")
		}
	}
	if input.MTU < 576 || input.MTU > 9000 || !validObservedState(input.State) {
		return errors.New("modem lease MTU or observed state is invalid")
	}
	return nil
}

func validObservedState(value string) bool {
	switch value {
	case StateDiscovered, StateLinkUp, StateConfiguring, StateRegistering, StateRestricted, StateReady, StateRecovering, StateSubnetConflict, StateError:
		return true
	default:
		return false
	}
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:-", char) {
			continue
		}
		return false
	}
	return true
}

const sha256Bytes = 32

func validateEnabledSet(ctx context.Context, transaction *sql.Tx, orderedIDs []string) error {
	seen := make(map[string]struct{}, len(orderedIDs))
	for _, id := range orderedIDs {
		if id == "" {
			return store.ErrPrioritySetMismatch
		}
		if _, exists := seen[id]; exists {
			return store.ErrPrioritySetMismatch
		}
		seen[id] = struct{}{}
	}
	rows, err := transaction.QueryContext(ctx, "SELECT id FROM modems WHERE enabled=1")
	if err != nil {
		return fmt.Errorf("read enabled modems: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan enabled modem: %w", err)
		}
		if _, exists := seen[id]; !exists {
			return store.ErrPrioritySetMismatch
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate enabled modems: %w", err)
	}
	if count != len(orderedIDs) {
		return store.ErrPrioritySetMismatch
	}
	return nil
}

const modemSelect = `
SELECT id, display_number, name, operator_label, observed_operator,
       identity_kind, identity_hash, masked_serial, enabled, priority,
       interface_name, management_cidr, gateway, dns_json, mtu,
       routing_table_id, fwmark, route_generation, state, telemetry_state,
       management_reachability_state, last_seen_at, stable_since,
       api_secret_ref, created_at, updated_at
FROM modems`

type scanner interface {
	Scan(dest ...any) error
}

func scanModem(row scanner) (Modem, error) {
	var item Modem
	var operatorLabel, observedOperator, maskedSerial sql.NullString
	var interfaceName, managementCIDR, gateway, dnsJSON sql.NullString
	var mtu sql.NullInt64
	var lastSeenAt, stableSince, apiSecretRef sql.NullString
	var enabled int64
	err := row.Scan(
		&item.ID,
		&item.DisplayNumber,
		&item.Name,
		&operatorLabel,
		&observedOperator,
		&item.IdentityKind,
		&item.IdentityHash,
		&maskedSerial,
		&enabled,
		&item.Priority,
		&interfaceName,
		&managementCIDR,
		&gateway,
		&dnsJSON,
		&mtu,
		&item.RoutingTableID,
		&item.Fwmark,
		&item.RouteGeneration,
		&item.State,
		&item.TelemetryState,
		&item.ManagementReachabilityState,
		&lastSeenAt,
		&stableSince,
		&apiSecretRef,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	item.Enabled = enabled != 0
	item.OperatorLabel = operatorLabel.String
	item.ObservedOperator = observedOperator.String
	item.MaskedSerial = maskedSerial.String
	item.InterfaceName = interfaceName.String
	item.ManagementCIDR = managementCIDR.String
	item.Gateway = gateway.String
	item.DNSJSON = dnsJSON.String
	item.MTU = mtu.Int64
	item.LastSeenAt = lastSeenAt.String
	item.StableSince = stableSince.String
	item.APISecretRef = apiSecretRef.String
	return item, err
}

func nullIfEmpty(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
