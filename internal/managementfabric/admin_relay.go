package managementfabric

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"gateway-vpn/internal/store"
	"gateway-vpn/internal/wgingress"
)

const maximumAdminRelays = 256

// ConfigureAdminContour stores only the public identity and the fixed
// root-owned secret reference supplied by the privileged controller. It never
// creates or reads private key material itself.
func (repository *Repository) ConfigureAdminContour(ctx context.Context, input AdminContourRootInput) (AdminContour, error) {
	if repository == nil || repository.Database == nil || input.InterfaceName != AdminInterfaceName ||
		input.PrivateKeySecretRef != AdminPrivateKeySecretRef || input.ListenPort != AdminListenPort ||
		!wgingress.ValidKey(strings.TrimSpace(input.PublicKey)) {
		return AdminContour{}, errors.New("valid privileged administrator contour identity is required")
	}
	prefix, err := canonicalPrivatePrefix(input.Subnet, 16, 30)
	if err != nil {
		return AdminContour{}, errors.New("administrator contour subnet is invalid")
	}
	address, err := canonicalHostAddress(input.GatewayAddress, prefix)
	if err != nil {
		return AdminContour{}, errors.New("administrator contour Gateway address is invalid")
	}
	input.Subnet, input.GatewayAddress, input.PublicKey = prefix.String(), address.String(), strings.TrimSpace(input.PublicKey)
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminContour{}, err
	}
	defer tx.Rollback()
	if err := repository.rejectPrefixCollisionsTx(ctx, tx, []namedPrefix{{owner: "administrator-contour", prefix: prefix}}, "", true); err != nil {
		return AdminContour{}, err
	}
	var existing AdminContour
	var enabled int
	err = tx.QueryRowContext(ctx, adminContourSelect+" WHERE singleton_id=1").Scan(
		&enabled, &existing.InterfaceName, &existing.privateKeySecretRef, &existing.PublicKey,
		&existing.Subnet, &existing.GatewayAddress, &existing.ListenPort,
		&existing.DesiredGeneration, &existing.AppliedGeneration, &existing.State,
		&existing.LastErrorCode, &existing.CreatedAt, &existing.UpdatedAt,
	)
	stamp := repository.now().Format(time.RFC3339Nano)
	nextState := "CONFIGURED"
	if !input.Enabled {
		nextState = "DISABLED"
	}
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
INSERT INTO management_admin_contour(
 singleton_id,enabled,interface_name,private_key_secret_ref,public_key,subnet,
 gateway_address,listen_port,desired_generation,applied_generation,state,last_error_code,created_at,updated_at
) VALUES(1,?,?,?,?,?,?,?,1,0,?,'',?,?)`, boolInt(input.Enabled), input.InterfaceName,
			input.PrivateKeySecretRef, input.PublicKey, input.Subnet, input.GatewayAddress,
			input.ListenPort, nextState, stamp, stamp)
		if err != nil {
			return AdminContour{}, fmt.Errorf("create administrator contour: %w", err)
		}
	} else if err != nil {
		return AdminContour{}, err
	} else {
		existing.Enabled = enabled != 0
		if existing.InterfaceName != input.InterfaceName || existing.privateKeySecretRef != input.PrivateKeySecretRef || existing.PublicKey != input.PublicKey {
			return AdminContour{}, errors.New("administrator contour identity may change only through explicit root rotation")
		}
		if existing.Enabled == input.Enabled && existing.Subnet == input.Subnet && existing.GatewayAddress == input.GatewayAddress && existing.ListenPort == input.ListenPort {
			if err := tx.Commit(); err != nil {
				return AdminContour{}, err
			}
			return repository.GetAdminContour(ctx)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_contour
SET enabled=?,subnet=?,gateway_address=?,listen_port=?,desired_generation=desired_generation+1,
    state=?,last_error_code='',updated_at=?
WHERE singleton_id=1`, boolInt(input.Enabled), input.Subnet, input.GatewayAddress,
			input.ListenPort, nextState, stamp); err != nil {
			return AdminContour{}, fmt.Errorf("update administrator contour: %w", err)
		}
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return AdminContour{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminContour{}, err
	}
	return repository.GetAdminContour(ctx)
}

func (repository *Repository) RotateAdminContourIdentity(ctx context.Context, publicKey string) (AdminContour, error) {
	rotated, _, err := repository.RotateAdminContourIdentityWithRollback(ctx, publicKey)
	return rotated, err
}

// RotateAdminContourIdentityWithRollback atomically captures the exact
// pre-rotation desired/applied metadata and stages the new public identity.
// The opaque snapshot is accepted only by RestoreAdminContourIdentityRotation
// and only while the database still matches this specific rotation.
func (repository *Repository) RotateAdminContourIdentityWithRollback(ctx context.Context, publicKey string) (AdminContour, AdminIdentityRotationSnapshot, error) {
	publicKey = strings.TrimSpace(publicKey)
	if repository == nil || repository.Database == nil || !wgingress.ValidKey(publicKey) {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, errors.New("valid generated administrator contour public key is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	defer tx.Rollback()
	snapshot := AdminIdentityRotationSnapshot{candidatePublic: publicKey}
	if err := tx.QueryRowContext(ctx, `
SELECT desired_generation,applied_generation,state,last_error_code
FROM management_fabric_generations WHERE singleton_id=1`).Scan(
		&snapshot.fabric.desiredGeneration, &snapshot.fabric.appliedGeneration,
		&snapshot.fabric.state, &snapshot.fabric.errorCode,
	); err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	if err := tx.QueryRowContext(ctx, `
SELECT public_key,desired_generation,applied_generation,state,last_error_code
FROM management_admin_contour WHERE singleton_id=1`).Scan(
		&snapshot.contour.publicKey, &snapshot.contour.desiredGeneration,
		&snapshot.contour.appliedGeneration, &snapshot.contour.state, &snapshot.contour.errorCode,
	); errors.Is(err, sql.ErrNoRows) {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, store.ErrNotFound
	} else if err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT id,desired_generation,applied_generation,state,last_error_code
FROM management_admin_tunnels ORDER BY id`)
	if err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	for rows.Next() {
		var item adminIdentityTunnelState
		if err := rows.Scan(&item.id, &item.desiredGeneration, &item.appliedGeneration, &item.state, &item.errorCode); err != nil {
			rows.Close()
			return AdminContour{}, AdminIdentityRotationSnapshot{}, err
		}
		snapshot.tunnels = append(snapshot.tunnels, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	if err := rows.Close(); err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	if snapshot.contour.publicKey == publicKey {
		if err := tx.Commit(); err != nil {
			return AdminContour{}, AdminIdentityRotationSnapshot{}, err
		}
		contour, err := repository.GetAdminContour(ctx)
		return contour, snapshot, err
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_contour
SET public_key=?,desired_generation=desired_generation+1,state=CASE WHEN enabled=1 THEN 'CONFIGURED' ELSE 'DISABLED' END,
    last_error_code='IDENTITY_ROTATED_CLIENT_UPDATE_REQUIRED',updated_at=?
WHERE singleton_id=1`, publicKey, stamp); err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, fmt.Errorf("rotate administrator contour identity: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_tunnels
SET desired_generation=desired_generation+1,state=CASE WHEN state='REVOKED' THEN state ELSE 'CONFIGURED' END,
    last_error_code=CASE WHEN state='REVOKED' THEN last_error_code ELSE 'SERVER_IDENTITY_ROTATED' END,updated_at=?
WHERE state!='REVOKED'`, stamp); err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminContour{}, AdminIdentityRotationSnapshot{}, err
	}
	contour, err := repository.GetAdminContour(ctx)
	return contour, snapshot, err
}

// RestoreAdminContourIdentityRotation restores the exact pre-rotation state.
// It refuses the rollback if another desired-state mutation advanced the
// generation or replaced the candidate identity in the meantime.
func (repository *Repository) RestoreAdminContourIdentityRotation(ctx context.Context, snapshot AdminIdentityRotationSnapshot) error {
	if repository == nil || repository.Database == nil || !wgingress.ValidKey(snapshot.candidatePublic) ||
		!wgingress.ValidKey(snapshot.contour.publicKey) || snapshot.candidatePublic == snapshot.contour.publicKey ||
		snapshot.fabric.desiredGeneration < 1 || snapshot.fabric.appliedGeneration < 0 ||
		!validFabricState(snapshot.fabric.state) {
		return errors.New("valid administrator identity rollback snapshot is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentPublic string
	var currentDesired int64
	if err := tx.QueryRowContext(ctx, `
SELECT c.public_key,g.desired_generation
FROM management_admin_contour c JOIN management_fabric_generations g ON g.singleton_id=1
WHERE c.singleton_id=1`).Scan(&currentPublic, &currentDesired); err != nil {
		return err
	}
	if currentPublic != snapshot.candidatePublic || currentDesired != snapshot.fabric.desiredGeneration+1 {
		return errors.New("administrator identity rollback refused because desired state changed")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `
UPDATE management_admin_contour
SET public_key=?,desired_generation=?,applied_generation=?,state=?,last_error_code=?,updated_at=?
WHERE singleton_id=1 AND public_key=? AND desired_generation=?`,
		snapshot.contour.publicKey, snapshot.contour.desiredGeneration, snapshot.contour.appliedGeneration,
		snapshot.contour.state, snapshot.contour.errorCode, stamp,
		snapshot.candidatePublic, snapshot.contour.desiredGeneration+1)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("administrator identity rollback contour changed concurrently")
	}
	for _, item := range snapshot.tunnels {
		expectedDesired := item.desiredGeneration
		if item.state != "REVOKED" {
			expectedDesired++
		}
		result, err = tx.ExecContext(ctx, `
UPDATE management_admin_tunnels
SET desired_generation=?,applied_generation=?,state=?,last_error_code=?,updated_at=?
WHERE id=? AND desired_generation=?`, item.desiredGeneration, item.appliedGeneration,
			item.state, item.errorCode, stamp, item.id, expectedDesired)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return errors.New("administrator identity rollback tunnel changed concurrently")
		}
	}
	result, err = tx.ExecContext(ctx, `
UPDATE management_fabric_generations
SET desired_generation=?,applied_generation=?,state=?,last_error_code=?,updated_at=?
WHERE singleton_id=1 AND desired_generation=?`, snapshot.fabric.desiredGeneration,
		snapshot.fabric.appliedGeneration, snapshot.fabric.state, snapshot.fabric.errorCode,
		stamp, snapshot.fabric.desiredGeneration+1)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("administrator identity rollback generation changed concurrently")
	}
	return tx.Commit()
}

func (repository *Repository) GetAdminContour(ctx context.Context) (AdminContour, error) {
	if repository == nil || repository.Database == nil {
		return AdminContour{}, store.ErrNotFound
	}
	var item AdminContour
	var enabled int
	err := repository.Database.QueryRowContext(ctx, adminContourSelect+" WHERE singleton_id=1").Scan(
		&enabled, &item.InterfaceName, &item.privateKeySecretRef, &item.PublicKey,
		&item.Subnet, &item.GatewayAddress, &item.ListenPort, &item.DesiredGeneration,
		&item.AppliedGeneration, &item.State, &item.LastErrorCode, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminContour{}, store.ErrNotFound
	}
	if err != nil {
		return AdminContour{}, fmt.Errorf("read administrator contour: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func (repository *Repository) CreateAdminRelay(ctx context.Context, input AdminRelayInput) (AdminRelay, error) {
	if repository == nil || repository.Database == nil {
		return AdminRelay{}, errors.New("management database is required")
	}
	input = normalizeAdminRelayInput(input)
	if err := validateAdminRelayInput(input); err != nil {
		return AdminRelay{}, err
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminRelay{}, err
	}
	defer tx.Rollback()
	if err := validateAdminRelayReferences(ctx, tx, input); err != nil {
		return AdminRelay{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_admin_relays").Scan(&count); err != nil || count >= maximumAdminRelays {
		return AdminRelay{}, errors.New("administrator relay limit is reached")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	state := "CONFIGURED"
	if !input.Enabled {
		state = "DISABLED"
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO management_admin_relays(
 id,link_id,enabled,public_endpoint_host,public_bind_address,public_udp_port,destination_port,
 rate_limit_per_second,burst_packets,desired_generation,applied_generation,state,last_error_code,created_at,updated_at
) VALUES(?,?,?,?,?,?,?, ?,?,1,0,?,'',?,?)`, input.ID, input.LinkID, boolInt(input.Enabled),
		input.PublicEndpointHost, input.PublicBindAddress, input.PublicUDPPort, AdminListenPort,
		input.RateLimitPerSecond, input.BurstPackets, state, stamp, stamp); err != nil {
		return AdminRelay{}, fmt.Errorf("create administrator relay: %w", err)
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return AdminRelay{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminRelay{}, err
	}
	return repository.GetAdminRelay(ctx, input.ID)
}

func (repository *Repository) UpdateAdminRelay(ctx context.Context, id string, input AdminRelayInput) (AdminRelay, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return AdminRelay{}, store.ErrNotFound
	}
	input.ID = id
	input = normalizeAdminRelayInput(input)
	if err := validateAdminRelayInput(input); err != nil {
		return AdminRelay{}, err
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminRelay{}, err
	}
	defer tx.Rollback()
	var existingLink string
	if err := tx.QueryRowContext(ctx, "SELECT link_id FROM management_admin_relays WHERE id=?", id).Scan(&existingLink); errors.Is(err, sql.ErrNoRows) {
		return AdminRelay{}, store.ErrNotFound
	} else if err != nil {
		return AdminRelay{}, err
	} else if existingLink != input.LinkID {
		return AdminRelay{}, errors.New("administrator relay cannot move to another management link")
	}
	if err := validateAdminRelayReferences(ctx, tx, input); err != nil {
		return AdminRelay{}, err
	}
	state := "CONFIGURED"
	if !input.Enabled {
		state = "DISABLED"
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_relays
SET enabled=?,public_endpoint_host=?,public_bind_address=?,public_udp_port=?,destination_port=?,
    rate_limit_per_second=?,burst_packets=?,desired_generation=desired_generation+1,
    state=?,last_error_code='',updated_at=?
WHERE id=?`, boolInt(input.Enabled), input.PublicEndpointHost, input.PublicBindAddress,
		input.PublicUDPPort, AdminListenPort, input.RateLimitPerSecond, input.BurstPackets,
		state, stamp, id); err != nil {
		return AdminRelay{}, fmt.Errorf("update administrator relay: %w", err)
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return AdminRelay{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminRelay{}, err
	}
	return repository.GetAdminRelay(ctx, id)
}

func (repository *Repository) GetAdminRelay(ctx context.Context, id string) (AdminRelay, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return AdminRelay{}, store.ErrNotFound
	}
	return scanAdminRelay(repository.Database.QueryRowContext(ctx, adminRelaySelect+" WHERE id=?", id))
}

func (repository *Repository) ListAdminRelays(ctx context.Context) ([]AdminRelay, error) {
	if repository == nil || repository.Database == nil {
		return nil, errors.New("management database is required")
	}
	rows, err := repository.Database.QueryContext(ctx, adminRelaySelect+" ORDER BY id LIMIT ?", maximumAdminRelays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AdminRelay, 0)
	for rows.Next() {
		item, err := scanAdminRelay(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository *Repository) DeleteAdminRelay(ctx context.Context, id string) error {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return store.ErrNotFound
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM management_admin_relays WHERE id=?", id).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	} else if enabled != 0 {
		return errors.New("administrator relay must be disabled before deletion")
	}
	var activeTunnels int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_admin_tunnels WHERE relay_id=? AND state!='REVOKED'", id).Scan(&activeTunnels); err != nil || activeTunnels != 0 {
		return errors.New("administrator relay still has active inner tunnels")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "DELETE FROM management_admin_tunnels WHERE relay_id=? AND state='REVOKED'", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM management_admin_relays WHERE id=?", id); err != nil {
		return err
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) CreateAdminTunnel(ctx context.Context, input AdminTunnelInput) (AdminTunnel, error) {
	input.ID, input.AdminID, input.RelayID = strings.TrimSpace(input.ID), strings.TrimSpace(input.AdminID), strings.TrimSpace(input.RelayID)
	input.PublicKey, input.AssignedAddress = strings.TrimSpace(input.PublicKey), strings.TrimSpace(input.AssignedAddress)
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(input.ID) ||
		!safeIdentifier.MatchString(input.AdminID) || !safeIdentifier.MatchString(input.RelayID) || !wgingress.ValidKey(input.PublicKey) {
		return AdminTunnel{}, errors.New("valid administrator inner tunnel is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminTunnel{}, err
	}
	defer tx.Rollback()
	var subnetText, gatewayText string
	var contourEnabled int
	if err := tx.QueryRowContext(ctx, "SELECT enabled,subnet,gateway_address FROM management_admin_contour WHERE singleton_id=1").Scan(&contourEnabled, &subnetText, &gatewayText); err != nil || contourEnabled != 1 {
		return AdminTunnel{}, errors.New("enabled administrator contour is required")
	}
	subnet, _ := canonicalPrivatePrefix(subnetText, 16, 30)
	address, err := canonicalHostAddress(input.AssignedAddress, subnet)
	if err != nil || address.String() == gatewayText {
		return AdminTunnel{}, errors.New("administrator inner address is invalid")
	}
	input.AssignedAddress = address.String()
	var vpsID, linkID string
	var relayEnabled int
	if err := tx.QueryRowContext(ctx, `
SELECT link.vps_id,relay.link_id,relay.enabled
FROM management_admin_relays AS relay
JOIN management_links AS link ON link.id=relay.link_id
WHERE relay.id=?`, input.RelayID).Scan(&vpsID, &linkID, &relayEnabled); errors.Is(err, sql.ErrNoRows) {
		return AdminTunnel{}, store.ErrNotFound
	} else if err != nil || relayEnabled != 1 {
		return AdminTunnel{}, errors.New("enabled administrator relay is required")
	}
	var peerID, peerPublicKey string
	if err := tx.QueryRowContext(ctx, `
SELECT peer.id,peer.public_key
FROM management_admin_vps_peers AS peer
JOIN management_admins AS admin ON admin.id=peer.admin_id
WHERE peer.admin_id=? AND peer.vps_id=? AND peer.state!='REVOKED'
  AND admin.enabled=1 AND admin.state='ACTIVE'`, input.AdminID, vpsID).Scan(&peerID, &peerPublicKey); errors.Is(err, sql.ErrNoRows) {
		return AdminTunnel{}, errors.New("administrator has no active peer identity on relay VPS")
	} else if err != nil {
		return AdminTunnel{}, err
	} else if peerPublicKey != input.PublicKey {
		return AdminTunnel{}, errors.New("inner administrator key does not match the paired VPS inventory")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO management_admin_tunnels(
 id,admin_id,relay_id,public_key,assigned_address,state,desired_generation,applied_generation,
 latest_handshake_at,rx_bytes,tx_bytes,last_error_code,created_at,updated_at
) VALUES(?,?,?,?,?,'CONFIGURED',1,0,NULL,0,0,'',?,?)`, input.ID, input.AdminID,
		input.RelayID, input.PublicKey, input.AssignedAddress, stamp, stamp); err != nil {
		return AdminTunnel{}, fmt.Errorf("create administrator inner tunnel: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_vps_peers
SET trust_mode='END_TO_END_RELAY',desired_generation=desired_generation+1,state='CONFIGURED',updated_at=?
WHERE id=?`, stamp, peerID); err != nil {
		return AdminTunnel{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE management_links
SET desired_route_generation=desired_route_generation+1,desired_acl_generation=desired_acl_generation+1,updated_at=?
WHERE id=?`, stamp, linkID); err != nil {
		return AdminTunnel{}, err
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return AdminTunnel{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminTunnel{}, err
	}
	return repository.GetAdminTunnel(ctx, input.ID)
}

func (repository *Repository) GetAdminTunnel(ctx context.Context, id string) (AdminTunnel, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return AdminTunnel{}, store.ErrNotFound
	}
	return scanAdminTunnel(repository.Database.QueryRowContext(ctx, adminTunnelSelect+" WHERE id=?", id))
}

func (repository *Repository) ListAdminTunnels(ctx context.Context) ([]AdminTunnel, error) {
	if repository == nil || repository.Database == nil {
		return nil, errors.New("management database is required")
	}
	rows, err := repository.Database.QueryContext(ctx, adminTunnelSelect+" ORDER BY id LIMIT ?", maximumAdminRelays*4)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AdminTunnel, 0)
	for rows.Next() {
		item, err := scanAdminTunnel(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository *Repository) RevokeAdminTunnel(ctx context.Context, id string) (AdminTunnel, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return AdminTunnel{}, store.ErrNotFound
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminTunnel{}, err
	}
	defer tx.Rollback()
	var linkID string
	if err := tx.QueryRowContext(ctx, `
SELECT relay.link_id FROM management_admin_tunnels AS tunnel
JOIN management_admin_relays AS relay ON relay.id=tunnel.relay_id
WHERE tunnel.id=?`, id).Scan(&linkID); errors.Is(err, sql.ErrNoRows) {
		return AdminTunnel{}, store.ErrNotFound
	} else if err != nil {
		return AdminTunnel{}, err
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
UPDATE management_admin_tunnels
SET state='REVOKED',desired_generation=desired_generation+1,last_error_code='REVOKED_BY_ADMIN',updated_at=?
WHERE id=? AND state!='REVOKED'`, stamp, id); err != nil {
		return AdminTunnel{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_links SET desired_acl_generation=desired_acl_generation+1,updated_at=? WHERE id=?`, stamp, linkID); err != nil {
		return AdminTunnel{}, err
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return AdminTunnel{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminTunnel{}, err
	}
	return repository.GetAdminTunnel(ctx, id)
}

func (repository *Repository) DeleteAdminTunnel(ctx context.Context, id string) error {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return store.ErrNotFound
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM management_admin_tunnels WHERE id=? AND state='REVOKED'", id)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("administrator inner tunnel must be revoked before deletion")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) SetAdminTrustMode(ctx context.Context, adminID, vpsID, trustMode string) error {
	adminID, vpsID, trustMode = strings.TrimSpace(adminID), strings.TrimSpace(vpsID), strings.ToUpper(strings.TrimSpace(trustMode))
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(adminID) || !safeIdentifier.MatchString(vpsID) ||
		trustMode != TrustRoutedHub && trustMode != TrustEndToEndRelay {
		return errors.New("valid administrator trust-mode change is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var peerID, current string
	if err := tx.QueryRowContext(ctx, `SELECT id,trust_mode FROM management_admin_vps_peers WHERE admin_id=? AND vps_id=? AND state!='REVOKED'`, adminID, vpsID).Scan(&peerID, &current); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if current == trustMode {
		return tx.Commit()
	}
	var tunnels int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM management_admin_tunnels AS tunnel
JOIN management_admin_relays AS relay ON relay.id=tunnel.relay_id
JOIN management_links AS link ON link.id=relay.link_id
WHERE tunnel.admin_id=? AND link.vps_id=? AND tunnel.state!='REVOKED'`, adminID, vpsID).Scan(&tunnels); err != nil {
		return err
	}
	if trustMode == TrustEndToEndRelay && tunnels == 0 {
		return errors.New("END_TO_END_RELAY requires an active authenticated inner tunnel")
	}
	if trustMode == TrustRoutedHub && tunnels != 0 {
		return errors.New("revoke active inner tunnels before selecting ROUTED_HUB")
	}
	stamp := repository.now().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE management_admin_vps_peers SET trust_mode=?,desired_generation=desired_generation+1,state='CONFIGURED',updated_at=? WHERE id=?`, trustMode, stamp, peerID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_links SET desired_route_generation=desired_route_generation+1,desired_acl_generation=desired_acl_generation+1,updated_at=? WHERE vps_id=? AND state!='REVOKED'`, stamp, vpsID); err != nil {
		return err
	}
	if err := advanceGeneration(ctx, tx, stamp); err != nil {
		return err
	}
	return tx.Commit()
}

func normalizeAdminRelayInput(input AdminRelayInput) AdminRelayInput {
	input.ID, input.LinkID = strings.TrimSpace(input.ID), strings.TrimSpace(input.LinkID)
	input.PublicEndpointHost = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input.PublicEndpointHost), "."))
	input.PublicBindAddress = strings.TrimSpace(input.PublicBindAddress)
	if input.RateLimitPerSecond == 0 {
		input.RateLimitPerSecond = 100
	}
	if input.BurstPackets == 0 {
		input.BurstPackets = 200
	}
	return input
}

func validateAdminRelayInput(input AdminRelayInput) error {
	bind, err := netip.ParseAddr(input.PublicBindAddress)
	if !safeIdentifier.MatchString(input.ID) || !safeIdentifier.MatchString(input.LinkID) || !validEndpointHost(input.PublicEndpointHost) ||
		err != nil || !bind.Is4() || !bind.IsGlobalUnicast() || bind.IsUnspecified() || bind.IsLoopback() || bind.IsLinkLocalUnicast() || bind.String() != input.PublicBindAddress ||
		input.PublicUDPPort < 1 || input.PublicUDPPort > 65535 || input.RateLimitPerSecond < 1 || input.RateLimitPerSecond > 10000 ||
		input.BurstPackets < 1 || input.BurstPackets > 10000 {
		return errors.New("valid bounded administrator relay is required")
	}
	return nil
}

func validateAdminRelayReferences(ctx context.Context, tx *sql.Tx, input AdminRelayInput) error {
	var contourEnabled int
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM management_admin_contour WHERE singleton_id=1").Scan(&contourEnabled); err != nil || input.Enabled && contourEnabled != 1 {
		return errors.New("enabled administrator contour is required for an enabled relay")
	}
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM management_links WHERE id=?", input.LinkID).Scan(&state); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	} else if state == "REVOKED" {
		return errors.New("administrator relay management link is revoked")
	}
	var endpointConflict int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_link_endpoints WHERE link_id=? AND endpoint_port=?", input.LinkID, input.PublicUDPPort).Scan(&endpointConflict); err != nil || endpointConflict != 0 {
		return errors.New("administrator relay public UDP port conflicts with the management endpoint")
	}
	return nil
}

const adminContourSelect = `
SELECT enabled,interface_name,private_key_secret_ref,public_key,subnet,gateway_address,
       listen_port,desired_generation,applied_generation,state,last_error_code,created_at,updated_at
FROM management_admin_contour`

const adminRelaySelect = `
SELECT id,link_id,enabled,public_endpoint_host,public_bind_address,public_udp_port,
       destination_port,rate_limit_per_second,burst_packets,desired_generation,
       applied_generation,state,last_error_code,created_at,updated_at
FROM management_admin_relays`

func scanAdminRelay(scanner rowScanner) (AdminRelay, error) {
	var item AdminRelay
	var enabled int
	if err := scanner.Scan(&item.ID, &item.LinkID, &enabled, &item.PublicEndpointHost,
		&item.PublicBindAddress, &item.PublicUDPPort, &item.DestinationPort,
		&item.RateLimitPerSecond, &item.BurstPackets, &item.DesiredGeneration,
		&item.AppliedGeneration, &item.State, &item.LastErrorCode,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AdminRelay{}, store.ErrNotFound
		}
		return AdminRelay{}, err
	}
	item.Enabled = enabled != 0
	return item, nil
}

const adminTunnelSelect = `
SELECT id,admin_id,relay_id,public_key,assigned_address,state,desired_generation,
       applied_generation,COALESCE(latest_handshake_at,''),rx_bytes,tx_bytes,last_error_code,
       created_at,updated_at
FROM management_admin_tunnels`

func scanAdminTunnel(scanner rowScanner) (AdminTunnel, error) {
	var item AdminTunnel
	if err := scanner.Scan(&item.ID, &item.AdminID, &item.RelayID, &item.PublicKey,
		&item.AssignedAddress, &item.State, &item.DesiredGeneration, &item.AppliedGeneration,
		&item.LatestHandshakeAt, &item.RXBytes, &item.TXBytes, &item.LastErrorCode,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AdminTunnel{}, store.ErrNotFound
		}
		return AdminTunnel{}, err
	}
	return item, nil
}
