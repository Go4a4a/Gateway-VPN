package vpsagent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	maximumAdminRelays        = 256
	AdminRelayDestinationPort = 51822
)

type AdminRelayInput struct {
	ID                 string `json:"id,omitempty"`
	GatewayPeerID      string `json:"gateway_peer_id"`
	PublicEndpointHost string `json:"public_endpoint_host"`
	PublicBindAddress  string `json:"public_bind_address"`
	PublicUDPPort      int    `json:"public_udp_port"`
	DestinationPort    int    `json:"destination_port"`
	RateLimitPerSecond int    `json:"rate_limit_per_second"`
	BurstPackets       int    `json:"burst_packets"`
}

type AdminRelay struct {
	ID                 string `json:"id"`
	GatewayPeerID      string `json:"gateway_peer_id"`
	Enabled            bool   `json:"enabled"`
	PublicEndpointHost string `json:"public_endpoint_host"`
	PublicBindAddress  string `json:"public_bind_address"`
	PublicUDPPort      int    `json:"public_udp_port"`
	DestinationPort    int    `json:"destination_port"`
	RateLimitPerSecond int    `json:"rate_limit_per_second"`
	BurstPackets       int    `json:"burst_packets"`
	State              string `json:"state"`
	DesiredGeneration  int64  `json:"desired_generation"`
	AppliedGeneration  int64  `json:"applied_generation"`
	StatusReason       string `json:"status_reason"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

func (repository HubRepository) CreateAdminRelay(ctx context.Context, input AdminRelayInput) (AdminRelay, error) {
	if repository.Database == nil {
		return AdminRelay{}, errors.New("VPS Hub database is required")
	}
	input.GatewayPeerID = strings.TrimSpace(input.GatewayPeerID)
	input.PublicEndpointHost = canonicalRelayHost(input.PublicEndpointHost)
	bind, bindErr := netip.ParseAddr(strings.TrimSpace(input.PublicBindAddress))
	if input.DestinationPort == 0 {
		input.DestinationPort = AdminRelayDestinationPort
	}
	if input.RateLimitPerSecond == 0 {
		input.RateLimitPerSecond = 100
	}
	if input.BurstPackets == 0 {
		input.BurstPackets = 200
	}
	if !hubIdentifierPattern.MatchString(input.GatewayPeerID) || !validRelayHost(input.PublicEndpointHost) ||
		bindErr != nil || !bind.Is4() || !bind.IsGlobalUnicast() || bind.IsUnspecified() || bind.IsLoopback() || bind.IsLinkLocalUnicast() || bind.String() != strings.TrimSpace(input.PublicBindAddress) ||
		input.PublicUDPPort < 1 || input.PublicUDPPort > 65535 || input.PublicUDPPort == VPSManagementPort ||
		input.DestinationPort != AdminRelayDestinationPort || input.RateLimitPerSecond < 1 || input.RateLimitPerSecond > 10000 ||
		input.BurstPackets < 1 || input.BurstPackets > 10000 {
		return AdminRelay{}, errors.New("valid bounded administrator relay is required")
	}
	id := strings.TrimSpace(input.ID)
	if id == "" {
		var err error
		id, err = repository.randomID("relay-", 16)
		if err != nil {
			return AdminRelay{}, err
		}
	} else if !hubIdentifierPattern.MatchString(id) {
		return AdminRelay{}, errors.New("administrator relay id is invalid")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminRelay{}, err
	}
	defer transaction.Rollback()
	if err := enforceCount(ctx, transaction, "admin_relays", maximumAdminRelays); err != nil {
		return AdminRelay{}, err
	}
	var gatewayAddress, vpsAddress, state string
	if err := transaction.QueryRowContext(ctx, `SELECT assigned_address,remote_address,state FROM gateway_peers WHERE id=?`, input.GatewayPeerID).Scan(&gatewayAddress, &vpsAddress, &state); errors.Is(err, sql.ErrNoRows) {
		return AdminRelay{}, ErrHubNotFound
	} else if err != nil {
		return AdminRelay{}, err
	} else if state == "REVOKED" {
		return AdminRelay{}, errors.New("administrator relay Gateway is revoked")
	}
	if _, err := canonicalPrivateAddress(gatewayAddress); err != nil {
		return AdminRelay{}, errors.New("administrator relay Gateway destination is invalid")
	}
	if _, err := canonicalPrivateAddress(vpsAddress); err != nil {
		return AdminRelay{}, errors.New("administrator relay VPS source is invalid")
	}
	stamp := formatTime(repository.now())
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO admin_relays(
 id,gateway_peer_id,enabled,public_endpoint_host,public_bind_address,public_udp_port,
 destination_port,rate_limit_per_second,burst_packets,state,desired_generation,
 applied_generation,status_reason,created_at,updated_at
) VALUES(?,?,1,?,?,?,?,?,?,'CONFIGURED',1,0,'AWAITING_HOST_APPLY',?,?)`,
		id, input.GatewayPeerID, input.PublicEndpointHost, bind.String(), input.PublicUDPPort,
		input.DestinationPort, input.RateLimitPerSecond, input.BurstPackets, stamp, stamp); err != nil {
		return AdminRelay{}, fmt.Errorf("create administrator relay: %w", err)
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return AdminRelay{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AdminRelay{}, err
	}
	return repository.GetAdminRelay(ctx, id)
}

func (repository HubRepository) GetAdminRelay(ctx context.Context, id string) (AdminRelay, error) {
	if repository.Database == nil || !hubIdentifierPattern.MatchString(strings.TrimSpace(id)) {
		return AdminRelay{}, ErrHubNotFound
	}
	item, err := scanAdminRelay(repository.Database.QueryRowContext(ctx, adminRelaySelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return AdminRelay{}, ErrHubNotFound
	}
	return item, err
}

func (repository HubRepository) ListAdminRelays(ctx context.Context) ([]AdminRelay, error) {
	if repository.Database == nil {
		return nil, errors.New("VPS Hub database is required")
	}
	rows, err := repository.Database.QueryContext(ctx, adminRelaySelect+" ORDER BY created_at,id LIMIT ?", maximumAdminRelays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AdminRelay{}
	for rows.Next() {
		item, err := scanAdminRelay(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository HubRepository) SetAdminTrustMode(ctx context.Context, id, trustMode string) error {
	trustMode = strings.ToUpper(strings.TrimSpace(trustMode))
	if repository.Database == nil || !hubIdentifierPattern.MatchString(strings.TrimSpace(id)) || trustMode != TrustRoutedHub && trustMode != TrustEndToEndRelay {
		return errors.New("valid administrator and trust mode are required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := formatTime(repository.now())
	if trustMode == TrustEndToEndRelay {
		var keyMode string
		if err := transaction.QueryRowContext(ctx, "SELECT key_mode FROM admin_peers WHERE id=? AND state!='REVOKED'", id).Scan(&keyMode); errors.Is(err, sql.ErrNoRows) {
			return ErrHubNotFound
		} else if err != nil {
			return err
		} else if keyMode == "MANAGED" {
			return errors.New("managed VPS private key cannot be used for end-to-end relay")
		}
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE admin_peers
SET trust_mode=?,desired_generation=desired_generation+1,status_reason='AWAITING_HOST_APPLY',updated_at=?
WHERE id=? AND state!='REVOKED' AND trust_mode<>?`, trustMode, stamp, id, trustMode)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var existing string
		if err := transaction.QueryRowContext(ctx, "SELECT trust_mode FROM admin_peers WHERE id=? AND state!='REVOKED'", id).Scan(&existing); errors.Is(err, sql.ErrNoRows) {
			return ErrHubNotFound
		} else if err != nil {
			return err
		}
		return nil
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) DisableAdminRelay(ctx context.Context, id string) error {
	return repository.SetAdminRelayEnabled(ctx, id, false)
}

func (repository HubRepository) SetAdminRelayEnabled(ctx context.Context, id string, enabled bool) error {
	if repository.Database == nil || !hubIdentifierPattern.MatchString(strings.TrimSpace(id)) {
		return ErrHubNotFound
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := formatTime(repository.now())
	state, reason := "DISABLED", "DISABLED_BY_ADMIN"
	if enabled {
		state, reason = "CONFIGURED", "AWAITING_HOST_APPLY"
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE admin_relays
SET enabled=?,state=?,desired_generation=desired_generation+1,status_reason=?,updated_at=?
WHERE id=? AND enabled<>?`, boolInt(enabled), state, reason, stamp, id, boolInt(enabled))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var exists int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_relays WHERE id=?", id).Scan(&exists); err != nil || exists == 0 {
			return ErrHubNotFound
		}
		return nil
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) DeleteAdminRelay(ctx context.Context, id string) error {
	if repository.Database == nil || !hubIdentifierPattern.MatchString(strings.TrimSpace(id)) {
		return ErrHubNotFound
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var enabled int
	if err := transaction.QueryRowContext(ctx, "SELECT enabled FROM admin_relays WHERE id=?", id).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return ErrHubNotFound
	} else if err != nil {
		return err
	} else if enabled != 0 {
		return errors.New("administrator relay must be disabled before deletion")
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM admin_relays WHERE id=?", id); err != nil {
		return err
	}
	stamp := formatTime(repository.now())
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return err
	}
	return transaction.Commit()
}

const adminRelaySelect = `
SELECT id,gateway_peer_id,enabled,public_endpoint_host,public_bind_address,public_udp_port,
       destination_port,rate_limit_per_second,burst_packets,state,desired_generation,
       applied_generation,status_reason,created_at,updated_at
FROM admin_relays`

func scanAdminRelay(scanner interface{ Scan(...any) error }) (AdminRelay, error) {
	var item AdminRelay
	var enabled int
	err := scanner.Scan(&item.ID, &item.GatewayPeerID, &enabled, &item.PublicEndpointHost,
		&item.PublicBindAddress, &item.PublicUDPPort, &item.DestinationPort,
		&item.RateLimitPerSecond, &item.BurstPackets, &item.State,
		&item.DesiredGeneration, &item.AppliedGeneration, &item.StatusReason,
		&item.CreatedAt, &item.UpdatedAt)
	item.Enabled = enabled == 1
	return item, err
}

func canonicalRelayHost(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func validRelayHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Is4() && address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
	}
	return len(value) <= 253 && hostnamePattern.MatchString(value) && strings.Contains(value, ".")
}
