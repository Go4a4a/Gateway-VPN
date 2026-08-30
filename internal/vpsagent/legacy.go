package vpsagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/wgingress"
)

const (
	LegacyGatewayPeerID = "gateway-legacy"
	LegacyAdminPeerID   = "admin-legacy"
)

// LegacyAdoptionInput describes only the fixed single-link topology created by
// the original signed VPS installer. It is not a general peer import surface.
type LegacyAdoptionInput struct {
	GatewayPublicKey string
	AdminPublicKey   string
	Endpoint         string
	GatewayName      string
	AdminName        string
}

type LegacyAdoptionResult struct {
	Adopted bool   `json:"adopted"`
	Reason  string `json:"reason"`
	SiteID  string `json:"site_id,omitempty"`
}

// AdoptLegacyInstallerPeers imports the exact legacy wg-mgmt contract into an
// otherwise empty Hub database. Existing non-empty topology is left untouched
// so an upgrade can never overwrite newer user-managed peers.
func (repository HubRepository) AdoptLegacyInstallerPeers(ctx context.Context, input LegacyAdoptionInput) (LegacyAdoptionResult, error) {
	if repository.Database == nil {
		return LegacyAdoptionResult{}, errors.New("VPS Hub database is required")
	}
	input.GatewayPublicKey = strings.TrimSpace(input.GatewayPublicKey)
	input.AdminPublicKey = strings.TrimSpace(input.AdminPublicKey)
	input.GatewayName = strings.TrimSpace(input.GatewayName)
	input.AdminName = strings.TrimSpace(input.AdminName)
	endpoint, err := canonicalEndpoint(input.Endpoint)
	if err != nil || !wgingress.ValidKey(input.GatewayPublicKey) || !wgingress.ValidKey(input.AdminPublicKey) || input.GatewayPublicKey == input.AdminPublicKey {
		return LegacyAdoptionResult{}, errors.New("exact legacy WireGuard public keys and endpoint are required")
	}
	if input.GatewayName == "" {
		input.GatewayName = "Legacy Gateway"
	}
	if input.AdminName == "" {
		input.AdminName = "Legacy administrator"
	}
	if len(input.GatewayName) > 128 || len(input.AdminName) > 128 {
		return LegacyAdoptionResult{}, errors.New("legacy peer display name is too long")
	}
	digest := sha256.Sum256([]byte(input.GatewayPublicKey))
	siteID := "site-legacy-" + hex.EncodeToString(digest[:8])

	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return LegacyAdoptionResult{}, err
	}
	defer transaction.Rollback()
	counts := make([]int64, 6)
	for index, table := range []string{"gateway_peers", "admin_peers", "resource_publications", "acl_grants", "pairing_invitations", "prefix_allocations"} {
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&counts[index]); err != nil {
			return LegacyAdoptionResult{}, err
		}
	}
	if counts[0] != 0 || counts[1] != 0 || counts[2] != 0 || counts[3] != 0 || counts[4] != 0 || counts[5] != 0 {
		return LegacyAdoptionResult{Adopted: false, Reason: "TOPOLOGY_ALREADY_CONFIGURED"}, nil
	}
	stamp := formatTime(repository.now())
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO gateway_peers(
 id,site_id,display_name,public_key,assigned_subnet,assigned_address,remote_address,
 state,desired_generation,applied_generation,created_at,updated_at,endpoint,webui_url,status_reason
) VALUES(?,?,?,?,?,?,?,'PAIRING',1,1,?,?,?,?,?)`, LegacyGatewayPeerID, siteID, input.GatewayName, input.GatewayPublicKey,
		"10.80.0.0/24", "10.80.0.2", "10.80.0.1", stamp, stamp, endpoint, "", "LEGACY_HOST_APPLIED_AWAITING_HANDSHAKE"); err != nil {
		return LegacyAdoptionResult{}, fmt.Errorf("adopt legacy Gateway peer: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO admin_peers(
 id,name,public_key,private_key_secret_ref,assigned_address,state,desired_generation,applied_generation,
 created_at,updated_at,key_mode,status_reason,config_state
) VALUES(?,?,?,NULL,'10.80.0.10','CONFIGURED',1,1,?,?,'EXTERNAL','LEGACY_HOST_APPLIED','NOT_APPLICABLE')`, LegacyAdminPeerID, input.AdminName, input.AdminPublicKey, stamp, stamp); err != nil {
		return LegacyAdoptionResult{}, fmt.Errorf("adopt legacy administrator peer: %w", err)
	}
	for _, allocation := range []struct {
		id, kind, owner, prefix string
	}{
		{"prefix-legacy-gateway", "GATEWAY_LINK", LegacyGatewayPeerID, "10.80.0.0/24"},
		{"prefix-legacy-admin", "ADMIN_PEER", LegacyAdminPeerID, "10.80.0.10/32"},
	} {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO prefix_allocations(id,owner_kind,owner_id,prefix,state,created_at,updated_at)
VALUES(?,?,?,?,'ALLOCATED',?,?)`, allocation.id, allocation.kind, allocation.owner, allocation.prefix, stamp, stamp); err != nil {
			return LegacyAdoptionResult{}, fmt.Errorf("adopt legacy prefix: %w", err)
		}
	}
	settings, _ := json.Marshal(map[string]any{"desired_generation": 1, "applied_generation": 1, "state": "APPLIED"})
	if _, err := transaction.ExecContext(ctx, "UPDATE vps_settings SET value_json=?,updated_at=? WHERE key='fabric'", string(settings), stamp); err != nil {
		return LegacyAdoptionResult{}, err
	}
	if err := transaction.Commit(); err != nil {
		return LegacyAdoptionResult{}, err
	}
	return LegacyAdoptionResult{Adopted: true, Reason: "LEGACY_INSTALLER_CONTRACT_ADOPTED", SiteID: siteID}, nil
}

// MarkHostPlanApplied advances only database acknowledgement. The caller must
// already have verified and durably committed the exact host projection.
func (repository HubRepository) MarkHostPlanApplied(ctx context.Context, generation int64, appliedAt time.Time) error {
	if repository.Database == nil || generation < 1 {
		return errors.New("valid VPS host-plan generation is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var raw string
	if err := transaction.QueryRowContext(ctx, "SELECT value_json FROM vps_settings WHERE key='fabric'").Scan(&raw); err != nil {
		return err
	}
	var current struct {
		Desired int64 `json:"desired_generation"`
		Applied int64 `json:"applied_generation"`
	}
	if json.Unmarshal([]byte(raw), &current) != nil || current.Desired < 1 || current.Applied < 0 || current.Applied > current.Desired || generation != current.Desired {
		return errors.New("VPS fabric generation changed during host apply")
	}
	state := "APPLIED"
	stamp := formatTime(appliedAt.UTC())
	encoded, _ := json.Marshal(map[string]any{"desired_generation": current.Desired, "applied_generation": generation, "state": state})
	if _, err := transaction.ExecContext(ctx, "UPDATE vps_settings SET value_json=?,updated_at=? WHERE key='fabric'", string(encoded), stamp); err != nil {
		return err
	}
	for _, table := range []string{"gateway_peers", "admin_peers", "resource_publications"} {
		if _, err := transaction.ExecContext(ctx, "UPDATE "+table+" SET applied_generation=desired_generation,updated_at=?", stamp); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// RestoreHostPlanAppliedGeneration is used only after the root reconciler has
// restored the previous persistent and runtime projection. Desired generation
// is intentionally preserved so the failed change remains pending.
func (repository HubRepository) RestoreHostPlanAppliedGeneration(ctx context.Context, generation int64, restoredAt time.Time) error {
	if repository.Database == nil || generation < 0 {
		return errors.New("valid previous VPS host-plan generation is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var raw string
	if err := transaction.QueryRowContext(ctx, "SELECT value_json FROM vps_settings WHERE key='fabric'").Scan(&raw); err != nil {
		return err
	}
	var current struct {
		Desired int64 `json:"desired_generation"`
	}
	if json.Unmarshal([]byte(raw), &current) != nil || current.Desired < 1 || generation > current.Desired {
		return errors.New("previous VPS fabric generation is incompatible with desired state")
	}
	stamp := formatTime(restoredAt.UTC())
	encoded, _ := json.Marshal(map[string]any{"desired_generation": current.Desired, "applied_generation": generation, "state": "PENDING"})
	if _, err := transaction.ExecContext(ctx, "UPDATE vps_settings SET value_json=?,updated_at=? WHERE key='fabric'", string(encoded), stamp); err != nil {
		return err
	}
	for _, table := range []string{"gateway_peers", "admin_peers", "resource_publications"} {
		if _, err := transaction.ExecContext(ctx, "UPDATE "+table+" SET applied_generation=CASE WHEN desired_generation<? THEN desired_generation ELSE ? END,updated_at=?", generation, generation, stamp); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// FabricGenerations returns the durable desired/applied pair without exposing
// arbitrary settings values to the privileged caller.
func (repository HubRepository) FabricGenerations(ctx context.Context) (int64, int64, error) {
	if repository.Database == nil {
		return 0, 0, errors.New("VPS Hub database is required")
	}
	var raw string
	if err := repository.Database.QueryRowContext(ctx, "SELECT value_json FROM vps_settings WHERE key='fabric'").Scan(&raw); err != nil {
		return 0, 0, err
	}
	var current struct {
		Desired int64 `json:"desired_generation"`
		Applied int64 `json:"applied_generation"`
	}
	if json.Unmarshal([]byte(raw), &current) != nil || current.Desired < 1 || current.Applied < 0 || current.Applied > current.Desired {
		return 0, 0, errors.New("VPS fabric generation settings are invalid")
	}
	return current.Desired, current.Applied, nil
}
