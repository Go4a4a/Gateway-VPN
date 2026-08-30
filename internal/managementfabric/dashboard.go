package managementfabric

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type Dashboard struct {
	DesiredGeneration int64                  `json:"desired_generation"`
	AppliedGeneration int64                  `json:"applied_generation"`
	ApplyState        string                 `json:"apply_state"`
	LastErrorCode     string                 `json:"last_error_code,omitempty"`
	VPS               []DashboardVPS         `json:"vps"`
	Links             []DashboardLink        `json:"links"`
	Admins            []DashboardAdmin       `json:"admins"`
	Resources         []DashboardResource    `json:"resources"`
	Publications      []DashboardPublication `json:"publications"`
	ACL               []DashboardACL         `json:"acl"`
}

type DashboardVPS struct {
	ID                   string `json:"id"`
	Number               int64  `json:"number"`
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	Priority             int64  `json:"priority"`
	VerifiedFingerprint  string `json:"verified_fingerprint"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	AdminAddressPool     string `json:"admin_address_pool"`
	ResourceAliasPool    string `json:"resource_alias_pool"`
	State                string `json:"state"`
}

type DashboardLink struct {
	ID                     string     `json:"id"`
	VPSID                  string     `json:"vps_id"`
	Slot                   int64      `json:"slot"`
	InterfaceName          string     `json:"interface_name"`
	Enabled                bool       `json:"enabled"`
	ManagementSubnet       string     `json:"management_subnet"`
	LocalAddress           string     `json:"local_address"`
	RemoteAddress          string     `json:"remote_address"`
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
	LocalKeyFingerprint    string     `json:"local_key_fingerprint"`
	RemoteKeyFingerprint   string     `json:"remote_key_fingerprint"`
	Endpoints              []Endpoint `json:"endpoints"`
}

type DashboardAdmin struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Kind                 string `json:"kind"`
	Enabled              bool   `json:"enabled"`
	State                string `json:"state"`
	VPSID                string `json:"vps_id,omitempty"`
	AssignedAddress      string `json:"assigned_address,omitempty"`
	PeerState            string `json:"peer_state,omitempty"`
	PublicKeyFingerprint string `json:"public_key_fingerprint,omitempty"`
	DesiredGeneration    int64  `json:"desired_generation,omitempty"`
	AppliedGeneration    int64  `json:"applied_generation,omitempty"`
}

type DashboardResource struct {
	ID                        string          `json:"id"`
	Name                      string          `json:"name"`
	Kind                      string          `json:"kind"`
	AccessProfile             string          `json:"access_profile"`
	LocalDestination          string          `json:"local_destination"`
	Enabled                   bool            `json:"enabled"`
	AdvancedScopeAcknowledged bool            `json:"advanced_scope_acknowledged"`
	DesiredRouteGeneration    int64           `json:"desired_route_generation"`
	AppliedRouteGeneration    int64           `json:"applied_route_generation"`
	HealthState               string          `json:"health_state"`
	Ports                     []DashboardPort `json:"ports"`
}

type DashboardPort struct {
	Protocol  string `json:"protocol"`
	PortStart int    `json:"port_start"`
	PortEnd   int    `json:"port_end"`
}

type DashboardPublication struct {
	ID                     string `json:"id"`
	ResourceID             string `json:"resource_id"`
	LinkID                 string `json:"link_id"`
	PublishedAlias         string `json:"published_alias"`
	DesiredRouteGeneration int64  `json:"desired_route_generation"`
	AppliedRouteGeneration int64  `json:"applied_route_generation"`
	DesiredACLGeneration   int64  `json:"desired_acl_generation"`
	AppliedACLGeneration   int64  `json:"applied_acl_generation"`
	State                  string `json:"state"`
	LastErrorCode          string `json:"last_error_code,omitempty"`
}

type DashboardACL struct {
	ID         string `json:"id"`
	AdminID    string `json:"admin_id"`
	ResourceID string `json:"resource_id"`
	Protocol   string `json:"protocol"`
	PortStart  int    `json:"port_start"`
	PortEnd    int    `json:"port_end"`
	Enabled    bool   `json:"enabled"`
	Generation int64  `json:"generation"`
}

type UpdateVPSInput struct {
	Name    string
	Enabled bool
}

type UpdateLinkInput struct {
	Enabled             bool
	UplinkPolicy        string
	PinnedUplinkID      string
	PersistentKeepalive int
}

func (repository *Repository) Dashboard(ctx context.Context) (Dashboard, error) {
	if repository == nil || repository.Database == nil {
		return Dashboard{}, errors.New("management database is required")
	}
	var result Dashboard
	if err := repository.Database.QueryRowContext(ctx, `SELECT desired_generation,applied_generation,state,last_error_code FROM management_fabric_generations WHERE singleton_id=1`).Scan(&result.DesiredGeneration, &result.AppliedGeneration, &result.ApplyState, &result.LastErrorCode); err != nil {
		return Dashboard{}, fmt.Errorf("read management fabric generations: %w", err)
	}
	vpsItems, err := repository.ListVPS(ctx)
	if err != nil {
		return Dashboard{}, err
	}
	for _, item := range vpsItems {
		result.VPS = append(result.VPS, DashboardVPS{
			ID: item.ID, Number: item.DisplayNumber, Name: item.Name, Enabled: item.Enabled,
			Priority: item.Priority, VerifiedFingerprint: item.VerifiedFingerprint,
			PublicKeyFingerprint: keyFingerprint(item.PublicKey), AdminAddressPool: item.AdminAddressPool,
			ResourceAliasPool: item.ResourceAliasPool, State: item.State,
		})
	}
	linkItems, err := repository.ListLinks(ctx)
	if err != nil {
		return Dashboard{}, err
	}
	for _, item := range linkItems {
		result.Links = append(result.Links, DashboardLink{
			ID: item.ID, VPSID: item.VPSID, Slot: item.Slot, InterfaceName: item.InterfaceName,
			Enabled: item.Enabled, ManagementSubnet: item.ManagementSubnet, LocalAddress: item.LocalAddress,
			RemoteAddress: item.RemoteAddress, UplinkPolicy: item.UplinkPolicy, PinnedUplinkID: item.PinnedUplinkID,
			SelectedUplinkID: item.SelectedUplinkID, PersistentKeepalive: item.PersistentKeepalive,
			DesiredRouteGeneration: item.DesiredRouteGeneration, AppliedRouteGeneration: item.AppliedRouteGeneration,
			DesiredACLGeneration: item.DesiredACLGeneration, AppliedACLGeneration: item.AppliedACLGeneration,
			State: item.State, LastErrorCode: item.LastErrorCode, LastHandshakeAt: item.LastHandshakeAt,
			LocalKeyFingerprint: keyFingerprint(item.LocalPublicKey), RemoteKeyFingerprint: keyFingerprint(item.RemotePublicKey),
			Endpoints: append([]Endpoint(nil), item.Endpoints...),
		})
	}
	if err := repository.readDashboardAdmins(ctx, &result); err != nil {
		return Dashboard{}, err
	}
	if err := repository.readDashboardResources(ctx, &result); err != nil {
		return Dashboard{}, err
	}
	return result, nil
}

func (repository *Repository) readDashboardAdmins(ctx context.Context, result *Dashboard) error {
	rows, err := repository.Database.QueryContext(ctx, `
SELECT a.id,a.name,a.identity_kind,a.enabled,a.state,
       COALESCE(p.vps_id,''),COALESCE(p.assigned_address,''),COALESCE(p.state,''),
       COALESCE(p.public_key,''),COALESCE(p.desired_generation,0),COALESCE(p.applied_generation,0)
FROM management_admins AS a
LEFT JOIN management_admin_vps_peers AS p ON p.admin_id=a.id
ORDER BY a.name,a.id,p.vps_id`)
	if err != nil {
		return fmt.Errorf("list management administrators: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item DashboardAdmin
		var enabled int
		var publicKey string
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &enabled, &item.State, &item.VPSID, &item.AssignedAddress, &item.PeerState, &publicKey, &item.DesiredGeneration, &item.AppliedGeneration); err != nil {
			return fmt.Errorf("scan management administrator: %w", err)
		}
		item.Enabled = enabled != 0
		if publicKey != "" {
			item.PublicKeyFingerprint = keyFingerprint(publicKey)
		}
		result.Admins = append(result.Admins, item)
	}
	return rows.Err()
}

func (repository *Repository) readDashboardResources(ctx context.Context, result *Dashboard) error {
	rows, err := repository.Database.QueryContext(ctx, `
SELECT id,name,resource_kind,access_profile,local_destination,enabled,
       advanced_scope_acknowledged,desired_route_generation,applied_route_generation,health_state
FROM management_resources ORDER BY name,id`)
	if err != nil {
		return fmt.Errorf("list management resources: %w", err)
	}
	for rows.Next() {
		var item DashboardResource
		var enabled, acknowledged int
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.AccessProfile, &item.LocalDestination, &enabled, &acknowledged, &item.DesiredRouteGeneration, &item.AppliedRouteGeneration, &item.HealthState); err != nil {
			rows.Close()
			return fmt.Errorf("scan management resource: %w", err)
		}
		item.Enabled, item.AdvancedScopeAcknowledged = enabled != 0, acknowledged != 0
		result.Resources = append(result.Resources, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	ports, err := repository.Database.QueryContext(ctx, `SELECT resource_id,protocol,port_start,port_end FROM management_resource_ports ORDER BY resource_id,protocol,port_start,port_end`)
	if err != nil {
		return fmt.Errorf("list management resource ports: %w", err)
	}
	byResource := make(map[string]int, len(result.Resources))
	for index := range result.Resources {
		byResource[result.Resources[index].ID] = index
	}
	for ports.Next() {
		var resourceID string
		var item DashboardPort
		if err := ports.Scan(&resourceID, &item.Protocol, &item.PortStart, &item.PortEnd); err != nil {
			ports.Close()
			return err
		}
		if index, exists := byResource[resourceID]; exists {
			result.Resources[index].Ports = append(result.Resources[index].Ports, item)
		}
	}
	if err := ports.Close(); err != nil {
		return err
	}
	publicationRows, err := repository.Database.QueryContext(ctx, `
SELECT id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,
       desired_acl_generation,applied_acl_generation,state,last_error_code
FROM management_resource_publications ORDER BY resource_id,link_id,id`)
	if err != nil {
		return err
	}
	for publicationRows.Next() {
		var item DashboardPublication
		if err := publicationRows.Scan(&item.ID, &item.ResourceID, &item.LinkID, &item.PublishedAlias, &item.DesiredRouteGeneration, &item.AppliedRouteGeneration, &item.DesiredACLGeneration, &item.AppliedACLGeneration, &item.State, &item.LastErrorCode); err != nil {
			publicationRows.Close()
			return err
		}
		result.Publications = append(result.Publications, item)
	}
	if err := publicationRows.Close(); err != nil {
		return err
	}
	aclRows, err := repository.Database.QueryContext(ctx, `SELECT id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation FROM management_resource_acl ORDER BY admin_id,resource_id,id`)
	if err != nil {
		return err
	}
	defer aclRows.Close()
	for aclRows.Next() {
		var item DashboardACL
		var enabled int
		if err := aclRows.Scan(&item.ID, &item.AdminID, &item.ResourceID, &item.Protocol, &item.PortStart, &item.PortEnd, &enabled, &item.Generation); err != nil {
			return err
		}
		item.Enabled = enabled != 0
		result.ACL = append(result.ACL, item)
	}
	return aclRows.Err()
}

func (repository *Repository) UpdateVPS(ctx context.Context, id string, input UpdateVPSInput) (VPSNode, error) {
	name := strings.TrimSpace(input.Name)
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) || name == "" || len(name) > 128 {
		return VPSNode{}, errors.New("valid VPS update is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return VPSNode{}, err
	}
	defer tx.Rollback()
	var wasEnabled int
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT enabled,state FROM vps_nodes WHERE id=?", id).Scan(&wasEnabled, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VPSNode{}, store.ErrNotFound
		}
		return VPSNode{}, err
	}
	if state == "REVOKED" && input.Enabled {
		return VPSNode{}, errors.New("revoked VPS cannot be enabled")
	}
	priorityExpression := "priority"
	if wasEnabled == 0 && input.Enabled {
		priorityExpression = "(SELECT COALESCE(MAX(priority),0)+10 FROM vps_nodes WHERE enabled=1)"
	}
	now := repository.now().Format(time.RFC3339Nano)
	query := "UPDATE vps_nodes SET name=?,enabled=?,priority=" + priorityExpression + ",updated_at=? WHERE id=?"
	if _, err := tx.ExecContext(ctx, query, name, boolInt(input.Enabled), now, id); err != nil {
		return VPSNode{}, fmt.Errorf("update VPS: %w", err)
	}
	if wasEnabled != boolInt(input.Enabled) {
		if err := advanceGeneration(ctx, tx, now); err != nil {
			return VPSNode{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return VPSNode{}, err
	}
	return repository.GetVPS(ctx, id)
}

func (repository *Repository) ReorderVPS(ctx context.Context, orderedIDs []string) error {
	if repository == nil || repository.Database == nil || len(orderedIDs) == 0 {
		return errors.New("ordered enabled VPS ids are required")
	}
	seen := make(map[string]struct{}, len(orderedIDs))
	for _, id := range orderedIDs {
		if !safeIdentifier.MatchString(id) {
			return errors.New("ordered VPS id is invalid")
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("ordered VPS id is duplicated")
		}
		seen[id] = struct{}{}
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM vps_nodes WHERE enabled=1").Scan(&enabled); err != nil || enabled != len(orderedIDs) {
		return errors.New("reorder must contain every enabled VPS exactly once")
	}
	for _, id := range orderedIDs {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM vps_nodes WHERE id=? AND enabled=1", id).Scan(&exists); err != nil || exists != 1 {
			return errors.New("reorder contains an unavailable VPS")
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE vps_nodes SET priority=1000000000+display_number WHERE enabled=1"); err != nil {
		return err
	}
	now := repository.now().Format(time.RFC3339Nano)
	for index, id := range orderedIDs {
		if _, err := tx.ExecContext(ctx, "UPDATE vps_nodes SET priority=?,updated_at=? WHERE id=? AND enabled=1", int64(index+1)*10, now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (repository *Repository) UpdateLink(ctx context.Context, id string, input UpdateLinkInput) (Link, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) || input.PersistentKeepalive < 10 || input.PersistentKeepalive > 60 ||
		(input.UplinkPolicy != UplinkAuto && input.UplinkPolicy != UplinkPinnedWithFallback && input.UplinkPolicy != UplinkPinnedOnly) ||
		(input.UplinkPolicy == UplinkAuto && strings.TrimSpace(input.PinnedUplinkID) != "") ||
		(input.UplinkPolicy != UplinkAuto && !safeIdentifier.MatchString(input.PinnedUplinkID)) {
		return Link{}, errors.New("valid management link update is required")
	}
	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Link{}, err
	}
	defer tx.Rollback()
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM management_links WHERE id=?", id).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Link{}, store.ErrNotFound
		}
		return Link{}, err
	}
	if state == "REVOKED" {
		return Link{}, errors.New("revoked management link cannot be changed")
	}
	if input.PinnedUplinkID != "" {
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM uplinks WHERE id=? AND enabled=1", input.PinnedUplinkID).Scan(&exists); err != nil || exists != 1 {
			return Link{}, errors.New("pinned management uplink is unavailable")
		}
	}
	now := repository.now().Format(time.RFC3339Nano)
	nextState := "CONFIGURED"
	if !input.Enabled {
		nextState = "DISABLED"
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE management_links
SET enabled=?,uplink_policy=?,pinned_uplink_id=NULLIF(?,''),selected_uplink_id=NULL,
    persistent_keepalive=?,desired_route_generation=desired_route_generation+1,
    desired_acl_generation=desired_acl_generation+1,state=?,last_error_code='',updated_at=?
WHERE id=?`, boolInt(input.Enabled), input.UplinkPolicy, input.PinnedUplinkID, input.PersistentKeepalive, nextState, now, id); err != nil {
		return Link{}, fmt.Errorf("update management link: %w", err)
	}
	if err := advanceGeneration(ctx, tx, now); err != nil {
		return Link{}, err
	}
	if err := tx.Commit(); err != nil {
		return Link{}, err
	}
	return repository.GetLink(ctx, id)
}

func keyFingerprint(publicKey string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return hex.EncodeToString(digest[:])
}
