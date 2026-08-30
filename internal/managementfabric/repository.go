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
)

func NewRepository(database *sql.DB, reserved []ReservedPrefix) *Repository {
	return &Repository{Database: database, ReservedPrefixes: append([]ReservedPrefix(nil), reserved...), Now: time.Now}
}

func (repository *Repository) EnsureLocalSite(ctx context.Context, id, displayName string) (Site, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return Site{}, errors.New("management database and safe local site id are required")
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 128 {
		return Site{}, errors.New("local site display name is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Site{}, fmt.Errorf("begin local site transaction: %w", err)
	}
	defer transaction.Rollback()

	var existingID string
	err = transaction.QueryRowContext(ctx, "SELECT id FROM management_sites WHERE is_local=1").Scan(&existingID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Site{}, fmt.Errorf("inspect local management site: %w", err)
	}
	now := repository.now().Format(time.RFC3339Nano)
	switch {
	case err == nil && existingID != id:
		return Site{}, errors.New("a different immutable local site identity already exists")
	case err == nil:
		if _, err := transaction.ExecContext(ctx, "UPDATE management_sites SET display_name=?, updated_at=? WHERE id=? AND is_local=1", displayName, now, id); err != nil {
			return Site{}, fmt.Errorf("update local management site name: %w", err)
		}
	default:
		var occupied int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_sites WHERE id=?", id).Scan(&occupied); err != nil {
			return Site{}, fmt.Errorf("inspect management site id: %w", err)
		}
		if occupied != 0 {
			return Site{}, errors.New("site id already belongs to a non-local identity")
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO management_sites(id, display_name, is_local, identity_state, created_at, updated_at)
VALUES (?, ?, 1, 'ACTIVE', ?, ?)`, id, displayName, now, now); err != nil {
			return Site{}, fmt.Errorf("create local management site: %w", err)
		}
		if err := advanceGeneration(ctx, transaction, now); err != nil {
			return Site{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return Site{}, fmt.Errorf("commit local management site: %w", err)
	}
	return repository.GetSite(ctx, id)
}

func (repository *Repository) GetSite(ctx context.Context, id string) (Site, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return Site{}, store.ErrNotFound
	}
	var item Site
	var local int
	err := repository.Database.QueryRowContext(ctx, `
SELECT id, display_name, is_local, identity_state, created_at, updated_at
FROM management_sites WHERE id=?`, id).Scan(
		&item.ID, &item.DisplayName, &local, &item.IdentityState, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Site{}, store.ErrNotFound
	}
	if err != nil {
		return Site{}, fmt.Errorf("read management site: %w", err)
	}
	item.Local = local != 0
	return item, nil
}

func (repository *Repository) CreateVPS(ctx context.Context, input CreateVPSInput) (VPSNode, error) {
	if repository == nil || repository.Database == nil {
		return VPSNode{}, errors.New("management database is required")
	}
	if err := ValidateVPSInput(input); err != nil {
		return VPSNode{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return VPSNode{}, fmt.Errorf("begin VPS create: %w", err)
	}
	defer transaction.Rollback()
	if err := repository.rejectPrefixCollisionsTx(ctx, transaction, []namedPrefix{
		{owner: "new-vps-admin:" + input.ID, prefix: mustPrivatePrefix(input.AdminAddressPool, 16, 30)},
		{owner: "new-vps-alias:" + input.ID, prefix: mustPrivatePrefix(input.ResourceAliasPool, 8, 30)},
	}, ""); err != nil {
		return VPSNode{}, err
	}
	number, err := allocateVPSNumber(ctx, transaction)
	if err != nil {
		return VPSNode{}, err
	}
	priority := number * 10
	now := repository.now().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
INSERT INTO vps_nodes(
    id, display_number, name, enabled, priority, verified_fingerprint, public_key,
    admin_address_pool, resource_alias_pool, state, created_at, updated_at
) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 'CONFIGURED', ?, ?)`,
		input.ID, number, strings.TrimSpace(input.Name), priority,
		strings.ToLower(strings.TrimSpace(input.VerifiedFingerprint)), strings.TrimSpace(input.PublicKey),
		input.AdminAddressPool, input.ResourceAliasPool, now, now)
	if err != nil {
		return VPSNode{}, fmt.Errorf("store VPS identity (duplicate id, fingerprint, key, or priority): %w", err)
	}
	if err := advanceGeneration(ctx, transaction, now); err != nil {
		return VPSNode{}, err
	}
	if err := transaction.Commit(); err != nil {
		return VPSNode{}, fmt.Errorf("commit VPS create: %w", err)
	}
	return repository.GetVPS(ctx, input.ID)
}

func (repository *Repository) GetVPS(ctx context.Context, id string) (VPSNode, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return VPSNode{}, store.ErrNotFound
	}
	return scanVPS(repository.Database.QueryRowContext(ctx, `
SELECT id, display_number, name, enabled, priority, verified_fingerprint, public_key,
       admin_address_pool, resource_alias_pool, state, created_at, updated_at
FROM vps_nodes WHERE id=?`, id))
}

func (repository *Repository) ListVPS(ctx context.Context) ([]VPSNode, error) {
	if repository == nil || repository.Database == nil {
		return nil, errors.New("management database is required")
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT id, display_number, name, enabled, priority, verified_fingerprint, public_key,
       admin_address_pool, resource_alias_pool, state, created_at, updated_at
FROM vps_nodes ORDER BY priority, display_number, id`)
	if err != nil {
		return nil, fmt.Errorf("list VPS nodes: %w", err)
	}
	defer rows.Close()
	items := make([]VPSNode, 0)
	for rows.Next() {
		item, err := scanVPS(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate VPS nodes: %w", err)
	}
	return items, nil
}

func (repository *Repository) CreateLink(ctx context.Context, input CreateLinkInput) (Link, error) {
	if repository == nil || repository.Database == nil {
		return Link{}, errors.New("management database is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Link{}, fmt.Errorf("begin management link create: %w", err)
	}
	defer transaction.Rollback()
	if err := repository.createLinkTx(ctx, transaction, input); err != nil {
		return Link{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Link{}, fmt.Errorf("commit management link create: %w", err)
	}
	return repository.GetLink(ctx, input.ID)
}

func (repository *Repository) createLinkTx(ctx context.Context, transaction *sql.Tx, input CreateLinkInput) error {
	var isLocal int
	if err := transaction.QueryRowContext(ctx, "SELECT is_local FROM management_sites WHERE id=?", input.SiteID).Scan(&isLocal); err != nil || isLocal != 1 {
		return errors.New("management link must belong to the local immutable site")
	}
	var remotePublicKey string
	if err := transaction.QueryRowContext(ctx, "SELECT public_key FROM vps_nodes WHERE id=? AND state!='REVOKED'", input.VPSID).Scan(&remotePublicKey); err != nil {
		return errors.New("management link VPS identity is unavailable")
	}
	if strings.TrimSpace(input.RemotePublicKey) != remotePublicKey {
		return errors.New("management link remote public key does not match verified VPS identity")
	}
	if input.PinnedUplinkID != "" {
		var count int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM uplinks WHERE id=?", input.PinnedUplinkID).Scan(&count); err != nil || count != 1 {
			return errors.New("pinned management uplink does not exist")
		}
	}

	var slot int64
	if input.AdoptLegacySlot0 {
		slot = 0
		var count int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_links WHERE slot=0 OR interface_name='wg-mgmt'").Scan(&count); err != nil || count != 0 {
			return errors.New("legacy wg-mgmt slot is already adopted")
		}
	} else {
		var err error
		slot, err = allocateLinkSlot(ctx, transaction)
		if err != nil {
			return err
		}
	}
	interfaceName := InterfaceNameForSlot(slot)
	if err := ValidateLinkInput(input, slot, interfaceName); err != nil {
		return err
	}
	prefix := mustPrivatePrefix(input.ManagementSubnet, 16, 30)
	if err := repository.rejectPrefixCollisionsTx(ctx, transaction, []namedPrefix{{owner: "new-link:" + input.ID, prefix: prefix}}, ""); err != nil {
		return err
	}
	now := repository.now().Format(time.RFC3339Nano)
	_, err := transaction.ExecContext(ctx, `
INSERT INTO management_links(
    id, site_id, vps_id, slot, interface_name, enabled, management_subnet,
    local_address, remote_address, local_private_key_secret_ref, local_public_key,
    remote_public_key, uplink_policy, pinned_uplink_id, persistent_keepalive,
    state, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.ID, input.SiteID, input.VPSID, slot, interfaceName, boolInt(input.Enabled),
		input.ManagementSubnet, input.LocalAddress, input.RemoteAddress,
		input.LocalPrivateKeySecretRef, strings.TrimSpace(input.LocalPublicKey), strings.TrimSpace(input.RemotePublicKey),
		input.UplinkPolicy, nullIfEmpty(input.PinnedUplinkID), input.PersistentKeepalive,
		map[bool]string{true: "CONFIGURED", false: "DISABLED"}[input.Enabled], now, now)
	if err != nil {
		return fmt.Errorf("store management link (duplicate identity, address, subnet, key, or VPS binding): %w", err)
	}
	for index, endpoint := range input.Endpoints {
		endpointID := fmt.Sprintf("mgmt-endpoint:%s:%d", input.ID, index+1)
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(endpoint.Host), "."))
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO management_link_endpoints(
    id, link_id, priority, endpoint_host, endpoint_port, state, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, 'UNRESOLVED', ?, ?)`, endpointID, input.ID, index+1, host, endpoint.Port, now, now); err != nil {
			return fmt.Errorf("store management endpoint: %w", err)
		}
	}
	if err := advanceGeneration(ctx, transaction, now); err != nil {
		return err
	}
	return nil
}

func (repository *Repository) GetLink(ctx context.Context, id string) (Link, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return Link{}, store.ErrNotFound
	}
	item, err := scanLink(repository.Database.QueryRowContext(ctx, linkSelect+" WHERE id=?", id))
	if err != nil {
		return Link{}, err
	}
	item.Endpoints, err = repository.listEndpoints(ctx, item.ID)
	return item, err
}

func (repository *Repository) ListLinks(ctx context.Context) ([]Link, error) {
	if repository == nil || repository.Database == nil {
		return nil, errors.New("management database is required")
	}
	rows, err := repository.Database.QueryContext(ctx, linkSelect+" ORDER BY slot, id")
	if err != nil {
		return nil, fmt.Errorf("list management links: %w", err)
	}
	items := make([]Link, 0)
	for rows.Next() {
		item, err := scanLink(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate management links: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close management links: %w", err)
	}
	for index := range items {
		items[index].Endpoints, err = repository.listEndpoints(ctx, items[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (repository *Repository) listEndpoints(ctx context.Context, linkID string) ([]Endpoint, error) {
	rows, err := repository.Database.QueryContext(ctx, `
SELECT id, link_id, priority, endpoint_host, endpoint_port,
       COALESCE(resolved_address,''), COALESCE(resolved_expires_at,''), state, last_error_code
FROM management_link_endpoints WHERE link_id=? ORDER BY priority, id`, linkID)
	if err != nil {
		return nil, fmt.Errorf("list management link endpoints: %w", err)
	}
	defer rows.Close()
	items := make([]Endpoint, 0)
	for rows.Next() {
		var item Endpoint
		if err := rows.Scan(&item.ID, &item.LinkID, &item.Priority, &item.Host, &item.Port,
			&item.ResolvedAddress, &item.ResolvedExpiresAt, &item.State, &item.LastErrorCode); err != nil {
			return nil, fmt.Errorf("scan management link endpoint: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository *Repository) rejectPrefixCollisionsTx(ctx context.Context, transaction *sql.Tx, candidates []namedPrefix, excludedLinkID string) error {
	all := make([]namedPrefix, 0, len(repository.ReservedPrefixes)+len(candidates)+16)
	for _, reserved := range repository.ReservedPrefixes {
		prefix, err := canonicalPrefix(reserved.CIDR)
		if err != nil || prefix.Bits() == 0 {
			return fmt.Errorf("configured reserved prefix %q is invalid", reserved.Owner)
		}
		all = append(all, namedPrefix{owner: "reserved:" + reserved.Owner, prefix: prefix})
	}
	all = append(all, candidates...)

	queries := []struct {
		statement string
		owner     string
		args      []any
	}{
		{"SELECT admin_address_pool FROM vps_nodes", "vps-admin-pool", nil},
		{"SELECT resource_alias_pool FROM vps_nodes", "vps-alias-pool", nil},
		{"SELECT management_subnet FROM management_links WHERE id<>?", "management-link", []any{excludedLinkID}},
		{"SELECT published_alias FROM management_resource_publications", "published-alias", nil},
		{"SELECT subnet_cidr FROM wireguard_ingress_servers", "wireguard-ingress", nil},
		{"SELECT management_cidr FROM modems WHERE management_cidr IS NOT NULL AND management_cidr<>''", "modem", nil},
		{"SELECT ipv4_cidr FROM uplinks WHERE ipv4_cidr IS NOT NULL AND ipv4_cidr<>''", "uplink-runtime", nil},
		{"SELECT configured_ipv4_cidr FROM uplinks WHERE configured_ipv4_cidr IS NOT NULL AND configured_ipv4_cidr<>''", "uplink-config", nil},
	}
	for _, query := range queries {
		rows, err := transaction.QueryContext(ctx, query.statement, query.args...)
		if err != nil {
			return fmt.Errorf("read %s prefixes: %w", query.owner, err)
		}
		index := 0
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return fmt.Errorf("scan %s prefix: %w", query.owner, err)
			}
			prefix, err := canonicalPrefix(raw)
			if err != nil {
				rows.Close()
				return fmt.Errorf("stored %s prefix is invalid", query.owner)
			}
			index++
			all = append(all, namedPrefix{owner: fmt.Sprintf("%s:%d", query.owner, index), prefix: prefix})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate %s prefixes: %w", query.owner, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close %s prefixes: %w", query.owner, err)
		}
	}
	return rejectOverlaps(all)
}

func allocateVPSNumber(ctx context.Context, transaction *sql.Tx) (int64, error) {
	var number int64
	if err := transaction.QueryRowContext(ctx, "SELECT next_vps_number FROM management_fabric_counters WHERE singleton_id=1").Scan(&number); err != nil {
		return 0, fmt.Errorf("read next VPS number: %w", err)
	}
	if number < 1 || number > 1000000 {
		return 0, errors.New("VPS display number allocation is exhausted")
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE management_fabric_counters SET next_vps_number=? WHERE singleton_id=1", number+1); err != nil {
		return 0, fmt.Errorf("advance VPS number: %w", err)
	}
	return number, nil
}

func allocateLinkSlot(ctx context.Context, transaction *sql.Tx) (int64, error) {
	var slot int64
	if err := transaction.QueryRowContext(ctx, "SELECT next_link_slot FROM management_fabric_counters WHERE singleton_id=1").Scan(&slot); err != nil {
		return 0, fmt.Errorf("read next management link slot: %w", err)
	}
	if slot < 1 || slot >= MaximumLinks {
		return 0, errors.New("management link slot allocation is exhausted")
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE management_fabric_counters SET next_link_slot=? WHERE singleton_id=1", slot+1); err != nil {
		return 0, fmt.Errorf("advance management link slot: %w", err)
	}
	return slot, nil
}

func advanceGeneration(ctx context.Context, transaction *sql.Tx, now string) error {
	result, err := transaction.ExecContext(ctx, `
UPDATE management_fabric_generations
SET desired_generation=desired_generation+1, state='PENDING', updated_at=?
WHERE singleton_id=1`, now)
	if err != nil {
		return fmt.Errorf("advance management fabric generation: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return errors.New("management fabric generation singleton is missing")
	}
	return nil
}

const linkSelect = `
SELECT id, site_id, vps_id, slot, interface_name, enabled, management_subnet,
       local_address, remote_address, local_private_key_secret_ref, local_public_key,
       remote_public_key, uplink_policy, COALESCE(pinned_uplink_id,''),
       COALESCE(selected_uplink_id,''), persistent_keepalive,
       desired_route_generation, applied_route_generation,
       desired_acl_generation, applied_acl_generation, state, last_error_code,
       COALESCE(last_handshake_at,''), created_at, updated_at
FROM management_links`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanVPS(scanner rowScanner) (VPSNode, error) {
	var item VPSNode
	var enabled int
	if err := scanner.Scan(&item.ID, &item.DisplayNumber, &item.Name, &enabled, &item.Priority,
		&item.VerifiedFingerprint, &item.PublicKey, &item.AdminAddressPool, &item.ResourceAliasPool,
		&item.State, &item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VPSNode{}, store.ErrNotFound
		}
		return VPSNode{}, fmt.Errorf("scan VPS node: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanLink(scanner rowScanner) (Link, error) {
	var item Link
	var enabled int
	if err := scanner.Scan(
		&item.ID, &item.SiteID, &item.VPSID, &item.Slot, &item.InterfaceName, &enabled,
		&item.ManagementSubnet, &item.LocalAddress, &item.RemoteAddress, &item.privateKeySecretRef,
		&item.LocalPublicKey, &item.RemotePublicKey, &item.UplinkPolicy, &item.PinnedUplinkID,
		&item.SelectedUplinkID, &item.PersistentKeepalive, &item.DesiredRouteGeneration,
		&item.AppliedRouteGeneration, &item.DesiredACLGeneration, &item.AppliedACLGeneration,
		&item.State, &item.LastErrorCode, &item.LastHandshakeAt, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Link{}, store.ErrNotFound
		}
		return Link{}, fmt.Errorf("scan management link: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func mustPrivatePrefix(value string, minBits, maxBits int) netip.Prefix {
	prefix, err := canonicalPrivatePrefix(value, minBits, maxBits)
	if err != nil {
		panic("mustPrivatePrefix called without prior validation")
	}
	return prefix
}

func (repository *Repository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}
