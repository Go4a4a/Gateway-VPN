package wgingress

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type Repository struct {
	Database         *sql.DB
	SecretRoot       string
	ReservedPrefixes []netip.Prefix
	Now              func() time.Time
}

func (repository Repository) EnsureDefault(ctx context.Context, keys KeyStore) (Server, error) {
	if repository.Database == nil || !filepath.IsAbs(repository.SecretRoot) || filepath.Clean(repository.SecretRoot) != filepath.Clean(keys.Root) {
		return Server{}, errors.New("WireGuard ingress database and fixed secret root are required")
	}
	server, err := repository.GetServer(ctx)
	if err == nil {
		if !ValidKey(server.PublicKey) {
			return Server{}, errors.New("stored WireGuard ingress server public key is invalid")
		}
		return server, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return Server{}, err
	}
	pair, err := GenerateKeyPair()
	if err != nil {
		return Server{}, err
	}
	privatePath, err := keys.ServerPrivatePath(DefaultServerID)
	if err != nil {
		return Server{}, err
	}
	if err := keys.Write(privatePath, pair.Private); err != nil {
		return Server{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		_ = keys.Remove(privatePath)
		return Server{}, fmt.Errorf("begin WireGuard ingress default server: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `
INSERT INTO wireguard_ingress_servers(
    id, enabled, name, interface_name, subnet_cidr, listen_port, endpoint_host,
    mtu, private_key_secret_ref, public_key, topology_mode, config_generation,
    created_at, updated_at
) VALUES (?, 0, 'WireGuard для клиентов', ?, ?, ?, '', ?, ?, ?, 'ROUTED', 1, ?, ?)`,
		DefaultServerID, DefaultInterfaceName, DefaultSubnet, DefaultListenPort, DefaultMTU,
		privatePath, pair.Public, now, now)
	if err == nil {
		_, err = transaction.ExecContext(ctx, `
INSERT INTO wireguard_ingress_runtime(
    server_id, desired_generation, applied_generation, state, updated_at
) VALUES (?, 1, 0, 'DISABLED', ?)`, DefaultServerID, now)
	}
	if err != nil {
		_ = keys.Remove(privatePath)
		return Server{}, fmt.Errorf("insert WireGuard ingress default server: %w", err)
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_SERVER_CREATED", map[string]any{"server_id": DefaultServerID, "enabled": false}); err != nil {
		_ = keys.Remove(privatePath)
		return Server{}, err
	}
	if err := transaction.Commit(); err != nil {
		_ = keys.Remove(privatePath)
		return Server{}, fmt.Errorf("commit WireGuard ingress default server: %w", err)
	}
	return repository.GetServer(ctx)
}

func (repository Repository) GetServer(ctx context.Context) (Server, error) {
	if repository.Database == nil {
		return Server{}, errors.New("WireGuard ingress database is required")
	}
	var result Server
	var enabled int
	var mtu sql.NullInt64
	var networkInterfaceID, lastAppliedAt sql.NullString
	err := repository.Database.QueryRowContext(ctx, `
SELECT s.id, s.enabled, s.name, s.interface_name, s.subnet_cidr, s.listen_port,
       s.endpoint_host, s.mtu, s.private_key_secret_ref, s.public_key,
       s.topology_mode, s.network_interface_id, s.config_generation,
       r.desired_generation, r.applied_generation, r.state, r.last_error_code,
       r.last_applied_at, s.created_at, s.updated_at
FROM wireguard_ingress_servers AS s
JOIN wireguard_ingress_runtime AS r ON r.server_id=s.id
ORDER BY s.created_at, s.id LIMIT 1`).Scan(
		&result.ID, &enabled, &result.Name, &result.InterfaceName, &result.SubnetCIDR,
		&result.ListenPort, &result.EndpointHost, &mtu, &result.PrivateKeySecretRef,
		&result.PublicKey, &result.TopologyMode, &networkInterfaceID,
		&result.ConfigGeneration, &result.DesiredGeneration, &result.AppliedGeneration,
		&result.State, &result.LastErrorCode, &lastAppliedAt, &result.CreatedAt, &result.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Server{}, store.ErrNotFound
	}
	if err != nil {
		return Server{}, fmt.Errorf("read WireGuard ingress server: %w", err)
	}
	result.Enabled = enabled != 0
	result.MTU = int(mtu.Int64)
	result.NetworkInterfaceID = networkInterfaceID.String
	result.LastAppliedAt = lastAppliedAt.String
	prefix, err := canonicalIPv4Prefix(result.SubnetCIDR)
	if err != nil {
		return Server{}, errors.New("stored WireGuard ingress subnet is invalid")
	}
	address, ok := nextAddress(prefix, 1)
	if !ok {
		return Server{}, errors.New("stored WireGuard ingress subnet has no server address")
	}
	result.ServerAddress = address.String() + "/" + fmt.Sprint(prefix.Bits())
	if result.EndpointHost != "" {
		result.Endpoint = netipEndpoint(result.EndpointHost, result.ListenPort)
	}
	result.DNS, err = repository.serverDNS(ctx, result.ID)
	if err != nil {
		return Server{}, err
	}
	result.ListenInterfaces, err = repository.listenInterfaces(ctx, result.ID)
	if err != nil {
		return Server{}, err
	}
	return result, nil
}

func (repository Repository) UpdateServer(ctx context.Context, input ServerUpdate) (Server, error) {
	if repository.Database == nil {
		return Server{}, errors.New("WireGuard ingress database is required")
	}
	if err := ValidateServerUpdate(input); err != nil {
		return Server{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	prefix, _ := canonicalIPv4Prefix(input.SubnetCIDR)
	input.SubnetCIDR = prefix.String()
	input.DNS, _ = canonicalAddresses(input.DNS)
	if err := repository.validateServerTopology(ctx, input); err != nil {
		return Server{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Server{}, fmt.Errorf("begin WireGuard ingress server update: %w", err)
	}
	defer transaction.Rollback()
	var serverID, oldSubnet string
	err = transaction.QueryRowContext(ctx, "SELECT id, subnet_cidr FROM wireguard_ingress_servers ORDER BY created_at, id LIMIT 1").Scan(&serverID, &oldSubnet)
	if errors.Is(err, sql.ErrNoRows) {
		return Server{}, store.ErrNotFound
	}
	if err != nil {
		return Server{}, fmt.Errorf("read WireGuard ingress server for update: %w", err)
	}
	if err := validateExistingPeersForSubnet(ctx, transaction, serverID, prefix); err != nil {
		return Server{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_servers
SET enabled=?, name=?, subnet_cidr=?, listen_port=?, endpoint_host=?, mtu=?,
    topology_mode=?, network_interface_id=?, config_generation=config_generation+1,
    updated_at=?
WHERE id=?`, boolInt(input.Enabled), input.Name, input.SubnetCIDR, input.ListenPort,
		strings.TrimSpace(input.EndpointHost), input.MTU, input.TopologyMode,
		nullString(input.NetworkInterfaceID), now, serverID)
	if err != nil {
		return Server{}, fmt.Errorf("update WireGuard ingress server: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return Server{}, store.ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM wireguard_ingress_server_dns WHERE server_id=?", serverID); err != nil {
		return Server{}, fmt.Errorf("replace WireGuard ingress DNS: %w", err)
	}
	for index, address := range input.DNS {
		if _, err := transaction.ExecContext(ctx, "INSERT INTO wireguard_ingress_server_dns(server_id,address,priority) VALUES (?,?,?)", serverID, address, index+1); err != nil {
			return Server{}, fmt.Errorf("insert WireGuard ingress DNS: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM wireguard_ingress_listen_interfaces WHERE server_id=?", serverID); err != nil {
		return Server{}, fmt.Errorf("replace WireGuard ingress listen interfaces: %w", err)
	}
	for index, item := range input.ListenInterfaces {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO wireguard_ingress_listen_interfaces(server_id, network_interface_id, exposure_mode, priority)
VALUES (?, ?, ?, ?)`, serverID, item.NetworkInterfaceID, item.ExposureMode, index+1); err != nil {
			return Server{}, fmt.Errorf("insert WireGuard ingress listen interface: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_runtime
SET desired_generation=desired_generation+1, state='PENDING', last_error_code='', updated_at=?
WHERE server_id=?`, now, serverID); err != nil {
		return Server{}, fmt.Errorf("advance WireGuard ingress desired generation: %w", err)
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_SERVER_UPDATED", map[string]any{"server_id": serverID, "enabled": input.Enabled, "topology_mode": input.TopologyMode, "subnet_changed": oldSubnet != input.SubnetCIDR}); err != nil {
		return Server{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Server{}, fmt.Errorf("commit WireGuard ingress server update: %w", err)
	}
	return repository.GetServer(ctx)
}

func (repository Repository) ListPeers(ctx context.Context) ([]Peer, error) {
	server, err := repository.GetServer(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT p.id, p.server_id, p.display_number, p.name, p.enabled, p.peer_kind,
       p.key_mode, p.public_key, p.private_key_secret_ref, p.preshared_key_secret_ref,
       p.assigned_address, p.endpoint_override, p.persistent_keepalive,
       p.access_policy_mode, p.allow_whitelist_only, p.block_when_unqualified,
       p.client_dns_enabled, p.revoked_at, p.created_at, p.updated_at,
       r.last_handshake_at, r.rx_bytes, r.tx_bytes, r.observed_endpoint, r.state
FROM wireguard_ingress_peers AS p
JOIN wireguard_ingress_peer_runtime AS r ON r.peer_id=p.id
WHERE p.server_id=?
ORDER BY p.display_number, p.id`, server.ID)
	if err != nil {
		return nil, fmt.Errorf("list WireGuard ingress peers: %w", err)
	}
	items := make([]Peer, 0)
	for rows.Next() {
		item, err := scanPeer(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate WireGuard ingress peers: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close WireGuard ingress peer cursor: %w", err)
	}
	for index := range items {
		if err := repository.loadPeerLists(ctx, &items[index]); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (repository Repository) GetPeer(ctx context.Context, id string) (Peer, error) {
	if repository.Database == nil || !safeIdentifier.MatchString(id) {
		return Peer{}, store.ErrNotFound
	}
	row := repository.Database.QueryRowContext(ctx, `
SELECT p.id, p.server_id, p.display_number, p.name, p.enabled, p.peer_kind,
       p.key_mode, p.public_key, p.private_key_secret_ref, p.preshared_key_secret_ref,
       p.assigned_address, p.endpoint_override, p.persistent_keepalive,
       p.access_policy_mode, p.allow_whitelist_only, p.block_when_unqualified,
       p.client_dns_enabled, p.revoked_at, p.created_at, p.updated_at,
       r.last_handshake_at, r.rx_bytes, r.tx_bytes, r.observed_endpoint, r.state
FROM wireguard_ingress_peers AS p
JOIN wireguard_ingress_peer_runtime AS r ON r.peer_id=p.id
WHERE p.id=?`, id)
	item, err := scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Peer{}, store.ErrNotFound
	}
	if err != nil {
		return Peer{}, err
	}
	if err := repository.loadPeerLists(ctx, &item); err != nil {
		return Peer{}, err
	}
	return item, nil
}

func (repository Repository) CreatePeer(ctx context.Context, input PeerCreate, pair *KeyPair, presharedKey string, keys KeyStore) (Peer, error) {
	if err := ValidatePeerCreate(input); err != nil {
		return Peer{}, err
	}
	server, err := repository.GetServer(ctx)
	if err != nil {
		return Peer{}, err
	}
	var publicKey, privateRef, presharedRef string
	peerID, err := newID("wgpeer")
	if err != nil {
		return Peer{}, err
	}
	if input.KeyMode == "MANAGED" {
		if pair == nil || !ValidKey(pair.Private) || !ValidKey(pair.Public) || !ValidKey(presharedKey) {
			return Peer{}, errors.New("managed WireGuard peer key material is incomplete")
		}
		derived, err := PublicKey(pair.Private)
		if err != nil || derived != pair.Public {
			return Peer{}, errors.New("managed WireGuard peer keypair is inconsistent")
		}
		publicKey = pair.Public
		privateRef, _ = keys.PeerPrivatePath(peerID)
		presharedRef, _ = keys.PeerPresharedPath(peerID)
		if err := keys.Write(privateRef, pair.Private); err != nil {
			return Peer{}, err
		}
		if err := keys.Write(presharedRef, presharedKey); err != nil {
			_ = keys.Remove(privateRef)
			return Peer{}, err
		}
	} else {
		publicKey = strings.TrimSpace(input.PublicKey)
	}
	cleanupSecrets := func() {
		if privateRef != "" {
			_ = keys.Remove(privateRef)
		}
		if presharedRef != "" {
			_ = keys.Remove(presharedRef)
		}
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		cleanupSecrets()
		return Peer{}, fmt.Errorf("begin WireGuard peer create: %w", err)
	}
	defer transaction.Rollback()
	assigned, err := repository.allocatePeerAddress(ctx, transaction, server, input.AssignedAddress)
	if err != nil {
		cleanupSecrets()
		return Peer{}, err
	}
	if err := repository.validatePeerRoutesTx(ctx, transaction, server, peerID, assigned, input.BehindSubnets); err != nil {
		cleanupSecrets()
		return Peer{}, err
	}
	number, err := allocatePeerNumber(ctx, transaction)
	if err != nil {
		cleanupSecrets()
		return Peer{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
INSERT INTO wireguard_ingress_peers(
    id, server_id, display_number, name, enabled, peer_kind, key_mode, public_key,
    private_key_secret_ref, preshared_key_secret_ref, assigned_address,
    endpoint_override, persistent_keepalive, access_policy_mode,
    allow_whitelist_only, block_when_unqualified, client_dns_enabled,
    created_at, updated_at
) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		peerID, server.ID, number, strings.TrimSpace(input.Name), input.PeerKind,
		input.KeyMode, publicKey, nullString(privateRef), nullString(presharedRef), assigned,
		strings.TrimSpace(input.EndpointOverride), input.PersistentKeepalive,
		input.AccessPolicyMode, boolInt(input.AllowWhitelistOnly), boolInt(input.BlockWhenUnqualified),
		boolInt(input.ClientDNSEnabled), now, now)
	if err == nil {
		_, err = transaction.ExecContext(ctx, `
INSERT INTO wireguard_ingress_peer_runtime(peer_id, state, updated_at)
VALUES (?, 'NEVER_CONNECTED', ?)`, peerID, now)
	}
	if err == nil {
		err = replacePeerLists(ctx, transaction, peerID, input.BehindSubnets, input.ClientAllowedIPs, input.AllowedAccessMethodIDs, now)
	}
	if err == nil {
		_, err = transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_runtime SET desired_generation=desired_generation+1,
    state='PENDING', last_error_code='', updated_at=? WHERE server_id=?`, now, server.ID)
	}
	if err != nil {
		cleanupSecrets()
		return Peer{}, fmt.Errorf("insert WireGuard ingress peer: %w", err)
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_PEER_CREATED", map[string]any{"peer_id": peerID, "server_id": server.ID, "key_mode": input.KeyMode, "peer_kind": input.PeerKind}); err != nil {
		cleanupSecrets()
		return Peer{}, err
	}
	if err := transaction.Commit(); err != nil {
		cleanupSecrets()
		return Peer{}, fmt.Errorf("commit WireGuard ingress peer create: %w", err)
	}
	return repository.GetPeer(ctx, peerID)
}

func (repository Repository) UpdatePeer(ctx context.Context, id string, input PeerUpdate) (Peer, error) {
	if !safeIdentifier.MatchString(id) || ValidatePeerUpdate(input) != nil {
		return Peer{}, errors.New("valid WireGuard peer update is required")
	}
	server, err := repository.GetServer(ctx)
	if err != nil {
		return Peer{}, err
	}
	current, err := repository.GetPeer(ctx, id)
	if err != nil {
		return Peer{}, err
	}
	if current.RevokedAt != "" {
		return Peer{}, errors.New("revoked WireGuard peer cannot be edited")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Peer{}, fmt.Errorf("begin WireGuard peer update: %w", err)
	}
	defer transaction.Rollback()
	if err := repository.validatePeerRoutesTx(ctx, transaction, server, id, current.AssignedAddress, input.BehindSubnets); err != nil {
		return Peer{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_peers
SET name=?, enabled=?, endpoint_override=?, persistent_keepalive=?,
    access_policy_mode=?, allow_whitelist_only=?, block_when_unqualified=?,
    client_dns_enabled=?, updated_at=?
WHERE id=? AND revoked_at IS NULL`, strings.TrimSpace(input.Name), boolInt(input.Enabled),
		strings.TrimSpace(input.EndpointOverride), input.PersistentKeepalive, input.AccessPolicyMode,
		boolInt(input.AllowWhitelistOnly), boolInt(input.BlockWhenUnqualified), boolInt(input.ClientDNSEnabled), now, id)
	if err != nil {
		return Peer{}, fmt.Errorf("update WireGuard ingress peer: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return Peer{}, store.ErrNotFound
	}
	if err := replacePeerLists(ctx, transaction, id, input.BehindSubnets, input.ClientAllowedIPs, input.AllowedAccessMethodIDs, now); err != nil {
		return Peer{}, err
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_runtime SET desired_generation=desired_generation+1,
    state='PENDING', last_error_code='', updated_at=? WHERE server_id=?`, now, server.ID); err != nil {
		return Peer{}, err
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_PEER_UPDATED", map[string]any{"peer_id": id, "enabled": input.Enabled}); err != nil {
		return Peer{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Peer{}, fmt.Errorf("commit WireGuard ingress peer update: %w", err)
	}
	return repository.GetPeer(ctx, id)
}

func (repository Repository) RevokePeer(ctx context.Context, id string) (Peer, error) {
	return repository.setPeerRevoked(ctx, id, true)
}

func (repository Repository) setPeerRevoked(ctx context.Context, id string, revoked bool) (Peer, error) {
	if !safeIdentifier.MatchString(id) {
		return Peer{}, store.ErrNotFound
	}
	peer, err := repository.GetPeer(ctx, id)
	if err != nil {
		return Peer{}, err
	}
	if peer.RevokedAt != "" && revoked {
		return peer, nil
	}
	now := repository.now().Format(time.RFC3339Nano)
	revokedAt := any(nil)
	if revoked {
		revokedAt = now
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Peer{}, err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "UPDATE wireguard_ingress_peers SET enabled=0, revoked_at=?, updated_at=? WHERE id=?", revokedAt, now, id); err != nil {
		return Peer{}, err
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE wireguard_ingress_runtime SET desired_generation=desired_generation+1, state='PENDING', updated_at=? WHERE server_id=?`, now, peer.ServerID); err != nil {
		return Peer{}, err
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_PEER_REVOKED", map[string]any{"peer_id": id}); err != nil {
		return Peer{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Peer{}, err
	}
	return repository.GetPeer(ctx, id)
}

func (repository Repository) DeletePeer(ctx context.Context, id string) (Peer, error) {
	peer, err := repository.GetPeer(ctx, id)
	if err != nil {
		return Peer{}, err
	}
	if peer.RevokedAt == "" || peer.Enabled {
		return Peer{}, errors.New("WireGuard peer must be revoked before deletion")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Peer{}, err
	}
	defer transaction.Rollback()
	now := repository.now().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, "DELETE FROM wireguard_ingress_peers WHERE id=?", id); err != nil {
		return Peer{}, err
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE wireguard_ingress_runtime SET desired_generation=desired_generation+1, state='PENDING', updated_at=? WHERE server_id=?`, now, peer.ServerID); err != nil {
		return Peer{}, err
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_PEER_DELETED", map[string]any{"peer_id": id, "number": peer.DisplayNumber}); err != nil {
		return Peer{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Peer{}, err
	}
	return peer, nil
}

func (repository Repository) RotatePeerKey(ctx context.Context, id, publicKey string) (Peer, error) {
	peer, err := repository.GetPeer(ctx, id)
	if err != nil {
		return Peer{}, err
	}
	if peer.KeyMode != "MANAGED" || peer.RevokedAt != "" || !ValidKey(publicKey) || publicKey == peer.PublicKey {
		return Peer{}, errors.New("active managed WireGuard peer and a new public key are required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Peer{}, err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "UPDATE wireguard_ingress_peers SET public_key=?, updated_at=? WHERE id=?", publicKey, now, id); err != nil {
		return Peer{}, fmt.Errorf("rotate WireGuard ingress peer key: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE wireguard_ingress_runtime SET desired_generation=desired_generation+1, state='PENDING', updated_at=? WHERE server_id=?`, now, peer.ServerID); err != nil {
		return Peer{}, err
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_PEER_KEY_ROTATED", map[string]any{"peer_id": id}); err != nil {
		return Peer{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Peer{}, err
	}
	return repository.GetPeer(ctx, id)
}

func (repository Repository) RotateServerKey(ctx context.Context, id, publicKey string) (Server, error) {
	if !safeIdentifier.MatchString(id) || !ValidKey(publicKey) {
		return Server{}, errors.New("valid WireGuard ingress server and public key are required")
	}
	current, err := repository.GetServer(ctx)
	if err != nil {
		return Server{}, err
	}
	if current.ID != id || current.PublicKey == publicKey {
		return Server{}, errors.New("new WireGuard ingress server public key is required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Server{}, err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_servers
SET public_key=?, config_generation=config_generation+1, updated_at=? WHERE id=?`, publicKey, now, id); err != nil {
		return Server{}, fmt.Errorf("rotate WireGuard ingress server key: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_runtime
SET desired_generation=desired_generation+1, state='PENDING', last_error_code='', updated_at=?
WHERE server_id=?`, now, id); err != nil {
		return Server{}, err
	}
	if err := appendEvent(ctx, transaction, repository.now(), "WIREGUARD_INGRESS_SERVER_KEY_ROTATED", map[string]any{"server_id": id}); err != nil {
		return Server{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Server{}, err
	}
	return repository.GetServer(ctx)
}

func (repository Repository) SetRuntime(ctx context.Context, serverID, state, errorCode string, appliedGeneration int64) error {
	if !safeIdentifier.MatchString(serverID) || state == "" {
		return errors.New("valid WireGuard ingress runtime state is required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	lastApplied := any(nil)
	if state == "ACTIVE" || state == "DISABLED" {
		lastApplied = now
	}
	_, err := repository.Database.ExecContext(ctx, `
UPDATE wireguard_ingress_runtime
SET applied_generation=?, state=?, last_error_code=?, last_applied_at=COALESCE(?,last_applied_at), updated_at=?
WHERE server_id=?`, appliedGeneration, state, errorCode, lastApplied, now, serverID)
	if err != nil {
		return fmt.Errorf("update WireGuard ingress runtime: %w", err)
	}
	return nil
}

func (repository Repository) UpdatePeerRuntime(ctx context.Context, values []PeerRuntime) error {
	if repository.Database == nil {
		return errors.New("WireGuard ingress database is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	now := repository.now()
	for _, value := range values {
		if !ValidKey(value.PublicKey) || value.RXBytes < 0 || value.TXBytes < 0 {
			return errors.New("invalid WireGuard ingress runtime observation")
		}
		state := "NEVER_CONNECTED"
		var handshake any
		if !value.HandshakeAt.IsZero() {
			handshake = value.HandshakeAt.UTC().Format(time.RFC3339Nano)
			state = "HEALTHY"
			if now.Sub(value.HandshakeAt) > 3*time.Minute {
				state = "STALE_HANDSHAKE"
			}
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE wireguard_ingress_peer_runtime
SET last_handshake_at=?, rx_bytes=?, tx_bytes=?, observed_endpoint=?, state=?, updated_at=?
WHERE peer_id=(SELECT id FROM wireguard_ingress_peers WHERE public_key=?)`,
			handshake, value.RXBytes, value.TXBytes, maskEndpoint(value.Endpoint), state,
			now.Format(time.RFC3339Nano), value.PublicKey); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (repository Repository) serverDNS(ctx context.Context, serverID string) ([]string, error) {
	rows, err := repository.Database.QueryContext(ctx, "SELECT address FROM wireguard_ingress_server_dns WHERE server_id=? ORDER BY priority", serverID)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard ingress DNS: %w", err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (repository Repository) listenInterfaces(ctx context.Context, serverID string) ([]ListenInterface, error) {
	rows, err := repository.Database.QueryContext(ctx, `
SELECT l.network_interface_id, COALESCE(n.current_ifname,''), l.exposure_mode, l.priority
FROM wireguard_ingress_listen_interfaces AS l
JOIN network_interfaces AS n ON n.id=l.network_interface_id
WHERE l.server_id=? ORDER BY l.priority`, serverID)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard ingress listen interfaces: %w", err)
	}
	defer rows.Close()
	var result []ListenInterface
	for rows.Next() {
		var item ListenInterface
		if err := rows.Scan(&item.NetworkInterfaceID, &item.InterfaceName, &item.ExposureMode, &item.Priority); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (repository Repository) loadPeerLists(ctx context.Context, peer *Peer) error {
	queries := []struct {
		query string
		out   *[]string
	}{
		{"SELECT cidr FROM wireguard_ingress_peer_routes WHERE peer_id=? AND direction='INGRESS' ORDER BY cidr", &peer.BehindSubnets},
		{"SELECT cidr FROM wireguard_ingress_peer_client_allowed_ips WHERE peer_id=? ORDER BY priority", &peer.ClientAllowedIPs},
		{"SELECT access_method_id FROM wireguard_ingress_peer_access_methods WHERE peer_id=? ORDER BY priority", &peer.AllowedAccessMethodIDs},
	}
	for _, item := range queries {
		rows, err := repository.Database.QueryContext(ctx, item.query, peer.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				rows.Close()
				return err
			}
			*item.out = append(*item.out, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type rowScanner interface{ Scan(...any) error }

func scanPeer(row rowScanner) (Peer, error) {
	var item Peer
	var enabled, allowWhitelist, blockUnqualified, clientDNS int
	var privateRef, presharedRef, revokedAt, handshakeAt sql.NullString
	err := row.Scan(&item.ID, &item.ServerID, &item.DisplayNumber, &item.Name, &enabled,
		&item.PeerKind, &item.KeyMode, &item.PublicKey, &privateRef, &presharedRef,
		&item.AssignedAddress, &item.EndpointOverride, &item.PersistentKeepalive,
		&item.AccessPolicyMode, &allowWhitelist, &blockUnqualified, &clientDNS,
		&revokedAt, &item.CreatedAt, &item.UpdatedAt, &handshakeAt, &item.RXBytes,
		&item.TXBytes, &item.ObservedEndpoint, &item.RuntimeState)
	if err != nil {
		return Peer{}, err
	}
	item.Enabled = enabled != 0
	item.AllowWhitelistOnly = allowWhitelist != 0
	item.BlockWhenUnqualified = blockUnqualified != 0
	item.ClientDNSEnabled = clientDNS != 0
	item.RevokedAt = revokedAt.String
	item.LastHandshakeAt = handshakeAt.String
	item.privateKeySecretRef = privateRef.String
	item.presharedKeySecretRef = presharedRef.String
	item.PrivateKeyAvailable = item.KeyMode == "MANAGED" && item.privateKeySecretRef != ""
	return item, nil
}

func (repository Repository) validateServerTopology(ctx context.Context, input ServerUpdate) error {
	prefix, _ := canonicalIPv4Prefix(input.SubnetCIDR)
	for _, reserved := range append([]netip.Prefix{netip.MustParsePrefix("10.80.0.0/24")}, repository.ReservedPrefixes...) {
		if prefixesOverlap(prefix, reserved.Masked()) {
			return errors.New("WireGuard ingress subnet overlaps a reserved LAN/management subnet")
		}
	}
	rows, err := repository.Database.QueryContext(ctx, "SELECT ipv4_cidr FROM uplinks WHERE ipv4_cidr IS NOT NULL")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if rows.Scan(&value) == nil {
			if other, parseErr := netip.ParsePrefix(value); parseErr == nil && prefixesOverlap(prefix, other.Masked()) {
				return errors.New("WireGuard ingress subnet overlaps an uplink subnet")
			}
		}
	}
	for _, item := range input.ListenInterfaces {
		var currentIfname, carrier string
		var rolesJSON string
		err := repository.Database.QueryRowContext(ctx, `
SELECT COALESCE(n.current_ifname,''), n.carrier_state,
       COALESCE(json_group_array(a.role) FILTER (WHERE a.role IS NOT NULL), '[]')
FROM network_interfaces AS n
LEFT JOIN interface_role_assignments AS a ON a.network_interface_id=n.id
WHERE n.id=? GROUP BY n.id`, item.NetworkInterfaceID).Scan(&currentIfname, &carrier, &rolesJSON)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("WireGuard ingress listen interface does not exist")
		}
		if err != nil {
			return err
		}
		var roles []string
		if json.Unmarshal([]byte(rolesJSON), &roles) != nil || !validInterfaceName(currentIfname) || carrier == "ABSENT" {
			return errors.New("WireGuard ingress listen interface is not currently usable")
		}
		if item.ExposureMode == "PUBLIC" && !containsString(roles, "WG_ENDPOINT") && !containsString(roles, "SHARED_ONE_ARM") {
			return errors.New("public WireGuard exposure requires a WG_ENDPOINT or SHARED_ONE_ARM role")
		}
		if input.TopologyMode == "ONE_ARM" && !containsString(roles, "SHARED_ONE_ARM") {
			return errors.New("one-card WireGuard topology requires SHARED_ONE_ARM role")
		}
	}
	return rows.Err()
}

func validateExistingPeersForSubnet(ctx context.Context, transaction *sql.Tx, serverID string, prefix netip.Prefix) error {
	serverAddress, _ := nextAddress(prefix, 1)
	rows, err := transaction.QueryContext(ctx, `
SELECT assigned_address FROM wireguard_ingress_peers WHERE server_id=?`, serverID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return err
		}
		address, err := netip.ParseAddr(value)
		if err != nil || !prefix.Contains(address) || address == serverAddress {
			return errors.New("new WireGuard ingress subnet does not contain every existing peer")
		}
	}
	return rows.Err()
}

func (repository Repository) allocatePeerAddress(ctx context.Context, transaction *sql.Tx, server Server, requested string) (string, error) {
	prefix, _ := canonicalIPv4Prefix(server.SubnetCIDR)
	used := map[netip.Addr]struct{}{}
	serverAddress, _ := nextAddress(prefix, 1)
	used[serverAddress] = struct{}{}
	rows, err := transaction.QueryContext(ctx, "SELECT assigned_address FROM wireguard_ingress_peers WHERE server_id=?", server.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if rows.Scan(&value) == nil {
			if address, parseErr := netip.ParseAddr(value); parseErr == nil {
				used[address] = struct{}{}
			}
		}
	}
	if requested != "" {
		address, err := netip.ParseAddr(strings.TrimSpace(requested))
		if err != nil || !address.Is4() || !prefix.Contains(address) || address == prefix.Addr() {
			return "", errors.New("requested WireGuard peer address is outside the server subnet")
		}
		if _, exists := used[address]; exists {
			return "", errors.New("requested WireGuard peer address is already used")
		}
		return address.String(), nil
	}
	for offset := uint64(2); offset < uint64(2+MaximumPeers); offset++ {
		address, ok := nextAddress(prefix, offset)
		if !ok {
			break
		}
		if _, exists := used[address]; !exists {
			return address.String(), nil
		}
	}
	return "", errors.New("WireGuard ingress subnet has no free peer address")
}

func (repository Repository) validatePeerRoutesTx(ctx context.Context, transaction *sql.Tx, server Server, peerID, assigned string, routes []string) error {
	canonical, err := canonicalPrefixes(routes, false)
	if err != nil {
		return err
	}
	serverPrefix, _ := canonicalIPv4Prefix(server.SubnetCIDR)
	assignedAddress, err := netip.ParseAddr(assigned)
	if err != nil || !serverPrefix.Contains(assignedAddress) {
		return errors.New("WireGuard peer address is invalid")
	}
	candidates := []netip.Prefix{netip.PrefixFrom(assignedAddress, 32)}
	for _, value := range canonical {
		prefix, _ := canonicalIPv4Prefix(value)
		if prefixesOverlap(prefix, serverPrefix) {
			return errors.New("WireGuard peer behind subnet overlaps the tunnel subnet")
		}
		for _, reserved := range append([]netip.Prefix{netip.MustParsePrefix("10.80.0.0/24")}, repository.ReservedPrefixes...) {
			if prefixesOverlap(prefix, reserved.Masked()) {
				return errors.New("WireGuard peer behind subnet overlaps LAN/management")
			}
		}
		for _, candidate := range candidates {
			if prefixesOverlap(prefix, candidate) {
				return errors.New("WireGuard peer routes overlap each other")
			}
		}
		candidates = append(candidates, prefix)
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT p.id, p.assigned_address, r.cidr
FROM wireguard_ingress_peers AS p
LEFT JOIN wireguard_ingress_peer_routes AS r ON r.peer_id=p.id AND r.direction='INGRESS'
WHERE p.server_id=? AND p.id<>? AND p.revoked_at IS NULL`, server.ID, peerID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var otherID, otherAddress string
		var route sql.NullString
		if err := rows.Scan(&otherID, &otherAddress, &route); err != nil {
			return err
		}
		other, parseErr := netip.ParseAddr(otherAddress)
		if parseErr != nil {
			return errors.New("stored WireGuard peer address is invalid")
		}
		otherPrefixes := []netip.Prefix{netip.PrefixFrom(other, 32)}
		if route.Valid {
			parsed, parseErr := canonicalIPv4Prefix(route.String)
			if parseErr != nil {
				return errors.New("stored WireGuard peer route is invalid")
			}
			otherPrefixes = append(otherPrefixes, parsed)
		}
		for _, candidate := range candidates {
			for _, existing := range otherPrefixes {
				if prefixesOverlap(candidate, existing) {
					return errors.New("WireGuard peer address or route overlaps another peer")
				}
			}
		}
	}
	return rows.Err()
}

func replacePeerLists(ctx context.Context, transaction *sql.Tx, peerID string, behind, clientAllowed, methods []string, now string) error {
	behind, err := canonicalPrefixes(behind, false)
	if err != nil {
		return err
	}
	clientAllowed, err = canonicalPrefixes(clientAllowed, true)
	if err != nil {
		return err
	}
	for _, table := range []string{"wireguard_ingress_peer_routes", "wireguard_ingress_peer_client_allowed_ips", "wireguard_ingress_peer_access_methods"} {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM "+table+" WHERE peer_id=?", peerID); err != nil {
			return err
		}
	}
	for _, cidr := range behind {
		if _, err := transaction.ExecContext(ctx, "INSERT INTO wireguard_ingress_peer_routes(peer_id,cidr,direction,created_at) VALUES (?,?,'INGRESS',?)", peerID, cidr, now); err != nil {
			return err
		}
	}
	for index, cidr := range clientAllowed {
		if _, err := transaction.ExecContext(ctx, "INSERT INTO wireguard_ingress_peer_client_allowed_ips(peer_id,cidr,priority) VALUES (?,?,?)", peerID, cidr, index+1); err != nil {
			return err
		}
	}
	for index, methodID := range methods {
		if _, err := transaction.ExecContext(ctx, "INSERT INTO wireguard_ingress_peer_access_methods(peer_id,access_method_id,priority) VALUES (?,?,?)", peerID, methodID, index+1); err != nil {
			return errors.New("WireGuard peer references an unknown access method")
		}
	}
	return nil
}

func allocatePeerNumber(ctx context.Context, transaction *sql.Tx) (int64, error) {
	var number int64
	if err := transaction.QueryRowContext(ctx, "SELECT next_peer_number FROM wireguard_ingress_counters WHERE singleton_id=1").Scan(&number); err != nil || number <= 0 {
		return 0, errors.New("WireGuard peer counter is unavailable")
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE wireguard_ingress_counters SET next_peer_number=next_peer_number+1 WHERE singleton_id=1"); err != nil {
		return 0, err
	}
	return number, nil
}

func appendEvent(ctx context.Context, transaction *sql.Tx, now time.Time, eventType string, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES (?,'INFO',?,?)`, now.UTC().Format(time.RFC3339Nano), eventType, string(payload))
	return err
}

func (repository Repository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}

func newID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate WireGuard ingress id failed")
	}
	return prefix + "-" + hex.EncodeToString(value), nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func netipEndpoint(host string, port int) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(address, uint16(port)).String()
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func maskEndpoint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	addressPort, err := netip.ParseAddrPort(value)
	if err == nil && addressPort.Addr().Is4() {
		bytes := addressPort.Addr().As4()
		return fmt.Sprintf("%d.%d.x.x:%d", bytes[0], bytes[1], addressPort.Port())
	}
	if len(value) > 12 {
		return value[:4] + "…" + value[len(value)-4:]
	}
	return "скрыт"
}

// CanonicalPeerNetworks returns all server-side AllowedIPs for a peer.
func CanonicalPeerNetworks(peer Peer) []string {
	result := []string{peer.AssignedAddress + "/32"}
	result = append(result, peer.BehindSubnets...)
	sort.SliceStable(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}
