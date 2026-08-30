package vpsagent

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/wgingress"
)

const managedAdministratorSecretReferenceRoot = "/var/lib/gateway-vpn-vps/agent/secrets/administrators"

type AdminConfigArtifact struct {
	AdminID  string
	Filename string
	Content  []byte
}

// AdminKeyManager is the only unprivileged component allowed to create and
// consume VPS-owned administrator private keys. The database stores only a
// canonical reference and lifecycle state; list/read APIs never expose it.
type AdminKeyManager struct {
	Repository HubRepository
	Keys       wgingress.KeyStore
}

func NewAdminKeyManager(database *sql.DB, stateDirectory string, now func() time.Time) (AdminKeyManager, error) {
	if database == nil || !filepath.IsAbs(stateDirectory) {
		return AdminKeyManager{}, errors.New("absolute VPS Agent state directory and database are required")
	}
	stateDirectory = filepath.Clean(stateDirectory)
	return AdminKeyManager{
		Repository: HubRepository{Database: database, Now: now},
		Keys:       wgingress.KeyStore{Root: filepath.Join(stateDirectory, "secrets", "administrators")},
	}, nil
}

func (manager AdminKeyManager) Available() bool {
	return manager.Repository.Database != nil && filepath.IsAbs(manager.Keys.Root)
}

func (manager AdminKeyManager) Create(ctx context.Context, name, assignedAddress string) (AdminPeer, error) {
	return manager.create(ctx, name, assignedAddress, "", TrustRoutedHub)
}

func (manager AdminKeyManager) Rotate(ctx context.Context, sourceID, name, assignedAddress string) (AdminPeer, error) {
	source, err := manager.Repository.GetAdmin(ctx, strings.TrimSpace(sourceID))
	if err != nil {
		return AdminPeer{}, err
	}
	if source.State == "REVOKED" || source.KeyMode != "MANAGED" {
		return AdminPeer{}, errors.New("only an active managed administrator can be rotated")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = source.Name + " — сменный ключ"
		if len(name) > 128 {
			name = name[:128]
		}
	}
	return manager.create(ctx, name, assignedAddress, source.ID, source.TrustMode)
}

func (manager AdminKeyManager) create(ctx context.Context, name, assignedAddress, rotationSourceID, trustMode string) (AdminPeer, error) {
	if !manager.Available() {
		return AdminPeer{}, errors.New("managed administrator key service is unavailable")
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		return AdminPeer{}, err
	}
	secretID, err := manager.Repository.randomID("managed-admin-", 16)
	if err != nil {
		return AdminPeer{}, err
	}
	physicalPath, err := manager.Keys.PeerPrivatePath(secretID)
	if err != nil {
		return AdminPeer{}, err
	}
	secretReference := managedAdministratorSecretReferenceRoot + "/peers/" + secretID + ".key"
	if err := manager.Keys.Write(physicalPath, pair.Private); err != nil {
		return AdminPeer{}, err
	}
	item, createErr := manager.Repository.CreateAdmin(ctx, AdminCreateInput{
		Name: name, PublicKey: pair.Public, AssignedAddress: assignedAddress, KeyMode: "MANAGED",
		PrivateKeySecretRef: secretReference, RotationSourceID: rotationSourceID, TrustMode: trustMode,
	})
	pair.Private = ""
	if createErr != nil {
		removeErr := manager.Keys.Remove(physicalPath)
		return AdminPeer{}, errors.Join(createErr, removeErr)
	}
	return item, nil
}

// Export consumes a managed private key exactly once. The lifecycle is moved
// to CONSUMED before the protected file is removed and no content is returned
// unless deletion succeeded. A crash after the database commit therefore
// cannot make the private configuration downloadable twice.
func (manager AdminKeyManager) Export(ctx context.Context, id, endpoint string) (AdminConfigArtifact, error) {
	if !manager.Available() {
		return AdminConfigArtifact{}, errors.New("managed administrator key service is unavailable")
	}
	endpoint, err := canonicalEndpoint(endpoint)
	if err != nil {
		return AdminConfigArtifact{}, err
	}
	item, privateReference, err := manager.adminWithPrivateReference(ctx, id)
	if err != nil {
		return AdminConfigArtifact{}, err
	}
	if item.State == "REVOKED" || item.KeyMode != "MANAGED" || item.ConfigState != "AVAILABLE" {
		return AdminConfigArtifact{}, ErrHubConflict
	}
	physicalPath, err := manager.physicalPath(privateReference)
	if err != nil {
		return AdminConfigArtifact{}, err
	}
	privateKey, err := manager.Keys.Read(physicalPath)
	if err != nil {
		return AdminConfigArtifact{}, errors.New("managed administrator private key is unavailable")
	}
	derived, err := wgingress.PublicKey(privateKey)
	if err != nil || derived != item.PublicKey {
		privateKey = ""
		return AdminConfigArtifact{}, errors.New("managed administrator key does not match its public identity")
	}
	identity, err := ReadIdentity(ctx, manager.Repository.Database)
	if err != nil {
		privateKey = ""
		return AdminConfigArtifact{}, err
	}
	allowed, err := manager.allowedIPs(ctx)
	if err != nil {
		privateKey = ""
		return AdminConfigArtifact{}, err
	}
	content := renderAdministratorConfig(privateKey, item.AssignedAddress, identity.PublicKey, endpoint, allowed)
	privateKey = ""
	if len(content) == 0 {
		return AdminConfigArtifact{}, errors.New("managed administrator configuration is incomplete")
	}
	stamp := formatTime(manager.Repository.now())
	result, err := manager.Repository.Database.ExecContext(ctx, `
UPDATE admin_peers
SET config_state='CONSUMED',config_downloaded_at=?,updated_at=?
WHERE id=? AND key_mode='MANAGED' AND state!='REVOKED' AND config_state='AVAILABLE'`, stamp, stamp, item.ID)
	if err != nil {
		return AdminConfigArtifact{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return AdminConfigArtifact{}, ErrHubConflict
	}
	if err := manager.Keys.Remove(physicalPath); err != nil {
		_, _ = manager.Repository.Database.ExecContext(ctx, "UPDATE admin_peers SET config_state='CLEANUP_REQUIRED',updated_at=? WHERE id=?", stamp, item.ID)
		return AdminConfigArtifact{}, errors.New("managed administrator config was consumed but secret cleanup failed")
	}
	return AdminConfigArtifact{AdminID: item.ID, Filename: administratorConfigFilename(item.Name, item.ID), Content: content}, nil
}

func (manager AdminKeyManager) Revoke(ctx context.Context, id string) error {
	item, reference, err := manager.adminWithPrivateReference(ctx, id)
	if err != nil {
		return err
	}
	if err := manager.Repository.RevokeAdmin(ctx, item.ID); err != nil {
		return err
	}
	if reference == "" {
		return nil
	}
	physicalPath, err := manager.physicalPath(reference)
	if err != nil {
		return err
	}
	if err := manager.Keys.Remove(physicalPath); err != nil {
		return err
	}
	_, err = manager.Repository.Database.ExecContext(ctx, "UPDATE admin_peers SET config_state='CONSUMED' WHERE id=? AND config_state='CLEANUP_REQUIRED'", item.ID)
	return err
}

func (manager AdminKeyManager) CleanupConsumed(ctx context.Context) error {
	if !manager.Available() {
		return errors.New("managed administrator key service is unavailable")
	}
	rows, err := manager.Repository.Database.QueryContext(ctx, `
SELECT id,private_key_secret_ref FROM admin_peers
WHERE key_mode='MANAGED' AND private_key_secret_ref IS NOT NULL
  AND (state='REVOKED' OR config_state IN ('CONSUMED','CLEANUP_REQUIRED'))`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type pending struct{ id, reference string }
	items := []pending{}
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.reference); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		physicalPath, err := manager.physicalPath(item.reference)
		if err != nil {
			return err
		}
		if err := manager.Keys.Remove(physicalPath); err != nil {
			return err
		}
		if _, err := manager.Repository.Database.ExecContext(ctx, "UPDATE admin_peers SET config_state='CONSUMED' WHERE id=? AND config_state='CLEANUP_REQUIRED'", item.id); err != nil {
			return err
		}
	}
	return nil
}

func (manager AdminKeyManager) adminWithPrivateReference(ctx context.Context, id string) (AdminPeer, string, error) {
	id = strings.TrimSpace(id)
	if !hubIdentifierPattern.MatchString(id) {
		return AdminPeer{}, "", errors.New("administrator id is invalid")
	}
	item, err := manager.Repository.GetAdmin(ctx, id)
	if err != nil {
		return AdminPeer{}, "", err
	}
	var reference sql.NullString
	if err := manager.Repository.Database.QueryRowContext(ctx, "SELECT private_key_secret_ref FROM admin_peers WHERE id=?", id).Scan(&reference); err != nil {
		return AdminPeer{}, "", err
	}
	if item.KeyMode == "MANAGED" && (!reference.Valid || reference.String == "") {
		return AdminPeer{}, "", errors.New("managed administrator secret reference is missing")
	}
	return item, reference.String, nil
}

func (manager AdminKeyManager) physicalPath(reference string) (string, error) {
	prefix := managedAdministratorSecretReferenceRoot + "/"
	if !strings.HasPrefix(reference, prefix) {
		return "", errors.New("managed administrator secret reference is outside its fixed root")
	}
	relative := strings.TrimPrefix(reference, prefix)
	if relative == "" || strings.Contains(relative, "\\") || filepath.ToSlash(filepath.Clean(relative)) != relative || strings.HasPrefix(relative, "../") {
		return "", errors.New("managed administrator secret reference is unsafe")
	}
	physical := filepath.Join(manager.Keys.Root, filepath.FromSlash(relative))
	if _, err := filepath.Rel(filepath.Clean(manager.Keys.Root), physical); err != nil {
		return "", errors.New("managed administrator secret path is invalid")
	}
	return physical, nil
}

func (manager AdminKeyManager) allowedIPs(ctx context.Context) ([]string, error) {
	values := map[string]netip.Prefix{}
	add := func(raw string) error {
		raw = strings.TrimSpace(raw)
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			address, addressErr := netip.ParseAddr(raw)
			if addressErr != nil || !address.Is4() || !address.IsPrivate() {
				return errors.New("stored administrator destination is invalid")
			}
			prefix = netip.PrefixFrom(address, 32)
		}
		if !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 16 {
			return errors.New("stored administrator destination is unsafe")
		}
		values[prefix.String()] = prefix
		return nil
	}
	if err := add(VPSHubAddress + "/32"); err != nil {
		return nil, err
	}
	rows, err := manager.Repository.Database.QueryContext(ctx, `
SELECT assigned_address,remote_address FROM gateway_peers WHERE state!='REVOKED' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var local, remote string
		if err := rows.Scan(&local, &remote); err != nil {
			rows.Close()
			return nil, err
		}
		if err := add(local); err != nil {
			rows.Close()
			return nil, err
		}
		if err := add(remote); err != nil {
			rows.Close()
			return nil, err
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Client routing may include every published alias on this VPS. Access is
	// still default-deny and enforced by the versioned server/Gateway ACL, so a
	// later grant does not require the private config to be downloaded again.
	rows, err = manager.Repository.Database.QueryContext(ctx, `
SELECT DISTINCT published_alias
FROM resource_publications
WHERE enabled=1 AND state!='DISABLED'
ORDER BY published_alias`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		if err := add(value); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("administrator has no routable VPS or Gateway destination")
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func renderAdministratorConfig(privateKey, assignedAddress, serverPublicKey, endpoint string, allowed []string) []byte {
	if !wgingress.ValidKey(privateKey) || !wgingress.ValidKey(serverPublicKey) || len(allowed) == 0 {
		return nil
	}
	address, err := canonicalPrivateAddress(assignedAddress)
	if err != nil {
		return nil
	}
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = ")
	builder.WriteString(privateKey)
	builder.WriteString("\nAddress = ")
	builder.WriteString(address.String())
	builder.WriteString("/32\n\n[Peer]\nPublicKey = ")
	builder.WriteString(serverPublicKey)
	builder.WriteString("\nEndpoint = ")
	builder.WriteString(endpoint)
	builder.WriteString("\nAllowedIPs = ")
	builder.WriteString(strings.Join(allowed, ", "))
	builder.WriteString("\nPersistentKeepalive = 25\n")
	return []byte(builder.String())
}

func administratorConfigFilename(name, id string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var builder strings.Builder
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else if builder.Len() > 0 && builder.String()[builder.Len()-1] != '-' {
			builder.WriteByte('-')
		}
		if builder.Len() >= 48 {
			break
		}
	}
	value := strings.Trim(builder.String(), "-")
	if value == "" {
		value = "administrator-" + strings.TrimPrefix(id, "admin-")
	}
	return value + ".conf"
}
