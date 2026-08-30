package vpsagent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/wgingress"
)

const (
	maximumGateways    = 256
	maximumAdmins      = 256
	maximumResources   = 1024
	maximumACLGrants   = 4096
	maximumInvitations = 64
)

var (
	ErrHubNotFound       = errors.New("VPS Hub object not found")
	ErrHubConflict       = errors.New("VPS Hub object conflicts with existing state")
	ErrPairingRejected   = errors.New("pairing invitation rejected")
	hubIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
	hostnamePattern      = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

type HubRepository struct {
	Database           *sql.DB
	Now                func() time.Time
	Random             io.Reader
	HostApplyAvailable bool
}

type PairingCreateInput struct {
	GatewayName string        `json:"gateway_name"`
	Endpoint    string        `json:"endpoint"`
	Subnet      string        `json:"assigned_subnet"`
	ExpiresIn   time.Duration `json:"-"`
}

type PairingBundle struct {
	InvitationID        string `json:"invitation_id"`
	Token               string `json:"token,omitempty"`
	VPSID               string `json:"vps_id"`
	VPSName             string `json:"vps_name"`
	Endpoint            string `json:"endpoint"`
	VPSPublicKey        string `json:"vps_public_key"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	AssignedSubnet      string `json:"assigned_subnet"`
	VPSAddress          string `json:"vps_address"`
	GatewayAddress      string `json:"gateway_address"`
	GatewayName         string `json:"gateway_name"`
	State               string `json:"state"`
	AttemptCount        int    `json:"attempt_count"`
	ExpiresAt           string `json:"expires_at"`
	CreatedAt           string `json:"created_at"`
	ConsumedPeerID      string `json:"consumed_peer_id,omitempty"`
}

type PairingCompletion struct {
	InvitationID string `json:"invitation_id"`
	Token        string `json:"token"`
	SiteID       string `json:"site_id"`
	DisplayName  string `json:"display_name"`
	PublicKey    string `json:"public_key"`
	WebUIURL     string `json:"webui_url"`
}

type GatewayPeer struct {
	ID                string `json:"id"`
	SiteID            string `json:"site_id"`
	DisplayName       string `json:"display_name"`
	PublicKey         string `json:"public_key"`
	AssignedSubnet    string `json:"assigned_subnet"`
	AssignedAddress   string `json:"assigned_address"`
	RemoteAddress     string `json:"remote_address"`
	Endpoint          string `json:"endpoint"`
	WebUIURL          string `json:"webui_url"`
	State             string `json:"state"`
	DesiredGeneration int64  `json:"desired_generation"`
	AppliedGeneration int64  `json:"applied_generation"`
	LatestHandshakeAt string `json:"latest_handshake_at,omitempty"`
	RXBytes           int64  `json:"rx_bytes"`
	TXBytes           int64  `json:"tx_bytes"`
	RTTMilliseconds   *int64 `json:"rtt_ms,omitempty"`
	StatusReason      string `json:"status_reason"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type AdminCreateInput struct {
	Name                string `json:"name"`
	PublicKey           string `json:"public_key"`
	AssignedAddress     string `json:"assigned_address"`
	KeyMode             string `json:"key_mode"`
	PrivateKeySecretRef string `json:"-"`
	RotationSourceID    string `json:"-"`
}

type AdminPeer struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	PublicKey          string `json:"public_key"`
	AssignedAddress    string `json:"assigned_address"`
	KeyMode            string `json:"key_mode"`
	State              string `json:"state"`
	DesiredGeneration  int64  `json:"desired_generation"`
	AppliedGeneration  int64  `json:"applied_generation"`
	LatestHandshakeAt  string `json:"latest_handshake_at,omitempty"`
	RXBytes            int64  `json:"rx_bytes"`
	TXBytes            int64  `json:"tx_bytes"`
	StatusReason       string `json:"status_reason"`
	ConfigState        string `json:"config_state"`
	ConfigDownloadedAt string `json:"config_downloaded_at,omitempty"`
	RotationSourceID   string `json:"rotation_source_id,omitempty"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type ResourceInput struct {
	GatewayPeerID             string `json:"gateway_peer_id"`
	ResourceID                string `json:"resource_id"`
	DisplayName               string `json:"display_name"`
	ResourceKind              string `json:"resource_kind"`
	LocalDestination          string `json:"local_destination"`
	PublishedAlias            string `json:"published_alias"`
	AccessProfile             string `json:"access_profile"`
	Enabled                   bool   `json:"enabled"`
	AdvancedScopeAcknowledged bool   `json:"advanced_scope_acknowledged"`
}

type ResourcePublication struct {
	ID                        string `json:"id"`
	GatewayPeerID             string `json:"gateway_peer_id"`
	ResourceID                string `json:"resource_id"`
	DisplayName               string `json:"display_name"`
	ResourceKind              string `json:"resource_kind"`
	LocalDestination          string `json:"local_destination"`
	PublishedAlias            string `json:"published_alias"`
	AccessProfile             string `json:"access_profile"`
	Enabled                   bool   `json:"enabled"`
	AdvancedScopeAcknowledged bool   `json:"advanced_scope_acknowledged"`
	Health                    string `json:"health"`
	StatusReason              string `json:"status_reason"`
	State                     string `json:"state"`
	DesiredGeneration         int64  `json:"desired_generation"`
	AppliedGeneration         int64  `json:"applied_generation"`
	CreatedAt                 string `json:"created_at"`
	UpdatedAt                 string `json:"updated_at"`
}

type ACLInput struct {
	AdminPeerID   string `json:"admin_peer_id"`
	PublicationID string `json:"publication_id"`
	Protocol      string `json:"protocol"`
	PortStart     int    `json:"port_start"`
	PortEnd       int    `json:"port_end"`
}

type ACLGrant struct {
	ID            string `json:"id"`
	AdminPeerID   string `json:"admin_peer_id"`
	PublicationID string `json:"publication_id"`
	Protocol      string `json:"protocol"`
	PortStart     int    `json:"port_start"`
	PortEnd       int    `json:"port_end"`
	Generation    int64  `json:"generation"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type HubOverview struct {
	Identity           Identity         `json:"identity"`
	SchemaVersion      int64            `json:"schema_version"`
	Gateways           map[string]int64 `json:"gateways"`
	Administrators     map[string]int64 `json:"administrators"`
	Resources          map[string]int64 `json:"resources"`
	ACLGrants          int64            `json:"acl_grants"`
	OpenInvitations    int64            `json:"open_invitations"`
	DesiredGeneration  int64            `json:"desired_generation"`
	AppliedGeneration  int64            `json:"applied_generation"`
	FabricState        string           `json:"fabric_state"`
	HostApplyAvailable bool             `json:"host_apply_available"`
}

type ControllerComponent struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Reason    string `json:"reason"`
	OwnedOnly bool   `json:"owned_only"`
}

type ControllerHealth struct {
	State      string                `json:"state"`
	CheckedAt  string                `json:"checked_at"`
	Components []ControllerComponent `json:"components"`
}

type pairingPayload struct {
	GatewayName    string `json:"gateway_name"`
	Endpoint       string `json:"endpoint"`
	AssignedSubnet string `json:"assigned_subnet"`
	VPSAddress     string `json:"vps_address"`
	GatewayAddress string `json:"gateway_address"`
}

func (repository HubRepository) CreatePairing(ctx context.Context, input PairingCreateInput) (PairingBundle, error) {
	if repository.Database == nil {
		return PairingBundle{}, errors.New("VPS Hub database is required")
	}
	input.GatewayName = strings.TrimSpace(input.GatewayName)
	endpoint, err := canonicalEndpoint(input.Endpoint)
	if err != nil || input.GatewayName == "" || len(input.GatewayName) > 128 {
		return PairingBundle{}, errors.New("valid Gateway name and VPS endpoint are required")
	}
	prefix, err := canonicalPrivatePrefix(input.Subnet, 30, 30)
	if err != nil {
		return PairingBundle{}, errors.New("pairing subnet must be a canonical private IPv4 /30")
	}
	vpsAddress := prefix.Addr().Next()
	gatewayAddress := vpsAddress.Next()
	if !prefix.Contains(gatewayAddress) {
		return PairingBundle{}, errors.New("pairing subnet has no usable addresses")
	}
	expiresIn := input.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 30 * time.Minute
	}
	if expiresIn < 5*time.Minute || expiresIn > 24*time.Hour {
		return PairingBundle{}, errors.New("pairing expiry must be between 5 minutes and 24 hours")
	}
	id, err := repository.randomID("pairing-", 16)
	if err != nil {
		return PairingBundle{}, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(repository.randomReader(), tokenBytes); err != nil {
		return PairingBundle{}, errors.New("generate pairing token failed")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256([]byte(token))
	for index := range tokenBytes {
		tokenBytes[index] = 0
	}
	payload := pairingPayload{GatewayName: input.GatewayName, Endpoint: endpoint, AssignedSubnet: prefix.String(), VPSAddress: vpsAddress.String(), GatewayAddress: gatewayAddress.String()}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return PairingBundle{}, err
	}
	identity, err := ReadIdentity(ctx, repository.Database)
	if err != nil {
		return PairingBundle{}, err
	}
	now := repository.now()
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return PairingBundle{}, err
	}
	defer transaction.Rollback()
	var openInvitations int64
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM pairing_invitations WHERE state='OPEN'").Scan(&openInvitations); err != nil {
		return PairingBundle{}, err
	}
	if openInvitations >= maximumInvitations {
		return PairingBundle{}, errors.New("VPS Hub open invitation limit is reached")
	}
	if err := ensurePrefixAvailable(ctx, transaction, prefix, ""); err != nil {
		return PairingBundle{}, err
	}
	stamp, expiry := formatTime(now), formatTime(now.Add(expiresIn))
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO pairing_invitations(id,token_sha256,state,attempt_count,expires_at,created_at,updated_at,payload_json)
VALUES(?,?,'OPEN',0,?,?,?,?)`, id, hex.EncodeToString(digest[:]), expiry, stamp, stamp, string(payloadJSON)); err != nil {
		return PairingBundle{}, fmt.Errorf("store pairing invitation: %w", err)
	}
	prefixID, err := repository.randomID("prefix-", 16)
	if err != nil {
		return PairingBundle{}, err
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO prefix_allocations(id,owner_kind,owner_id,prefix,state,created_at,updated_at)
VALUES(?,'GATEWAY_LINK',?,?,'ALLOCATED',?,?)`, prefixID, id, prefix.String(), stamp, stamp); err != nil {
		return PairingBundle{}, fmt.Errorf("reserve pairing prefix: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return PairingBundle{}, err
	}
	return PairingBundle{
		InvitationID: id, Token: token, VPSID: identity.VPSID, VPSName: identity.DisplayName,
		Endpoint: endpoint, VPSPublicKey: identity.PublicKey, IdentityFingerprint: identity.IdentityFingerprint,
		AssignedSubnet: prefix.String(), VPSAddress: vpsAddress.String(), GatewayAddress: gatewayAddress.String(),
		GatewayName: input.GatewayName, State: "OPEN", ExpiresAt: expiry, CreatedAt: stamp,
	}, nil
}

func (repository HubRepository) ListPairings(ctx context.Context) ([]PairingBundle, error) {
	identity, err := ReadIdentity(ctx, repository.Database)
	if err != nil {
		return nil, err
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT id,state,attempt_count,expires_at,created_at,payload_json,consumed_peer_id
FROM pairing_invitations ORDER BY created_at DESC LIMIT ?`, maximumInvitations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []PairingBundle{}
	for rows.Next() {
		var item PairingBundle
		var payloadJSON string
		if err := rows.Scan(&item.InvitationID, &item.State, &item.AttemptCount, &item.ExpiresAt, &item.CreatedAt, &payloadJSON, &item.ConsumedPeerID); err != nil {
			return nil, err
		}
		var payload pairingPayload
		if json.Unmarshal([]byte(payloadJSON), &payload) != nil {
			return nil, errors.New("stored pairing payload is invalid")
		}
		item.VPSID, item.VPSName, item.VPSPublicKey, item.IdentityFingerprint = identity.VPSID, identity.DisplayName, identity.PublicKey, identity.IdentityFingerprint
		item.Endpoint, item.AssignedSubnet, item.VPSAddress, item.GatewayAddress, item.GatewayName = payload.Endpoint, payload.AssignedSubnet, payload.VPSAddress, payload.GatewayAddress, payload.GatewayName
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository HubRepository) CompletePairing(ctx context.Context, completion PairingCompletion) (GatewayPeer, error) {
	completion.InvitationID = strings.TrimSpace(completion.InvitationID)
	completion.SiteID = strings.TrimSpace(completion.SiteID)
	completion.DisplayName = strings.TrimSpace(completion.DisplayName)
	completion.WebUIURL = strings.TrimSpace(completion.WebUIURL)
	if !hubIdentifierPattern.MatchString(completion.InvitationID) || !hubIdentifierPattern.MatchString(completion.SiteID) || completion.DisplayName == "" || len(completion.DisplayName) > 128 || !wgingress.ValidKey(completion.PublicKey) {
		return GatewayPeer{}, errors.New("valid pairing completion identity is required")
	}
	webUIURL, err := canonicalWebUIURL(completion.WebUIURL)
	if err != nil {
		return GatewayPeer{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return GatewayPeer{}, err
	}
	defer transaction.Rollback()
	var storedDigest, state, expiresAt, payloadJSON, consumedPeerID string
	var attempts int
	err = transaction.QueryRowContext(ctx, `
SELECT token_sha256,state,attempt_count,expires_at,payload_json,consumed_peer_id
FROM pairing_invitations WHERE id=?`, completion.InvitationID).Scan(&storedDigest, &state, &attempts, &expiresAt, &payloadJSON, &consumedPeerID)
	if errors.Is(err, sql.ErrNoRows) {
		return GatewayPeer{}, ErrHubNotFound
	}
	if err != nil {
		return GatewayPeer{}, err
	}
	if state != "OPEN" {
		return GatewayPeer{}, ErrPairingRejected
	}
	now := repository.now()
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || !expiry.After(now) {
		_, _ = transaction.ExecContext(ctx, "UPDATE pairing_invitations SET state='EXPIRED',updated_at=? WHERE id=?", formatTime(now), completion.InvitationID)
		_, _ = transaction.ExecContext(ctx, "UPDATE prefix_allocations SET state='RELEASED',updated_at=? WHERE owner_kind='GATEWAY_LINK' AND owner_id=?", formatTime(now), completion.InvitationID)
		_ = transaction.Commit()
		return GatewayPeer{}, ErrPairingRejected
	}
	provided := sha256.Sum256([]byte(completion.Token))
	stored, decodeErr := hex.DecodeString(storedDigest)
	validToken := decodeErr == nil && len(stored) == len(provided) && subtle.ConstantTimeCompare(stored, provided[:]) == 1
	if !validToken {
		attempts++
		newState := "OPEN"
		if attempts >= 8 {
			newState = "REJECTED"
		}
		if _, err := transaction.ExecContext(ctx, "UPDATE pairing_invitations SET attempt_count=?,state=?,updated_at=? WHERE id=?", attempts, newState, formatTime(now), completion.InvitationID); err != nil {
			return GatewayPeer{}, err
		}
		if newState == "REJECTED" {
			_, _ = transaction.ExecContext(ctx, "UPDATE prefix_allocations SET state='RELEASED',updated_at=? WHERE owner_kind='GATEWAY_LINK' AND owner_id=?", formatTime(now), completion.InvitationID)
		}
		if err := transaction.Commit(); err != nil {
			return GatewayPeer{}, err
		}
		return GatewayPeer{}, ErrPairingRejected
	}
	var payload pairingPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return GatewayPeer{}, errors.New("stored pairing payload is invalid")
	}
	if err := enforceCount(ctx, transaction, "gateway_peers", maximumGateways); err != nil {
		return GatewayPeer{}, err
	}
	if err := ensurePeerKeyAvailable(ctx, transaction, completion.PublicKey); err != nil {
		return GatewayPeer{}, err
	}
	peerID, err := repository.randomID("gateway-", 16)
	if err != nil {
		return GatewayPeer{}, err
	}
	stamp := formatTime(now)
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO gateway_peers(
 id,site_id,display_name,public_key,assigned_subnet,assigned_address,remote_address,
 state,desired_generation,applied_generation,created_at,updated_at,endpoint,webui_url,status_reason
) VALUES(?,?,?,?,?,?,?,'PAIRING',1,0,?,?,?,?,?)`, peerID, completion.SiteID, completion.DisplayName, completion.PublicKey,
		payload.AssignedSubnet, payload.GatewayAddress, payload.VPSAddress, stamp, stamp, payload.Endpoint, webUIURL, "AWAITING_HOST_APPLY"); err != nil {
		return GatewayPeer{}, fmt.Errorf("create Gateway peer: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE prefix_allocations SET owner_id=?,updated_at=?
WHERE owner_kind='GATEWAY_LINK' AND owner_id=? AND prefix=? AND state='ALLOCATED'`, peerID, stamp, completion.InvitationID, payload.AssignedSubnet)
	if err != nil {
		return GatewayPeer{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return GatewayPeer{}, errors.New("pairing prefix reservation is missing")
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE pairing_invitations SET state='CONSUMED',consumed_peer_id=?,updated_at=? WHERE id=? AND state='OPEN'`, peerID, stamp, completion.InvitationID); err != nil {
		return GatewayPeer{}, err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return GatewayPeer{}, err
	}
	if err := transaction.Commit(); err != nil {
		return GatewayPeer{}, err
	}
	return repository.GetGateway(ctx, peerID)
}

func (repository HubRepository) RejectPairing(ctx context.Context, id string) error {
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := formatTime(repository.now())
	result, err := transaction.ExecContext(ctx, "UPDATE pairing_invitations SET state='REJECTED',updated_at=? WHERE id=? AND state='OPEN'", stamp, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrHubNotFound
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE prefix_allocations SET state='RELEASED',updated_at=? WHERE owner_kind='GATEWAY_LINK' AND owner_id=?", stamp, id); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) ListGateways(ctx context.Context) ([]GatewayPeer, error) {
	rows, err := repository.Database.QueryContext(ctx, gatewaySelect+" ORDER BY created_at LIMIT ?", maximumGateways)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GatewayPeer{}
	for rows.Next() {
		item, err := scanGateway(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository HubRepository) GetGateway(ctx context.Context, id string) (GatewayPeer, error) {
	item, err := scanGateway(repository.Database.QueryRowContext(ctx, gatewaySelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return GatewayPeer{}, ErrHubNotFound
	}
	return item, err
}

func (repository HubRepository) RevokeGateway(ctx context.Context, id string) error {
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := formatTime(repository.now())
	var state string
	if err := transaction.QueryRowContext(ctx, "SELECT state FROM gateway_peers WHERE id=?", id).Scan(&state); errors.Is(err, sql.ErrNoRows) {
		return ErrHubNotFound
	} else if err != nil {
		return err
	}
	if state == "REVOKED" {
		return nil
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM acl_grants WHERE publication_id IN (SELECT id FROM resource_publications WHERE gateway_peer_id=?)", id); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE resource_publications SET enabled=0,state='DISABLED',desired_generation=desired_generation+1,updated_at=? WHERE gateway_peer_id=?", stamp, id); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE gateway_peers SET state='REVOKED',desired_generation=desired_generation+1,status_reason='REVOKED_BY_ADMIN',updated_at=? WHERE id=?", stamp, id); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE prefix_allocations SET state='RELEASED',updated_at=? WHERE owner_kind='GATEWAY_LINK' AND owner_id=?", stamp, id); err != nil {
		return err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) CreateAdmin(ctx context.Context, input AdminCreateInput) (AdminPeer, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.KeyMode = strings.ToUpper(strings.TrimSpace(input.KeyMode))
	input.RotationSourceID = strings.TrimSpace(input.RotationSourceID)
	if input.Name == "" || len(input.Name) > 128 || !wgingress.ValidKey(input.PublicKey) || input.KeyMode != "MANAGED" && input.KeyMode != "EXTERNAL" {
		return AdminPeer{}, errors.New("valid administrator name, key and key mode are required")
	}
	if input.KeyMode == "MANAGED" && !validSecretRef(input.PrivateKeySecretRef) || input.KeyMode == "EXTERNAL" && input.PrivateKeySecretRef != "" {
		return AdminPeer{}, errors.New("administrator private-key reference does not match key mode")
	}
	address, err := canonicalPrivateAddress(input.AssignedAddress)
	if err != nil {
		return AdminPeer{}, err
	}
	id, err := repository.randomID("admin-", 16)
	if err != nil {
		return AdminPeer{}, err
	}
	prefixID, err := repository.randomID("prefix-", 16)
	if err != nil {
		return AdminPeer{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AdminPeer{}, err
	}
	defer transaction.Rollback()
	if err := enforceCount(ctx, transaction, "admin_peers", maximumAdmins); err != nil {
		return AdminPeer{}, err
	}
	if err := ensurePeerKeyAvailable(ctx, transaction, input.PublicKey); err != nil {
		return AdminPeer{}, err
	}
	if input.RotationSourceID != "" {
		var sourceState, sourceMode string
		if !hubIdentifierPattern.MatchString(input.RotationSourceID) {
			return AdminPeer{}, errors.New("administrator rotation source id is invalid")
		}
		if err := transaction.QueryRowContext(ctx, "SELECT state,key_mode FROM admin_peers WHERE id=?", input.RotationSourceID).Scan(&sourceState, &sourceMode); errors.Is(err, sql.ErrNoRows) {
			return AdminPeer{}, ErrHubNotFound
		} else if err != nil {
			return AdminPeer{}, err
		} else if sourceState == "REVOKED" || sourceMode != "MANAGED" || input.KeyMode != "MANAGED" {
			return AdminPeer{}, errors.New("administrator rotation requires an active managed source and replacement")
		}
	}
	prefix := netip.PrefixFrom(address, 32)
	if err := ensurePrefixAvailable(ctx, transaction, prefix, ""); err != nil {
		return AdminPeer{}, err
	}
	stamp := formatTime(repository.now())
	configState := "NOT_APPLICABLE"
	if input.KeyMode == "MANAGED" {
		configState = "AVAILABLE"
	}
	var privateRef any
	if input.PrivateKeySecretRef != "" {
		privateRef = input.PrivateKeySecretRef
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO admin_peers(
 id,name,public_key,private_key_secret_ref,assigned_address,state,desired_generation,applied_generation,
 created_at,updated_at,key_mode,status_reason,config_state,rotation_source_id
)
VALUES(?,?,?,?,?,'CONFIGURED',1,0,?,?,?,'AWAITING_HOST_APPLY',?,?)`, id, input.Name, input.PublicKey, privateRef, address.String(), stamp, stamp, input.KeyMode, configState, input.RotationSourceID); err != nil {
		return AdminPeer{}, fmt.Errorf("create administrator peer: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO prefix_allocations(id,owner_kind,owner_id,prefix,state,created_at,updated_at)
VALUES(?,'ADMIN_PEER',?,?,'ALLOCATED',?,?)`, prefixID, id, prefix.String(), stamp, stamp); err != nil {
		return AdminPeer{}, err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return AdminPeer{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AdminPeer{}, err
	}
	return repository.GetAdmin(ctx, id)
}

func (repository HubRepository) ListAdmins(ctx context.Context) ([]AdminPeer, error) {
	rows, err := repository.Database.QueryContext(ctx, adminSelect+" ORDER BY created_at LIMIT ?", maximumAdmins)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AdminPeer{}
	for rows.Next() {
		item, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository HubRepository) GetAdmin(ctx context.Context, id string) (AdminPeer, error) {
	item, err := scanAdmin(repository.Database.QueryRowContext(ctx, adminSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return AdminPeer{}, ErrHubNotFound
	}
	return item, err
}

func (repository HubRepository) RevokeAdmin(ctx context.Context, id string) error {
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := formatTime(repository.now())
	var state string
	if err := transaction.QueryRowContext(ctx, "SELECT state FROM admin_peers WHERE id=?", id).Scan(&state); errors.Is(err, sql.ErrNoRows) {
		return ErrHubNotFound
	} else if err != nil {
		return err
	}
	if state == "REVOKED" {
		return nil
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM acl_grants WHERE admin_peer_id=?", id); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE admin_peers
SET state='REVOKED',desired_generation=desired_generation+1,status_reason='REVOKED_BY_ADMIN',
    config_state=CASE WHEN key_mode='MANAGED' AND config_state='AVAILABLE' THEN 'CLEANUP_REQUIRED' ELSE config_state END,
    updated_at=?
WHERE id=?`, stamp, id); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE prefix_allocations SET state='RELEASED',updated_at=? WHERE owner_kind='ADMIN_PEER' AND owner_id=?", stamp, id); err != nil {
		return err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) CreateResource(ctx context.Context, input ResourceInput) (ResourcePublication, error) {
	canonical, localPrefix, aliasPrefix, err := validateResourceInput(input)
	if err != nil {
		return ResourcePublication{}, err
	}
	id, err := repository.randomID("publication-", 16)
	if err != nil {
		return ResourcePublication{}, err
	}
	prefixID, err := repository.randomID("prefix-", 16)
	if err != nil {
		return ResourcePublication{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ResourcePublication{}, err
	}
	defer transaction.Rollback()
	if err := enforceCount(ctx, transaction, "resource_publications", maximumResources); err != nil {
		return ResourcePublication{}, err
	}
	var peerState string
	if err := transaction.QueryRowContext(ctx, "SELECT state FROM gateway_peers WHERE id=?", canonical.GatewayPeerID).Scan(&peerState); errors.Is(err, sql.ErrNoRows) {
		return ResourcePublication{}, ErrHubNotFound
	} else if err != nil || peerState == "REVOKED" {
		return ResourcePublication{}, errors.New("resource Gateway peer is not available")
	}
	_ = localPrefix
	if err := ensurePrefixAvailable(ctx, transaction, aliasPrefix, ""); err != nil {
		return ResourcePublication{}, err
	}
	stamp := formatTime(repository.now())
	state := "PENDING"
	if !canonical.Enabled {
		state = "DISABLED"
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO resource_publications(
 id,gateway_peer_id,resource_id,resource_kind,local_destination,published_alias,state,
 desired_generation,applied_generation,created_at,updated_at,display_name,access_profile,
 enabled,advanced_scope_acknowledged,health,status_reason
) VALUES(?,?,?,?,?,?,?,1,0,?,?,?,?,?,?,'UNKNOWN','AWAITING_GATEWAY_AND_HOST_APPLY')`, id, canonical.GatewayPeerID, canonical.ResourceID,
		canonical.ResourceKind, canonical.LocalDestination, canonical.PublishedAlias, state, stamp, stamp, canonical.DisplayName,
		canonical.AccessProfile, boolInt(canonical.Enabled), boolInt(canonical.AdvancedScopeAcknowledged)); err != nil {
		return ResourcePublication{}, fmt.Errorf("create resource publication: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO prefix_allocations(id,owner_kind,owner_id,prefix,state,created_at,updated_at)
VALUES(?,'RESOURCE_ALIAS',?,?,'ALLOCATED',?,?)`, prefixID, id, aliasPrefix.String(), stamp, stamp); err != nil {
		return ResourcePublication{}, err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return ResourcePublication{}, err
	}
	if err := transaction.Commit(); err != nil {
		return ResourcePublication{}, err
	}
	return repository.GetResource(ctx, id)
}

func (repository HubRepository) UpdateResource(ctx context.Context, id string, input ResourceInput) (ResourcePublication, error) {
	canonical, _, aliasPrefix, err := validateResourceInput(input)
	if err != nil {
		return ResourcePublication{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ResourcePublication{}, err
	}
	defer transaction.Rollback()
	var existingGateway, existingResource string
	if err := transaction.QueryRowContext(ctx, "SELECT gateway_peer_id,resource_id FROM resource_publications WHERE id=?", id).Scan(&existingGateway, &existingResource); errors.Is(err, sql.ErrNoRows) {
		return ResourcePublication{}, ErrHubNotFound
	} else if err != nil {
		return ResourcePublication{}, err
	}
	if canonical.GatewayPeerID != existingGateway || canonical.ResourceID != existingResource {
		return ResourcePublication{}, errors.New("resource identity and Gateway binding are immutable")
	}
	if err := ensurePrefixAvailable(ctx, transaction, aliasPrefix, id); err != nil {
		return ResourcePublication{}, err
	}
	stamp := formatTime(repository.now())
	state := "PENDING"
	if !canonical.Enabled {
		state = "DISABLED"
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE resource_publications SET display_name=?,resource_kind=?,local_destination=?,published_alias=?,access_profile=?,
 enabled=?,advanced_scope_acknowledged=?,state=?,health='UNKNOWN',status_reason='AWAITING_GATEWAY_AND_HOST_APPLY',
 desired_generation=desired_generation+1,updated_at=? WHERE id=?`, canonical.DisplayName, canonical.ResourceKind,
		canonical.LocalDestination, canonical.PublishedAlias, canonical.AccessProfile, boolInt(canonical.Enabled),
		boolInt(canonical.AdvancedScopeAcknowledged), state, stamp, id); err != nil {
		return ResourcePublication{}, err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE prefix_allocations SET prefix=?,state='ALLOCATED',updated_at=? WHERE owner_kind='RESOURCE_ALIAS' AND owner_id=?", aliasPrefix.String(), stamp, id); err != nil {
		return ResourcePublication{}, err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return ResourcePublication{}, err
	}
	if err := transaction.Commit(); err != nil {
		return ResourcePublication{}, err
	}
	return repository.GetResource(ctx, id)
}

func (repository HubRepository) DeleteResource(ctx context.Context, id string) error {
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := formatTime(repository.now())
	if _, err := transaction.ExecContext(ctx, "DELETE FROM acl_grants WHERE publication_id=?", id); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM resource_publications WHERE id=?", id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrHubNotFound
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE prefix_allocations SET state='RELEASED',updated_at=? WHERE owner_kind='RESOURCE_ALIAS' AND owner_id=?", stamp, id); err != nil {
		return err
	}
	if _, err := bumpFabricGeneration(ctx, transaction, stamp); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) ListResources(ctx context.Context) ([]ResourcePublication, error) {
	rows, err := repository.Database.QueryContext(ctx, resourceSelect+" ORDER BY created_at LIMIT ?", maximumResources)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ResourcePublication{}
	for rows.Next() {
		item, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository HubRepository) GetResource(ctx context.Context, id string) (ResourcePublication, error) {
	item, err := scanResource(repository.Database.QueryRowContext(ctx, resourceSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ResourcePublication{}, ErrHubNotFound
	}
	return item, err
}

func (repository HubRepository) CreateACL(ctx context.Context, input ACLInput) (ACLGrant, error) {
	input.Protocol = strings.ToUpper(strings.TrimSpace(input.Protocol))
	if !hubIdentifierPattern.MatchString(input.AdminPeerID) || !hubIdentifierPattern.MatchString(input.PublicationID) || !validPorts(input.Protocol, input.PortStart, input.PortEnd) {
		return ACLGrant{}, errors.New("ACL requires a concrete administrator, resource, protocol and bounded ports")
	}
	id, err := repository.randomID("acl-", 16)
	if err != nil {
		return ACLGrant{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return ACLGrant{}, err
	}
	defer transaction.Rollback()
	if err := enforceCount(ctx, transaction, "acl_grants", maximumACLGrants); err != nil {
		return ACLGrant{}, err
	}
	var adminState, publicationState string
	if err := transaction.QueryRowContext(ctx, "SELECT state FROM admin_peers WHERE id=?", input.AdminPeerID).Scan(&adminState); err != nil || adminState == "REVOKED" {
		return ACLGrant{}, errors.New("ACL administrator is unavailable")
	}
	if err := transaction.QueryRowContext(ctx, "SELECT state FROM resource_publications WHERE id=?", input.PublicationID).Scan(&publicationState); err != nil || publicationState == "DISABLED" {
		return ACLGrant{}, errors.New("ACL resource publication is unavailable")
	}
	stamp := formatTime(repository.now())
	generation, err := bumpFabricGeneration(ctx, transaction, stamp)
	if err != nil {
		return ACLGrant{}, err
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO acl_grants(id,admin_peer_id,publication_id,protocol,port_start,port_end,generation,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?)`, id, input.AdminPeerID, input.PublicationID, input.Protocol, input.PortStart, input.PortEnd, generation, stamp, stamp); err != nil {
		return ACLGrant{}, fmt.Errorf("create ACL grant: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE admin_peers SET desired_generation=?,updated_at=? WHERE id=?", generation, stamp, input.AdminPeerID); err != nil {
		return ACLGrant{}, err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE resource_publications SET desired_generation=?,state='PENDING',updated_at=? WHERE id=?", generation, stamp, input.PublicationID); err != nil {
		return ACLGrant{}, err
	}
	if err := transaction.Commit(); err != nil {
		return ACLGrant{}, err
	}
	return repository.GetACL(ctx, id)
}

func (repository HubRepository) DeleteACL(ctx context.Context, id string) error {
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var adminID, publicationID string
	if err := transaction.QueryRowContext(ctx, "SELECT admin_peer_id,publication_id FROM acl_grants WHERE id=?", id).Scan(&adminID, &publicationID); errors.Is(err, sql.ErrNoRows) {
		return ErrHubNotFound
	} else if err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM acl_grants WHERE id=?", id); err != nil {
		return err
	}
	stamp := formatTime(repository.now())
	generation, err := bumpFabricGeneration(ctx, transaction, stamp)
	if err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE admin_peers SET desired_generation=?,updated_at=? WHERE id=?", generation, stamp, adminID); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE resource_publications SET desired_generation=?,state='PENDING',updated_at=? WHERE id=?", generation, stamp, publicationID); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository HubRepository) ListACL(ctx context.Context) ([]ACLGrant, error) {
	rows, err := repository.Database.QueryContext(ctx, aclSelect+" ORDER BY created_at LIMIT ?", maximumACLGrants)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ACLGrant{}
	for rows.Next() {
		item, err := scanACL(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (repository HubRepository) GetACL(ctx context.Context, id string) (ACLGrant, error) {
	item, err := scanACL(repository.Database.QueryRowContext(ctx, aclSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ACLGrant{}, ErrHubNotFound
	}
	return item, err
}

func (repository HubRepository) Overview(ctx context.Context) (HubOverview, error) {
	identity, err := ReadIdentity(ctx, repository.Database)
	if err != nil {
		return HubOverview{}, err
	}
	result := HubOverview{Identity: identity, SchemaVersion: SchemaVersion, HostApplyAvailable: repository.HostApplyAvailable}
	result.Gateways, err = groupedCounts(ctx, repository.Database, "gateway_peers", "state")
	if err != nil {
		return HubOverview{}, err
	}
	result.Administrators, err = groupedCounts(ctx, repository.Database, "admin_peers", "state")
	if err != nil {
		return HubOverview{}, err
	}
	result.Resources, err = groupedCounts(ctx, repository.Database, "resource_publications", "state")
	if err != nil {
		return HubOverview{}, err
	}
	if err := repository.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM acl_grants").Scan(&result.ACLGrants); err != nil {
		return HubOverview{}, err
	}
	if err := repository.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pairing_invitations WHERE state='OPEN' AND expires_at>?", formatTime(repository.now())).Scan(&result.OpenInvitations); err != nil {
		return HubOverview{}, err
	}
	var settings string
	if err := repository.Database.QueryRowContext(ctx, "SELECT value_json FROM vps_settings WHERE key='fabric'").Scan(&settings); err != nil {
		return HubOverview{}, err
	}
	var fabric struct {
		Desired int64  `json:"desired_generation"`
		Applied int64  `json:"applied_generation"`
		State   string `json:"state"`
	}
	if json.Unmarshal([]byte(settings), &fabric) != nil {
		return HubOverview{}, errors.New("VPS fabric settings are invalid")
	}
	result.DesiredGeneration, result.AppliedGeneration, result.FabricState = fabric.Desired, fabric.Applied, fabric.State
	return result, nil
}

func (repository HubRepository) ControllerHealth(ctx context.Context) ControllerHealth {
	result := ControllerHealth{State: "HEALTHY", CheckedAt: formatTime(repository.now())}
	appendComponent := func(name, state, reason string) {
		result.Components = append(result.Components, ControllerComponent{Name: name, State: state, Reason: reason, OwnedOnly: true})
		if state == "FAILED" {
			result.State = "FAILED"
		} else if state == "PENDING" && result.State == "HEALTHY" {
			result.State = "PENDING"
		}
	}
	if err := Verify(ctx, repository.Database); err != nil {
		appendComponent("database", "FAILED", "SQLITE_INTEGRITY_OR_SCHEMA_INVALID")
		return result
	}
	appendComponent("database", "HEALTHY", "SCHEMA_AND_INTEGRITY_OK")
	if _, err := ReadIdentity(ctx, repository.Database); err != nil {
		appendComponent("identity", "FAILED", "VPS_IDENTITY_MISSING")
	} else {
		appendComponent("identity", "HEALTHY", "IDENTITY_PRESENT")
	}
	for _, item := range []struct{ name, table string }{{"gateway_links", "gateway_peers"}, {"administrator_peers", "admin_peers"}, {"resource_acl", "resource_publications"}} {
		var pending int64
		query := "SELECT COUNT(*) FROM " + item.table + " WHERE desired_generation>applied_generation"
		if err := repository.Database.QueryRowContext(ctx, query).Scan(&pending); err != nil {
			appendComponent(item.name, "FAILED", "STATE_QUERY_FAILED")
		} else if pending > 0 {
			reason := "HOST_APPLY_PENDING"
			if !repository.HostApplyAvailable {
				reason = "HOST_APPLY_NOT_IMPLEMENTED"
			}
			appendComponent(item.name, "PENDING", reason)
		} else {
			appendComponent(item.name, "HEALTHY", "DESIRED_EQUALS_APPLIED")
		}
	}
	appendComponent("foreign_services", "HEALTHY", "MONITORING_EXCLUDED_BY_OWNERSHIP")
	return result
}

const gatewaySelect = `
SELECT id,site_id,display_name,public_key,assigned_subnet,assigned_address,remote_address,
       endpoint,webui_url,state,desired_generation,applied_generation,latest_handshake_at,
       rx_bytes,tx_bytes,rtt_ms,status_reason,created_at,updated_at
FROM gateway_peers`

const adminSelect = `
SELECT id,name,public_key,assigned_address,key_mode,state,desired_generation,applied_generation,
       latest_handshake_at,rx_bytes,tx_bytes,status_reason,config_state,config_downloaded_at,
       rotation_source_id,created_at,updated_at
FROM admin_peers`

const resourceSelect = `
SELECT id,gateway_peer_id,resource_id,display_name,resource_kind,local_destination,published_alias,
       access_profile,enabled,advanced_scope_acknowledged,health,status_reason,state,
       desired_generation,applied_generation,created_at,updated_at
FROM resource_publications`

const aclSelect = `
SELECT id,admin_peer_id,publication_id,protocol,port_start,port_end,generation,created_at,updated_at
FROM acl_grants`

func scanGateway(scanner interface{ Scan(...any) error }) (GatewayPeer, error) {
	var item GatewayPeer
	var handshake sql.NullString
	var rtt sql.NullInt64
	err := scanner.Scan(&item.ID, &item.SiteID, &item.DisplayName, &item.PublicKey, &item.AssignedSubnet,
		&item.AssignedAddress, &item.RemoteAddress, &item.Endpoint, &item.WebUIURL, &item.State,
		&item.DesiredGeneration, &item.AppliedGeneration, &handshake, &item.RXBytes, &item.TXBytes,
		&rtt, &item.StatusReason, &item.CreatedAt, &item.UpdatedAt)
	if handshake.Valid {
		item.LatestHandshakeAt = handshake.String
	}
	if rtt.Valid {
		value := rtt.Int64
		item.RTTMilliseconds = &value
	}
	return item, err
}

func scanAdmin(scanner interface{ Scan(...any) error }) (AdminPeer, error) {
	var item AdminPeer
	var handshake, downloaded sql.NullString
	err := scanner.Scan(&item.ID, &item.Name, &item.PublicKey, &item.AssignedAddress, &item.KeyMode,
		&item.State, &item.DesiredGeneration, &item.AppliedGeneration, &handshake, &item.RXBytes,
		&item.TXBytes, &item.StatusReason, &item.ConfigState, &downloaded, &item.RotationSourceID,
		&item.CreatedAt, &item.UpdatedAt)
	if handshake.Valid {
		item.LatestHandshakeAt = handshake.String
	}
	if downloaded.Valid {
		item.ConfigDownloadedAt = downloaded.String
	}
	return item, err
}

func scanResource(scanner interface{ Scan(...any) error }) (ResourcePublication, error) {
	var item ResourcePublication
	var enabled, acknowledged int
	err := scanner.Scan(&item.ID, &item.GatewayPeerID, &item.ResourceID, &item.DisplayName,
		&item.ResourceKind, &item.LocalDestination, &item.PublishedAlias, &item.AccessProfile,
		&enabled, &acknowledged, &item.Health, &item.StatusReason, &item.State,
		&item.DesiredGeneration, &item.AppliedGeneration, &item.CreatedAt, &item.UpdatedAt)
	item.Enabled, item.AdvancedScopeAcknowledged = enabled == 1, acknowledged == 1
	return item, err
}

func scanACL(scanner interface{ Scan(...any) error }) (ACLGrant, error) {
	var item ACLGrant
	err := scanner.Scan(&item.ID, &item.AdminPeerID, &item.PublicationID, &item.Protocol,
		&item.PortStart, &item.PortEnd, &item.Generation, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func validateResourceInput(input ResourceInput) (ResourceInput, netip.Prefix, netip.Prefix, error) {
	input.GatewayPeerID, input.ResourceID = strings.TrimSpace(input.GatewayPeerID), strings.TrimSpace(input.ResourceID)
	input.DisplayName, input.ResourceKind = strings.TrimSpace(input.DisplayName), strings.ToUpper(strings.TrimSpace(input.ResourceKind))
	input.AccessProfile = strings.ToUpper(strings.TrimSpace(input.AccessProfile))
	if !hubIdentifierPattern.MatchString(input.GatewayPeerID) || !hubIdentifierPattern.MatchString(input.ResourceID) || input.DisplayName == "" || len(input.DisplayName) > 128 {
		return input, netip.Prefix{}, netip.Prefix{}, errors.New("valid resource identity, Gateway and name are required")
	}
	validKinds := map[string]bool{"GATEWAY_SERVICE": true, "KEENETIC_SERVICE": true, "LOCAL_HOST": true, "LOCAL_SUBNET": true, "CUSTOM_SERVICE": true}
	validProfiles := map[string]bool{"GATEWAY_ONLY": true, "KEENETIC_WAN": true, "VIA_KEENETIC_WAN_ROUTED": true, "VIA_WG_ROUTER": true, "VIA_DEDICATED_LAN": true}
	if !validKinds[input.ResourceKind] || !validProfiles[input.AccessProfile] {
		return input, netip.Prefix{}, netip.Prefix{}, errors.New("resource kind or access profile is invalid")
	}
	var local, alias netip.Prefix
	var err error
	if input.ResourceKind == "LOCAL_SUBNET" {
		if !input.AdvancedScopeAcknowledged {
			return input, local, alias, errors.New("LOCAL_SUBNET requires explicit advanced-scope acknowledgement")
		}
		local, err = canonicalPrivatePrefix(input.LocalDestination, 8, 30)
		if err == nil {
			alias, err = canonicalPrivatePrefix(input.PublishedAlias, local.Bits(), local.Bits())
		}
	} else {
		var localAddress, aliasAddress netip.Addr
		localAddress, err = canonicalPrivateAddress(input.LocalDestination)
		if err == nil {
			aliasAddress, err = canonicalPrivateAddress(input.PublishedAlias)
		}
		if err == nil {
			local, alias = netip.PrefixFrom(localAddress, 32), netip.PrefixFrom(aliasAddress, 32)
		}
	}
	if err != nil {
		return input, local, alias, errors.New("resource destination and published alias must be canonical private IPv4 values of matching scope")
	}
	input.LocalDestination, input.PublishedAlias = local.String(), alias.String()
	if local.Bits() == 32 {
		input.LocalDestination, input.PublishedAlias = local.Addr().String(), alias.Addr().String()
	}
	return input, local, alias, nil
}

func canonicalPrivateAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !address.Is4() || !address.IsPrivate() || address.IsUnspecified() || address.IsMulticast() || address.String() != strings.TrimSpace(value) {
		return netip.Addr{}, errors.New("canonical private IPv4 address is required")
	}
	return address, nil
}

func canonicalPrivatePrefix(value string, minimumBits, maximumBits int) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < minimumBits || prefix.Bits() > maximumBits || prefix.Masked() != prefix || prefix.String() != strings.TrimSpace(value) {
		return netip.Prefix{}, errors.New("canonical private IPv4 prefix is required")
	}
	return prefix, nil
}

func canonicalEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 300 {
		return "", errors.New("bounded endpoint is required")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", errors.New("endpoint must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("endpoint port is invalid")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = address.String()
	} else if !hostnamePattern.MatchString(host) || strings.Contains(host, "..") {
		return "", errors.New("endpoint host is invalid")
	} else {
		host = strings.ToLower(host)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func canonicalWebUIURL(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 512 {
		return "", errors.New("Gateway WebUI URL is too long")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("Gateway WebUI URL must be an HTTPS origin without credentials, query or fragment")
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func validPorts(protocol string, start, end int) bool {
	if protocol == "ICMP" {
		return start == 0 && end == 0
	}
	return (protocol == "TCP" || protocol == "UDP") && start >= 1 && end >= start && end <= 65535
}

func ensurePrefixAvailable(ctx context.Context, transaction *sql.Tx, candidate netip.Prefix, ownerID string) error {
	reserved, err := netip.ParsePrefix("10.80.0.0/24")
	if err != nil || candidate.Overlaps(reserved) {
		return fmt.Errorf("%w: prefix overlaps the VPS Hub system subnet", ErrHubConflict)
	}
	rows, err := transaction.QueryContext(ctx, "SELECT owner_id,prefix FROM prefix_allocations")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var currentOwner, value string
		if err := rows.Scan(&currentOwner, &value); err != nil {
			return err
		}
		if ownerID != "" && currentOwner == ownerID {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return errors.New("stored VPS prefix allocation is invalid")
		}
		if prefix.Overlaps(candidate) {
			return fmt.Errorf("%w: prefix overlaps an existing allocation", ErrHubConflict)
		}
	}
	return rows.Err()
}

func ensurePeerKeyAvailable(ctx context.Context, transaction *sql.Tx, publicKey string) error {
	var count int64
	if err := transaction.QueryRowContext(ctx, `
SELECT
 (SELECT COUNT(*) FROM vps_identity WHERE public_key=?)+
 (SELECT COUNT(*) FROM gateway_peers WHERE public_key=?)+
 (SELECT COUNT(*) FROM admin_peers WHERE public_key=?)`, publicKey, publicKey, publicKey).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("%w: WireGuard public key is already assigned", ErrHubConflict)
	}
	return nil
}

func enforceCount(ctx context.Context, transaction *sql.Tx, table string, maximum int64) error {
	allowed := map[string]bool{"pairing_invitations": true, "gateway_peers": true, "admin_peers": true, "resource_publications": true, "acl_grants": true}
	if !allowed[table] {
		return errors.New("internal VPS table count request is invalid")
	}
	var count int64
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
		return err
	}
	if count >= maximum {
		return errors.New("VPS Hub object limit is reached")
	}
	return nil
}

func bumpFabricGeneration(ctx context.Context, transaction *sql.Tx, stamp string) (int64, error) {
	var settings string
	if err := transaction.QueryRowContext(ctx, "SELECT value_json FROM vps_settings WHERE key='fabric'").Scan(&settings); err != nil {
		return 0, err
	}
	var value struct {
		Desired int64 `json:"desired_generation"`
		Applied int64 `json:"applied_generation"`
	}
	if json.Unmarshal([]byte(settings), &value) != nil || value.Desired < 1 || value.Applied < 0 || value.Applied > value.Desired {
		return 0, errors.New("VPS fabric generation settings are invalid")
	}
	value.Desired++
	encoded, _ := json.Marshal(map[string]any{"desired_generation": value.Desired, "applied_generation": value.Applied, "state": "PENDING"})
	if _, err := transaction.ExecContext(ctx, "UPDATE vps_settings SET value_json=?,updated_at=? WHERE key='fabric'", string(encoded), stamp); err != nil {
		return 0, err
	}
	return value.Desired, nil
}

func groupedCounts(ctx context.Context, database *sql.DB, table, column string) (map[string]int64, error) {
	allowed := map[string]bool{"gateway_peers\x00state": true, "admin_peers\x00state": true, "resource_publications\x00state": true}
	if !allowed[table+"\x00"+column] {
		return nil, errors.New("internal VPS grouped count is invalid")
	}
	rows, err := database.QueryContext(ctx, "SELECT "+column+",COUNT(*) FROM "+table+" GROUP BY "+column)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		result[key] = count
	}
	return result, rows.Err()
}

func (repository HubRepository) randomReader() io.Reader {
	if repository.Random != nil {
		return repository.Random
	}
	return rand.Reader
}

func (repository HubRepository) randomID(prefix string, bytes int) (string, error) {
	content := make([]byte, bytes)
	if _, err := io.ReadFull(repository.randomReader(), content); err != nil {
		return "", errors.New("generate VPS object id failed")
	}
	return prefix + hex.EncodeToString(content), nil
}

func (repository HubRepository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
