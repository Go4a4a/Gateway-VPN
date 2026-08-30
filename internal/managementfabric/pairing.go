package managementfabric

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

const pairingAttemptBudget = 8

var pairingTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

func (repository *Repository) ImportPairing(ctx context.Context, bundle PairingBundle) (PairingInvitation, error) {
	if repository == nil || repository.Database == nil {
		return PairingInvitation{}, errors.New("management database is required")
	}
	if err := repository.validatePairingBundle(bundle); err != nil {
		return PairingInvitation{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return PairingInvitation{}, fmt.Errorf("begin pairing import: %w", err)
	}
	defer transaction.Rollback()

	var fingerprint, publicKey, adminPool, aliasPool string
	err = transaction.QueryRowContext(ctx, `
SELECT verified_fingerprint, public_key, admin_address_pool, resource_alias_pool
FROM vps_nodes WHERE id=?`, bundle.VPSID).Scan(&fingerprint, &publicKey, &adminPool, &aliasPool)
	if errors.Is(err, sql.ErrNoRows) {
		if err := repository.rejectPrefixCollisionsTx(ctx, transaction, []namedPrefix{
			{owner: "pairing-vps-admin:" + bundle.VPSID, prefix: mustPrivatePrefix(bundle.AdminAddressPool, 16, 30)},
			{owner: "pairing-vps-alias:" + bundle.VPSID, prefix: mustPrivatePrefix(bundle.ResourceAliasPool, 8, 30)},
		}, ""); err != nil {
			return PairingInvitation{}, err
		}
		number, err := allocateVPSNumber(ctx, transaction)
		if err != nil {
			return PairingInvitation{}, err
		}
		now := repository.now().Format(time.RFC3339Nano)
		_, err = transaction.ExecContext(ctx, `
INSERT INTO vps_nodes(
    id, display_number, name, enabled, priority, verified_fingerprint, public_key,
    admin_address_pool, resource_alias_pool, state, created_at, updated_at
) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 'PAIRING', ?, ?)`,
			bundle.VPSID, number, strings.TrimSpace(bundle.VPSName), number*10,
			strings.ToLower(bundle.ExpectedFingerprint), strings.TrimSpace(bundle.ExpectedPublicKey),
			bundle.AdminAddressPool, bundle.ResourceAliasPool, now, now)
		if err != nil {
			return PairingInvitation{}, fmt.Errorf("stage pairing VPS identity: %w", err)
		}
	} else if err != nil {
		return PairingInvitation{}, fmt.Errorf("inspect pairing VPS identity: %w", err)
	} else if fingerprint != strings.ToLower(bundle.ExpectedFingerprint) || publicKey != bundle.ExpectedPublicKey || adminPool != bundle.AdminAddressPool || aliasPool != bundle.ResourceAliasPool {
		return PairingInvitation{}, errors.New("pairing bundle conflicts with the pinned VPS identity")
	}

	var linkCount int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_links WHERE vps_id=?", bundle.VPSID).Scan(&linkCount); err != nil || linkCount != 0 {
		return PairingInvitation{}, errors.New("a management link to this VPS already exists")
	}
	if err := repository.rejectPrefixCollisionsTx(ctx, transaction, []namedPrefix{{
		owner: "pairing-link:" + bundle.InvitationID, prefix: mustPrivatePrefix(bundle.AssignedSubnet, 16, 30),
	}}, ""); err != nil {
		return PairingInvitation{}, err
	}
	digest := tokenDigest(bundle.Token)
	now := repository.now().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
INSERT INTO management_pairing_invitations(
    id, vps_id, token_sha256, expected_fingerprint, expected_public_key,
    endpoint_host, endpoint_port, assigned_subnet, assigned_local_address,
    assigned_remote_address, state, attempt_count, expires_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'IMPORTED', 0, ?, ?, ?)`,
		bundle.InvitationID, bundle.VPSID, digest, strings.ToLower(bundle.ExpectedFingerprint),
		bundle.ExpectedPublicKey, strings.ToLower(strings.TrimSuffix(bundle.EndpointHost, ".")),
		bundle.EndpointPort, bundle.AssignedSubnet, bundle.AssignedLocal, bundle.AssignedRemote,
		bundle.ExpiresAt, now, now)
	if err != nil {
		return PairingInvitation{}, fmt.Errorf("store pairing invitation (duplicate or already open): %w", err)
	}
	if err := advanceGeneration(ctx, transaction, now); err != nil {
		return PairingInvitation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return PairingInvitation{}, fmt.Errorf("commit pairing import: %w", err)
	}
	return repository.GetPairing(ctx, bundle.InvitationID)
}

func (repository *Repository) GetPairing(ctx context.Context, id string) (PairingInvitation, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) {
		return PairingInvitation{}, store.ErrNotFound
	}
	return scanPairing(repository.Database.QueryRowContext(ctx, `
SELECT id, vps_id, expected_fingerprint, expected_public_key, endpoint_host,
       endpoint_port, assigned_subnet, assigned_local_address, assigned_remote_address,
       state, attempt_count, expires_at, COALESCE(consumed_at,''), created_at, updated_at
FROM management_pairing_invitations WHERE id=?`, id))
}

func (repository *Repository) ConfirmPairing(ctx context.Context, id, token, fingerprint string) (PairingInvitation, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) || !pairingTokenPattern.MatchString(token) {
		return PairingInvitation{}, errors.New("valid pairing confirmation is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return PairingInvitation{}, fmt.Errorf("begin pairing confirmation: %w", err)
	}
	defer transaction.Rollback()
	var expectedDigest, expectedFingerprint, state, expiresAt string
	var attempts int
	if err := transaction.QueryRowContext(ctx, `
SELECT token_sha256, expected_fingerprint, state, attempt_count, expires_at
FROM management_pairing_invitations WHERE id=?`, id).Scan(
		&expectedDigest, &expectedFingerprint, &state, &attempts, &expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PairingInvitation{}, store.ErrNotFound
		}
		return PairingInvitation{}, fmt.Errorf("read pairing confirmation: %w", err)
	}
	nowTime := repository.now()
	now := nowTime.Format(time.RFC3339Nano)
	expires, parseErr := time.Parse(time.RFC3339Nano, expiresAt)
	if parseErr != nil || !nowTime.Before(expires) {
		if state != "CONSUMED" && state != "REJECTED" {
			if _, err := transaction.ExecContext(ctx, "UPDATE management_pairing_invitations SET state='EXPIRED', updated_at=? WHERE id=?", now, id); err != nil {
				return PairingInvitation{}, fmt.Errorf("expire pairing invitation: %w", err)
			}
			if err := transaction.Commit(); err != nil {
				return PairingInvitation{}, fmt.Errorf("commit pairing expiry: %w", err)
			}
		}
		return PairingInvitation{}, errors.New("pairing invitation has expired")
	}
	if state == "CONSUMED" || state == "REJECTED" || state == "EXPIRED" {
		return PairingInvitation{}, errors.New("pairing invitation is not confirmable")
	}
	validToken := constantDigestEqual(expectedDigest, tokenDigest(token))
	validFingerprint := subtle.ConstantTimeCompare([]byte(expectedFingerprint), []byte(strings.ToLower(strings.TrimSpace(fingerprint)))) == 1
	if !validToken || !validFingerprint {
		attempts++
		nextState := state
		if attempts >= pairingAttemptBudget {
			nextState = "REJECTED"
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE management_pairing_invitations SET attempt_count=?, state=?, updated_at=? WHERE id=?`, attempts, nextState, now, id); err != nil {
			return PairingInvitation{}, fmt.Errorf("record failed pairing confirmation: %w", err)
		}
		if err := transaction.Commit(); err != nil {
			return PairingInvitation{}, fmt.Errorf("commit failed pairing confirmation: %w", err)
		}
		return PairingInvitation{}, errors.New("pairing confirmation failed")
	}
	if state == "IMPORTED" {
		if _, err := transaction.ExecContext(ctx, "UPDATE management_pairing_invitations SET state='CONFIRMED', updated_at=? WHERE id=? AND state='IMPORTED'", now, id); err != nil {
			return PairingInvitation{}, fmt.Errorf("confirm pairing invitation: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return PairingInvitation{}, fmt.Errorf("commit pairing confirmation: %w", err)
	}
	return repository.GetPairing(ctx, id)
}

func (repository *Repository) ConsumePairing(ctx context.Context, id, token string, completion PairingCompletion) (Link, error) {
	if repository == nil || repository.Database == nil || !safeIdentifier.MatchString(id) || !pairingTokenPattern.MatchString(token) {
		return Link{}, errors.New("valid confirmed pairing invitation is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Link{}, fmt.Errorf("begin pairing consume: %w", err)
	}
	defer transaction.Rollback()
	var vpsID, expectedDigest, publicKey, endpointHost, subnet, local, remote, state, expiresAt string
	var endpointPort, attempts int
	if err := transaction.QueryRowContext(ctx, `
SELECT i.vps_id, i.token_sha256, i.expected_public_key, i.endpoint_host,
       i.endpoint_port, i.assigned_subnet, i.assigned_local_address,
       i.assigned_remote_address, i.state, i.attempt_count, i.expires_at
FROM management_pairing_invitations AS i WHERE i.id=?`, id).Scan(
		&vpsID, &expectedDigest, &publicKey, &endpointHost, &endpointPort,
		&subnet, &local, &remote, &state, &attempts, &expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Link{}, store.ErrNotFound
		}
		return Link{}, fmt.Errorf("read pairing consume state: %w", err)
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, expiresAt)
	nowTime := repository.now()
	now := nowTime.Format(time.RFC3339Nano)
	if parseErr != nil || !nowTime.Before(expires) {
		if state != "CONSUMED" && state != "REJECTED" {
			if _, err := transaction.ExecContext(ctx, "UPDATE management_pairing_invitations SET state='EXPIRED', updated_at=? WHERE id=?", now, id); err != nil {
				return Link{}, fmt.Errorf("expire pairing before consume: %w", err)
			}
			if err := transaction.Commit(); err != nil {
				return Link{}, fmt.Errorf("commit pairing expiry before consume: %w", err)
			}
		}
		return Link{}, errors.New("pairing invitation has expired")
	}
	if state != "CONFIRMED" {
		return Link{}, errors.New("pairing invitation is not confirmed")
	}
	if !constantDigestEqual(expectedDigest, tokenDigest(token)) {
		attempts++
		nextState := state
		if attempts >= pairingAttemptBudget {
			nextState = "REJECTED"
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE management_pairing_invitations SET attempt_count=?, state=?, updated_at=? WHERE id=?`, attempts, nextState, now, id); err != nil {
			return Link{}, fmt.Errorf("record failed pairing consume proof: %w", err)
		}
		if err := transaction.Commit(); err != nil {
			return Link{}, fmt.Errorf("commit failed pairing consume proof: %w", err)
		}
		return Link{}, errors.New("pairing consume proof failed")
	}
	input := CreateLinkInput{
		ID: completion.LinkID, SiteID: completion.SiteID, VPSID: vpsID, Enabled: true,
		ManagementSubnet: subnet, LocalAddress: local, RemoteAddress: remote,
		LocalPrivateKeySecretRef: completion.LocalPrivateKeySecretRef,
		LocalPublicKey:           completion.LocalPublicKey, RemotePublicKey: publicKey,
		UplinkPolicy: completion.UplinkPolicy, PinnedUplinkID: completion.PinnedUplinkID,
		PersistentKeepalive: completion.PersistentKeepalive,
		Endpoints:           []EndpointSpec{{Host: endpointHost, Port: endpointPort}},
	}
	if err := repository.createLinkTx(ctx, transaction, input); err != nil {
		return Link{}, err
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE management_pairing_invitations
SET state='CONSUMED', consumed_at=?, updated_at=? WHERE id=? AND state='CONFIRMED'`, now, now, id)
	if err != nil {
		return Link{}, fmt.Errorf("consume pairing invitation: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return Link{}, errors.New("pairing invitation was already consumed")
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE vps_nodes SET state='CONFIGURED', updated_at=? WHERE id=? AND state='PAIRING'", now, vpsID); err != nil {
		return Link{}, fmt.Errorf("activate paired VPS identity: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Link{}, fmt.Errorf("commit pairing consume: %w", err)
	}
	return repository.GetLink(ctx, completion.LinkID)
}

func (repository *Repository) validatePairingBundle(bundle PairingBundle) error {
	if !safeIdentifier.MatchString(bundle.InvitationID) || !pairingTokenPattern.MatchString(bundle.Token) {
		return errors.New("pairing invitation id or bounded token is invalid")
	}
	if err := ValidateVPSInput(CreateVPSInput{
		ID: bundle.VPSID, Name: bundle.VPSName, VerifiedFingerprint: bundle.ExpectedFingerprint,
		PublicKey: bundle.ExpectedPublicKey, AdminAddressPool: bundle.AdminAddressPool,
		ResourceAliasPool: bundle.ResourceAliasPool,
	}); err != nil {
		return err
	}
	if err := validateEndpoints([]EndpointSpec{{Host: bundle.EndpointHost, Port: bundle.EndpointPort}}); err != nil {
		return err
	}
	prefix, err := canonicalPrivatePrefix(bundle.AssignedSubnet, 16, 30)
	if err != nil {
		return errors.New("pairing assigned management subnet is invalid")
	}
	local, localErr := canonicalHostAddress(bundle.AssignedLocal, prefix)
	remote, remoteErr := canonicalHostAddress(bundle.AssignedRemote, prefix)
	if localErr != nil || remoteErr != nil || local == remote {
		return errors.New("pairing assigned management addresses are invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, bundle.ExpiresAt)
	now := repository.now()
	if err != nil || !now.Before(expires) || expires.Sub(now) > 24*time.Hour {
		return errors.New("pairing invitation expiry must be in the next 24 hours")
	}
	return nil
}

func scanPairing(scanner rowScanner) (PairingInvitation, error) {
	var item PairingInvitation
	if err := scanner.Scan(
		&item.ID, &item.VPSID, &item.ExpectedFingerprint, &item.ExpectedPublicKey,
		&item.EndpointHost, &item.EndpointPort, &item.AssignedSubnet, &item.AssignedLocal,
		&item.AssignedRemote, &item.State, &item.AttemptCount, &item.ExpiresAt,
		&item.ConsumedAt, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PairingInvitation{}, store.ErrNotFound
		}
		return PairingInvitation{}, fmt.Errorf("scan pairing invitation: %w", err)
	}
	return item, nil
}

func tokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func constantDigestEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
