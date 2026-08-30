package gatewayfabric

import (
	"context"
	"errors"
	"fmt"

	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/wgingress"
)

// ConfigureAdminContour is the only operation allowed to create the fixed
// wg-admin private identity. The unprivileged caller selects only the bounded
// private subnet/address and enable state; interface, port and key path are
// compile-time constants.
func (applier *Applier) ConfigureAdminContour(ctx context.Context, request managementfabric.AdminContourRequest) (managementfabric.AdminContour, error) {
	applier.mutex.Lock()
	defer applier.mutex.Unlock()
	if err := managementfabric.ValidateAdminContourRequest(request); err != nil {
		return managementfabric.AdminContour{}, err
	}
	if err := applier.validate(); err != nil {
		return managementfabric.AdminContour{}, err
	}
	secretPath, err := applier.secretPath(managementfabric.AdminPrivateKeySecretRef)
	if err != nil {
		return managementfabric.AdminContour{}, err
	}
	keys := wgingress.KeyStore{Root: applier.Paths.SecretRoot}
	existing, existingErr := applier.Repository.GetAdminContour(ctx)
	createdIdentity := false
	publicKey := ""
	if errors.Is(existingErr, store.ErrNotFound) {
		if !request.Enabled {
			return managementfabric.AdminContour{}, errors.New("administrator contour does not exist")
		}
		pair, err := wgingress.GenerateKeyPair()
		if err != nil {
			return managementfabric.AdminContour{}, err
		}
		if err := keys.Write(secretPath, pair.Private); err != nil {
			return managementfabric.AdminContour{}, err
		}
		publicKey, createdIdentity = pair.Public, true
	} else if existingErr != nil {
		return managementfabric.AdminContour{}, existingErr
	} else {
		privateKey, err := keys.Read(secretPath)
		if err != nil {
			return managementfabric.AdminContour{}, errors.New("administrator contour private identity is unavailable")
		}
		derived, err := wgingress.PublicKey(privateKey)
		privateKey = ""
		if err != nil || derived != existing.PublicKey {
			return managementfabric.AdminContour{}, errors.New("administrator contour private identity does not match durable public identity")
		}
		publicKey = existing.PublicKey
	}
	configured, err := applier.Repository.ConfigureAdminContour(ctx, managementfabric.AdminContourRootInput{
		Enabled: request.Enabled, InterfaceName: managementfabric.AdminInterfaceName,
		PrivateKeySecretRef: managementfabric.AdminPrivateKeySecretRef, PublicKey: publicKey,
		Subnet: request.Subnet, GatewayAddress: request.GatewayAddress, ListenPort: managementfabric.AdminListenPort,
	})
	if err != nil {
		if createdIdentity {
			_ = keys.Remove(secretPath)
		}
		return managementfabric.AdminContour{}, err
	}
	if err := applier.applyUnlocked(ctx); err != nil {
		return configured, fmt.Errorf("administrator contour configuration is durable but host apply is pending: %w", err)
	}
	return applier.Repository.GetAdminContour(ctx)
}

// RotateAdminContourIdentity performs an explicit fixed-key rotation. A
// failed host apply restores both the previous private/public identity and the
// previous runtime generation before returning an error.
func (applier *Applier) RotateAdminContourIdentity(ctx context.Context) (managementfabric.AdminContour, error) {
	applier.mutex.Lock()
	defer applier.mutex.Unlock()
	if err := applier.validate(); err != nil {
		return managementfabric.AdminContour{}, err
	}
	current, err := applier.Repository.GetAdminContour(ctx)
	if err != nil {
		return managementfabric.AdminContour{}, err
	}
	secretPath, err := applier.secretPath(managementfabric.AdminPrivateKeySecretRef)
	if err != nil {
		return managementfabric.AdminContour{}, err
	}
	keys := wgingress.KeyStore{Root: applier.Paths.SecretRoot}
	oldPrivate, err := keys.Read(secretPath)
	if err != nil {
		return managementfabric.AdminContour{}, errors.New("administrator contour private identity is unavailable")
	}
	oldPublic, err := wgingress.PublicKey(oldPrivate)
	if err != nil || oldPublic != current.PublicKey {
		oldPrivate = ""
		return managementfabric.AdminContour{}, errors.New("administrator contour private identity does not match durable public identity")
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		oldPrivate = ""
		return managementfabric.AdminContour{}, err
	}
	if err := keys.Write(secretPath, pair.Private); err != nil {
		oldPrivate = ""
		return managementfabric.AdminContour{}, err
	}
	pair.Private = ""
	_, rollbackSnapshot, err := applier.Repository.RotateAdminContourIdentityWithRollback(ctx, pair.Public)
	if err != nil {
		_ = keys.Write(secretPath, oldPrivate)
		oldPrivate = ""
		return managementfabric.AdminContour{}, err
	}
	if err := applier.applyUnlocked(ctx); err != nil {
		keyRollbackErr := keys.Write(secretPath, oldPrivate)
		databaseRollbackErr := applier.Repository.RestoreAdminContourIdentityRotation(ctx, rollbackSnapshot)
		runtimeRollbackErr := error(nil)
		if keyRollbackErr == nil && databaseRollbackErr == nil {
			// The failed host transaction can legitimately retain its journal
			// when the candidate key prevented its own runtime rollback.  Recover
			// that journal only after the exact old key and database generation
			// are durable. If apply already completed its own rollback there is
			// no journal and the previous receipt/runtime must simply verify.
			if exists(applier.journalPath()) {
				_, runtimeRollbackErr = applier.recoverUnlocked(ctx)
			}
			if runtimeRollbackErr == nil {
				needed, reason, verifyErr := applier.NeedsApply(ctx)
				if verifyErr != nil {
					runtimeRollbackErr = verifyErr
				} else if needed {
					runtimeRollbackErr = fmt.Errorf("administrator contour rollback verification failed: %s", reason)
				}
			}
		}
		oldPrivate = ""
		return managementfabric.AdminContour{}, errors.Join(
			errors.New("administrator contour identity rotation failed and rollback was requested"),
			err, keyRollbackErr, databaseRollbackErr, runtimeRollbackErr,
		)
	}
	oldPrivate = ""
	return applier.Repository.GetAdminContour(ctx)
}
