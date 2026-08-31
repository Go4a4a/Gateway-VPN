package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// RestorePointController serializes retention operations with update apply,
// recovery and finalization. Protection is derived only from fixed release
// pointers and the verified root-owned journal; callers cannot invent it.
type RestorePointController struct {
	Store       *RestorePointStore
	Journals    JournalStore
	Requests    RollbackRequestStore
	ReleaseRoot string
}

func (controller *RestorePointController) Inventory(ctx context.Context) ([]RestorePoint, error) {
	if err := controller.validate(); err != nil {
		return nil, err
	}
	unlock, err := acquireTransactionLock(controller.Journals.Root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, recovery, active, err := controller.protection(ctx)
	if err != nil {
		return nil, err
	}
	return controller.Store.Inventory(ctx, current, recovery, active)
}

func (controller *RestorePointController) Delete(ctx context.Context, pointID string) error {
	if err := controller.validate(); err != nil {
		return err
	}
	if !restorePointIDPattern.MatchString(pointID) {
		return errors.New("restore point id is invalid")
	}
	unlock, err := acquireTransactionLock(controller.Journals.Root)
	if err != nil {
		return err
	}
	defer unlock()
	current, recovery, active, err := controller.protection(ctx)
	if err != nil {
		return err
	}
	return controller.Store.Delete(ctx, pointID, current, recovery, active)
}

func (controller *RestorePointController) Prune(ctx context.Context, policy RestorePointPolicy) ([]string, error) {
	if err := controller.validate(); err != nil {
		return nil, err
	}
	if !validRestorePointPolicy(policy) {
		return nil, errors.New("restore point retention policy is invalid")
	}
	unlock, err := acquireTransactionLock(controller.Journals.Root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, recovery, active, err := controller.protection(ctx)
	if err != nil {
		return nil, err
	}
	return controller.Store.Prune(ctx, policy, current, recovery, active)
}

func (controller *RestorePointController) StageRollback(ctx context.Context, pointID string) (RollbackRequest, error) {
	if err := controller.validate(); err != nil {
		return RollbackRequest{}, err
	}
	if err := controller.Requests.validate(); err != nil {
		return RollbackRequest{}, err
	}
	if ValidateRestorePointID(pointID) != nil {
		return RollbackRequest{}, errors.New("restore point id is invalid")
	}
	unlock, err := acquireTransactionLock(controller.Journals.Root)
	if err != nil {
		return RollbackRequest{}, err
	}
	defer unlock()
	journal, exists, err := controller.Journals.LoadActive()
	if err != nil {
		return RollbackRequest{}, err
	}
	if exists && !terminalState(journal.State) {
		return RollbackRequest{}, ErrUpdateInProgress
	}
	point, err := controller.Store.Get(ctx, pointID)
	if err != nil {
		return RollbackRequest{}, err
	}
	if !point.Compatible {
		return RollbackRequest{}, errors.New("restore point host contract is incompatible")
	}
	return controller.Requests.Write(pointID)
}

func (controller *RestorePointController) DiscardRollback(pointID string) error {
	if err := controller.validate(); err != nil {
		return err
	}
	unlock, err := acquireTransactionLock(controller.Journals.Root)
	if err != nil {
		return err
	}
	defer unlock()
	return controller.Requests.Remove(pointID)
}

func (controller *RestorePointController) validate() error {
	if controller == nil || controller.Store == nil || !filepath.IsAbs(controller.ReleaseRoot) || filepath.Clean(controller.Store.ReleaseRoot) != filepath.Clean(controller.ReleaseRoot) || !filepath.IsAbs(controller.Journals.Root) || filepath.Base(filepath.Clean(controller.Journals.Root)) != "update-transactions" || !filepath.IsAbs(controller.Requests.Root) || filepath.Clean(controller.Requests.Root) != filepath.Join(filepath.Dir(filepath.Clean(controller.Journals.Root)), "update-rollback") {
		return errors.New("complete fixed restore point controller configuration is required")
	}
	return controller.Store.validate()
}

func (controller *RestorePointController) protection(ctx context.Context) (string, string, []string, error) {
	_, currentRelease, err := readReleasePointer(controller.ReleaseRoot, "current")
	if err != nil {
		return "", "", nil, err
	}
	_, recoveryRelease, err := readReleasePointer(controller.ReleaseRoot, "recovery")
	if err != nil {
		return "", "", nil, err
	}
	active := []string{}
	journal, exists, err := controller.Journals.LoadActive()
	if err != nil {
		return "", "", nil, err
	}
	if exists && journal.State != StateFinalized && journal.State != StateRolledBack {
		active = append(active, journal.OldVersion, journal.NewVersion)
	}
	request, pending, err := controller.Requests.Load()
	if err != nil {
		return "", "", nil, err
	}
	if pending {
		point, err := controller.Store.Get(ctx, request.PointID)
		if err != nil {
			return "", "", nil, errors.New("pending restore point rollback target is unavailable")
		}
		active = append(active, point.Manifest.GatewayVersion)
	}
	return currentRelease.GatewayVersion, recoveryRelease.GatewayVersion, active, nil
}

func readReleasePointer(root, name string) (string, Release, error) {
	if !filepath.IsAbs(root) || name != "current" && name != "recovery" {
		return "", Release{}, errors.New("fixed release root and pointer are required")
	}
	target, err := readCurrentLink(filepath.Join(filepath.Clean(root), name))
	if err != nil || filepath.IsAbs(target) {
		return "", Release{}, errors.New("release pointer is unavailable or unsafe")
	}
	target = filepath.ToSlash(filepath.Clean(target))
	version := strings.TrimPrefix(target, "releases/v")
	if target != "releases/v"+version || ValidateGatewayVersion(version) != nil {
		return "", Release{}, errors.New("release pointer target is invalid")
	}
	releasePath := filepath.Join(root, filepath.FromSlash(target))
	info, err := os.Lstat(releasePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", Release{}, errors.New("release pointer target directory is unsafe")
	}
	release, err := ReadReleaseMetadata(releasePath)
	if err != nil || release.GatewayVersion != version {
		return "", Release{}, errors.New("release pointer metadata mismatch")
	}
	return target, release, nil
}
