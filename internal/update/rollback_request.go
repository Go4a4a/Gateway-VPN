package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const RollbackRequestFormatVersion = 1

type RollbackRequest struct {
	FormatVersion int    `json:"format_version"`
	PointID       string `json:"point_id"`
	RequestedAt   string `json:"requested_at"`
}

type rollbackRequestEnvelope struct {
	Request RollbackRequest `json:"request"`
	SHA256  string          `json:"sha256"`
}

type RollbackRequestStore struct {
	Root string
	Now  func() time.Time
}

func (store RollbackRequestStore) Write(pointID string) (RollbackRequest, error) {
	if err := store.validate(); err != nil {
		return RollbackRequest{}, err
	}
	if ValidateRestorePointID(pointID) != nil {
		return RollbackRequest{}, errors.New("rollback request point id is invalid")
	}
	if existing, exists, err := store.Load(); err != nil {
		return RollbackRequest{}, err
	} else if exists {
		if existing.PointID == pointID {
			return existing, nil
		}
		return RollbackRequest{}, errors.New("another restore point rollback request is pending")
	}
	now := time.Now().UTC()
	if store.Now != nil {
		now = store.Now().UTC()
	}
	request := RollbackRequest{FormatVersion: RollbackRequestFormatVersion, PointID: pointID, RequestedAt: now.Format(time.RFC3339Nano)}
	plain, err := marshalLine(request)
	if err != nil {
		return RollbackRequest{}, err
	}
	digest := sha256.Sum256(plain)
	content, err := marshalLine(rollbackRequestEnvelope{Request: request, SHA256: hex.EncodeToString(digest[:])})
	if err != nil {
		return RollbackRequest{}, err
	}
	if err := writeAtomic(store.filename(), content, 0o600); err != nil {
		return RollbackRequest{}, err
	}
	return request, nil
}

func (store RollbackRequestStore) Load() (RollbackRequest, bool, error) {
	if err := store.validate(); err != nil {
		return RollbackRequest{}, false, err
	}
	content, err := readBoundedRegular(store.filename(), 16<<10)
	if errors.Is(err, os.ErrNotExist) || !pathExists(store.filename()) {
		return RollbackRequest{}, false, nil
	}
	if err != nil {
		return RollbackRequest{}, false, errors.New("rollback request is unavailable or unsafe")
	}
	var envelope rollbackRequestEnvelope
	if decodeStrict(content, &envelope) != nil || !digestPattern.MatchString(envelope.SHA256) || !validRollbackRequest(envelope.Request) {
		return RollbackRequest{}, false, errors.New("rollback request contract is invalid")
	}
	plain, err := marshalLine(envelope.Request)
	if err != nil {
		return RollbackRequest{}, false, err
	}
	digest := sha256.Sum256(plain)
	if envelope.SHA256 != hex.EncodeToString(digest[:]) {
		return RollbackRequest{}, false, errors.New("rollback request checksum mismatch")
	}
	return envelope.Request, true, nil
}

func (store RollbackRequestStore) Remove(pointID string) error {
	request, exists, err := store.Load()
	if err != nil || !exists {
		return err
	}
	if request.PointID != pointID {
		return errors.New("rollback request identity changed")
	}
	if err := os.Remove(store.filename()); err != nil {
		return err
	}
	return syncDirectoryPath(store.Root)
}

// DiscardPending removes only the fixed rollback marker. Recovery uses this
// after it has reconciled any durable update journal: a request that survived
// a reboot or SIGKILL is no longer an executable instruction and the operator
// must explicitly request the rollback again. A corrupted regular marker and
// a replaced symlink can be unlinked safely because the parent is a fixed,
// root-owned 0700 directory; directories and special files remain errors.
func (store RollbackRequestStore) DiscardPending() error {
	if err := store.validate(); err != nil {
		return err
	}
	filename := store.filename()
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() || !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("rollback request marker is an unsafe filesystem object")
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	return syncDirectoryPath(store.Root)
}

func (store RollbackRequestStore) validate() error {
	if !filepath.IsAbs(store.Root) || filepath.Base(filepath.Clean(store.Root)) != "update-rollback" {
		return errors.New("fixed rollback request root is required")
	}
	return secureRealDirectory(store.Root, 0o700)
}

func (store RollbackRequestStore) filename() string {
	return filepath.Join(filepath.Clean(store.Root), "pending.json")
}

func validRollbackRequest(request RollbackRequest) bool {
	created, err := time.Parse(time.RFC3339Nano, request.RequestedAt)
	return request.FormatVersion == RollbackRequestFormatVersion && ValidateRestorePointID(request.PointID) == nil && err == nil && !created.IsZero()
}
