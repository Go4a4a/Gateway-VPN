package vpsupdate

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

type Service struct {
	Stager         *Stager
	StatusPath     string
	CurrentVersion string
	CurrentSchema  int64
	ApplyAvailable bool
	Now            func() time.Time
}

type View struct {
	Available      bool       `json:"available"`
	ApplyAvailable bool       `json:"apply_available"`
	CurrentVersion string     `json:"current_version"`
	CurrentSchema  int64      `json:"current_schema"`
	Staged         bool       `json:"staged"`
	Operation      *Operation `json:"operation,omitempty"`
	Transaction    *Status    `json:"transaction,omitempty"`
	Confirmation   string     `json:"confirmation_phrase"`
	MaximumBytes   int64      `json:"maximum_archive_bytes"`
	HostUpdateHint string     `json:"host_update_hint"`
}

func (service *Service) EnsureInitialStatus() error {
	if service == nil {
		return errors.New("VPS update service is unavailable")
	}
	if existing, err := (StatusStore{Path: service.StatusPath}).Read(); err == nil {
		if existing.CurrentVersion == service.CurrentVersion && existing.CurrentSchema == service.CurrentSchema {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(service.StatusPath); statErr == nil {
			return err
		}
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	return writeAtomicJSON(service.StatusPath, Status{FormatVersion: JournalFormatVersion, Available: true, CurrentVersion: service.CurrentVersion, CurrentSchema: service.CurrentSchema, UpdatedAt: now.Format(time.RFC3339Nano)}, 0o600)
}

func (service *Service) View() (View, error) {
	if service == nil || service.Stager == nil {
		return View{}, errors.New("VPS update service is unavailable")
	}
	operation, staged, err := service.Stager.Status()
	if err != nil {
		return View{}, err
	}
	transaction, transactionErr := (StatusStore{Path: service.StatusPath}).Read()
	if transactionErr != nil {
		return View{}, transactionErr
	}
	view := View{Available: true, ApplyAvailable: service.ApplyAvailable, CurrentVersion: transaction.CurrentVersion, CurrentSchema: transaction.CurrentSchema, Staged: staged, Confirmation: "ОБНОВИТЬ VPS HUB", MaximumBytes: MaximumArchiveBytes, HostUpdateHint: "Если signed host contract изменился, используйте установщик вместо pointer-only update."}
	if staged {
		copy := operation
		view.Operation = &copy
	}
	if transaction.UpdateID != "" {
		copy := transaction
		view.Transaction = &copy
	}
	return view, nil
}

func (service *Service) Stage(ctx context.Context, archive io.Reader) (Operation, error) {
	if service == nil || service.Stager == nil {
		return Operation{}, errors.New("VPS update service is unavailable")
	}
	return service.Stager.Stage(ctx, archive)
}
func (service *Service) Discard(updateID string) error {
	if service == nil || service.Stager == nil {
		return errors.New("VPS update service is unavailable")
	}
	return service.Stager.Discard(updateID)
}
