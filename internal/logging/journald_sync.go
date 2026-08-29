package logging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"gateway-vpn/internal/platformexec"
)

const journaldNamespaceUnit = "systemd-journald@gateway-vpn.service"

type JournaldPaths struct {
	ConfigFile string
	Systemctl  string
	Unit       string
}

func DefaultJournaldPaths() JournaldPaths {
	return JournaldPaths{
		ConfigFile: "/etc/systemd/journald@gateway-vpn.conf.d/retention.conf",
		Systemctl:  "/usr/bin/systemctl",
		Unit:       journaldNamespaceUnit,
	}
}

type JournaldSynchronizer struct {
	Settings Repository
	Runtime  RuntimeRepository
	Executor platformexec.Executor
	Paths    JournaldPaths
	Exporter *Exporter
}

func (synchronizer JournaldSynchronizer) SyncLogging(ctx context.Context) error {
	if err := synchronizer.syncRetention(ctx); err != nil {
		return err
	}
	if synchronizer.Exporter != nil {
		return synchronizer.Exporter.Sync(ctx)
	}
	return nil
}

func (synchronizer JournaldSynchronizer) syncRetention(ctx context.Context) error {
	if err := synchronizer.validate(); err != nil {
		return err
	}
	settings, err := synchronizer.Settings.Get(ctx)
	if err != nil {
		return err
	}
	desired := RetentionFingerprint(settings)
	content, err := RenderJournaldConfig(settings)
	if err != nil {
		return err
	}
	previous, existed, err := readManagedFile(synchronizer.Paths.ConfigFile)
	if err != nil {
		markErr := synchronizer.Runtime.MarkApplying(ctx, desired)
		failErr := synchronizer.Runtime.MarkFailed(context.WithoutCancel(ctx), desired, "JOURNALD_CONFIG_READ_FAILED")
		return errors.Join(err, markErr, failErr)
	}
	status, err := synchronizer.Runtime.Get(ctx)
	if err != nil {
		return err
	}
	if bytes.Equal(previous, content) && status.State == RetentionApplied && status.DesiredSHA256 == desired && status.AppliedSHA256 == desired {
		return synchronizer.verifyActive(ctx)
	}
	if err := synchronizer.Runtime.MarkApplying(ctx, desired); err != nil {
		return err
	}
	fail := func(code string, cause error) error {
		return errors.Join(cause, synchronizer.Runtime.MarkFailed(context.WithoutCancel(ctx), desired, code))
	}
	if bytes.Equal(previous, content) {
		if err := synchronizer.verifyActive(ctx); err != nil {
			return fail("JOURNALD_VERIFY_FAILED", err)
		}
		return synchronizer.Runtime.MarkApplied(ctx, desired)
	}
	if err := atomicManagedWrite(synchronizer.Paths.ConfigFile, content); err != nil {
		return fail("JOURNALD_CONFIG_WRITE_FAILED", err)
	}
	applyErr := synchronizer.restartAndVerify(ctx)
	if applyErr != nil {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		restoreErr := restoreManagedFile(synchronizer.Paths.ConfigFile, previous, existed)
		restartErr := synchronizer.restartAndVerify(rollbackContext)
		return fail("JOURNALD_APPLY_FAILED", errors.Join(applyErr, restoreErr, restartErr))
	}
	if err := synchronizer.Runtime.MarkApplied(ctx, desired); err != nil {
		return err
	}
	return nil
}

func RenderJournaldConfig(settings Settings) ([]byte, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	runtimeLimit := settings.MaxDiskUsageBytes / 4
	if runtimeLimit < 16<<20 {
		runtimeLimit = 16 << 20
	}
	content := "# Managed by Gateway VPN. Manual changes are replaced.\n" +
		"[Journal]\n" +
		"Storage=persistent\n" +
		"Compress=yes\n" +
		"Seal=yes\n" +
		"SystemMaxUse=" + strconv.FormatInt(settings.MaxDiskUsageBytes, 10) + "\n" +
		"RuntimeMaxUse=" + strconv.FormatInt(runtimeLimit, 10) + "\n" +
		"MaxRetentionSec=" + strconv.FormatInt(int64(settings.RetentionDays)*24*60*60, 10) + "s\n" +
		"MaxFileSec=1day\n"
	return []byte(content), nil
}

func (synchronizer JournaldSynchronizer) restartAndVerify(ctx context.Context) error {
	if _, err := synchronizer.Executor.Run(ctx, platformexec.Request{Executable: synchronizer.Paths.Systemctl, Arguments: []string{"restart", synchronizer.Paths.Unit}}); err != nil {
		return errors.New("restart namespaced journald failed")
	}
	return synchronizer.verifyActive(ctx)
}

func (synchronizer JournaldSynchronizer) verifyActive(ctx context.Context) error {
	if _, err := synchronizer.Executor.Run(ctx, platformexec.Request{Executable: synchronizer.Paths.Systemctl, Arguments: []string{"is-active", "--quiet", synchronizer.Paths.Unit}}); err != nil {
		return errors.New("namespaced journald is not active")
	}
	return nil
}

func (synchronizer JournaldSynchronizer) validate() error {
	if synchronizer.Settings.Database == nil || synchronizer.Runtime.Database == nil || synchronizer.Executor == nil ||
		!filepath.IsAbs(synchronizer.Paths.ConfigFile) || !filepath.IsAbs(synchronizer.Paths.Systemctl) || synchronizer.Paths.Unit != journaldNamespaceUnit {
		return errors.New("complete fixed journald synchronizer dependencies are required")
	}
	return nil
}

func readManagedFile(filename string) ([]byte, bool, error) {
	if err := validateManagedParent(filename); err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<10 {
		return nil, false, errors.New("journald config is not a bounded regular file")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, false, errors.New("read journald config failed")
	}
	return content, true, nil
}

func atomicManagedWrite(filename string, content []byte) error {
	if len(content) == 0 || len(content) > 64<<10 {
		return errors.New("journald config content is invalid")
	}
	if err := validateManagedParent(filename); err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".gateway-vpn-journald-*")
	if err != nil {
		return errors.New("create journald config temporary file failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	fail := func(cause error) error {
		_ = temporary.Close()
		return cause
	}
	if err := temporary.Chmod(0o644); err != nil {
		return fail(errors.New("set journald config permissions failed"))
	}
	if _, err := temporary.Write(content); err != nil {
		return fail(errors.New("write journald config failed"))
	}
	if err := temporary.Sync(); err != nil {
		return fail(errors.New("sync journald config failed"))
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close journald config failed")
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		if runtime.GOOS != "windows" {
			return errors.New("replace journald config failed")
		}
		if removeErr := os.Remove(filename); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.New("replace journald config failed")
		}
		if retryErr := os.Rename(temporaryName, filename); retryErr != nil {
			return errors.New("replace journald config failed")
		}
	}
	return syncDirectory(directory)
}

func restoreManagedFile(filename string, previous []byte, existed bool) error {
	if existed {
		return atomicManagedWrite(filename, previous)
	}
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove failed journald config failed")
	}
	return syncDirectory(filepath.Dir(filename))
}

func validateManagedParent(filename string) error {
	directory := filepath.Dir(filename)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journald config directory is unsafe")
	}
	return nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		// Windows development cannot fsync directory handles. Production Linux
		// always executes the durability path below.
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("open journald config directory failed")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync journald config directory: %w", err)
	}
	return nil
}
