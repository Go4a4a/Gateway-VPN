package logging

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gateway-vpn/internal/platformexec"
)

const (
	ExportPending  = "PENDING"
	ExportApplying = "APPLYING"
	ExportApplied  = "APPLIED"
	ExportFailed   = "FAILED"
	ExportDisabled = "DISABLED"

	exportJournalLines      = 4096
	exportJournalInputBytes = int64(32 << 20)
)

var archiveLogName = regexp.MustCompile(`^([a-z][a-z0-9-]{0,31})-([0-9]{8})\.log$`)

type ExportPolicy struct {
	Enabled           bool
	MaxFileBytes      int64
	MaxArchiveFiles   int
	MaxTotalBytes     int64
	RetentionDays     int
	Categories        []string
	DesiredGeneration int64
	AppliedGeneration int64
	State             string
	UpdatedAt         string
}

func (policy ExportPolicy) Validate() error {
	if policy.MaxFileBytes < 1<<20 || policy.MaxFileBytes > 1<<30 ||
		policy.MaxArchiveFiles < 1 || policy.MaxArchiveFiles > 365 ||
		policy.MaxTotalBytes < 10<<20 || policy.MaxTotalBytes > 10<<30 ||
		policy.RetentionDays < 1 || policy.RetentionDays > 365 ||
		policy.DesiredGeneration < 1 || policy.AppliedGeneration < 0 || policy.AppliedGeneration > policy.DesiredGeneration {
		return errors.New("log export policy is outside supported bounds")
	}
	if policy.State != ExportPending && policy.State != ExportApplying && policy.State != ExportApplied && policy.State != ExportFailed && policy.State != ExportDisabled {
		return errors.New("log export policy state is invalid")
	}
	if policy.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, policy.UpdatedAt); err != nil {
			return errors.New("log export policy timestamp is invalid")
		}
	}
	if len(policy.Categories) == 0 || len(policy.Categories) > len(categoryOrder) {
		return errors.New("log export policy requires bounded categories")
	}
	seen := make(map[string]struct{}, len(policy.Categories))
	for _, category := range policy.Categories {
		if !validCategory(category) || category == "" {
			return errors.New("log export policy contains an unknown category")
		}
		if _, duplicate := seen[category]; duplicate {
			return errors.New("log export policy contains a duplicate category")
		}
		seen[category] = struct{}{}
	}
	return nil
}

func (policy ExportPolicy) effectiveFileBytes() int64 {
	maximum := policy.MaxTotalBytes / int64(len(policy.Categories))
	if maximum > policy.MaxFileBytes {
		maximum = policy.MaxFileBytes
	}
	return maximum
}

type ExportRepository struct {
	Database *sql.DB
	Now      func() time.Time
}

func (repository ExportRepository) Get(ctx context.Context) (ExportPolicy, error) {
	if repository.Database == nil {
		return ExportPolicy{}, errors.New("log export database is required")
	}
	var policy ExportPolicy
	var enabled int
	var categories string
	err := repository.Database.QueryRowContext(ctx, `
SELECT enabled, max_file_bytes, max_archive_files, max_total_bytes,
       retention_days, categories_json, desired_generation,
       applied_generation, state, updated_at
FROM log_export_policy WHERE singleton_id=1`).Scan(
		&enabled, &policy.MaxFileBytes, &policy.MaxArchiveFiles, &policy.MaxTotalBytes,
		&policy.RetentionDays, &categories, &policy.DesiredGeneration,
		&policy.AppliedGeneration, &policy.State, &policy.UpdatedAt,
	)
	if err != nil {
		return ExportPolicy{}, fmt.Errorf("read log export policy: %w", err)
	}
	if enabled != 0 && enabled != 1 {
		return ExportPolicy{}, errors.New("log export enabled state is invalid")
	}
	policy.Enabled = enabled == 1
	decoder := json.NewDecoder(strings.NewReader(categories))
	if err := decoder.Decode(&policy.Categories); err != nil {
		return ExportPolicy{}, errors.New("decode log export categories failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ExportPolicy{}, errors.New("log export categories contain trailing JSON")
	}
	if err := policy.Validate(); err != nil {
		return ExportPolicy{}, err
	}
	return policy, nil
}

func (repository ExportRepository) MarkApplying(ctx context.Context, generation int64) error {
	return repository.update(ctx, `
UPDATE log_export_policy SET state='APPLYING', updated_at=?
WHERE singleton_id=1 AND desired_generation=?`, repository.now().Format(time.RFC3339Nano), generation)
}

func (repository ExportRepository) MarkApplied(ctx context.Context, generation int64, disabled bool) error {
	state := ExportApplied
	if disabled {
		state = ExportDisabled
	}
	return repository.update(ctx, `
UPDATE log_export_policy
SET applied_generation=?, state=?, updated_at=?
WHERE singleton_id=1 AND desired_generation=?`, generation, state, repository.now().Format(time.RFC3339Nano), generation)
}

func (repository ExportRepository) MarkFailed(ctx context.Context, generation int64) error {
	return repository.update(ctx, `
UPDATE log_export_policy SET state='FAILED', updated_at=?
WHERE singleton_id=1 AND desired_generation=?`, repository.now().Format(time.RFC3339Nano), generation)
}

func (repository ExportRepository) update(ctx context.Context, query string, arguments ...any) error {
	if repository.Database == nil {
		return errors.New("log export database is required")
	}
	result, err := repository.Database.ExecContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("update log export runtime: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("log export update lost desired generation")
	}
	return nil
}

func (repository ExportRepository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}

type ExportPaths struct {
	Root       string
	Journalctl string
}

func DefaultExportPaths() ExportPaths {
	return ExportPaths{Root: "/var/log/gateway-vpn", Journalctl: "/usr/bin/journalctl"}
}

type Exporter struct {
	Repository ExportRepository
	Executor   platformexec.Executor
	Paths      ExportPaths
	Now        func() time.Time
}

func (exporter Exporter) Sync(ctx context.Context) error {
	if exporter.Repository.Database == nil || exporter.Executor == nil || !filepath.IsAbs(exporter.Paths.Root) || !filepath.IsAbs(exporter.Paths.Journalctl) || filepath.Base(exporter.Paths.Root) != "gateway-vpn" {
		return errors.New("complete fixed log exporter dependencies are required")
	}
	policy, err := exporter.Repository.Get(ctx)
	if err != nil {
		return err
	}
	if err := validateExportTree(exporter.Paths.Root); err != nil {
		return exporter.fail(ctx, policy.DesiredGeneration, err)
	}
	converged := policy.AppliedGeneration == policy.DesiredGeneration &&
		(policy.Enabled && policy.State == ExportApplied || !policy.Enabled && policy.State == ExportDisabled)
	if !converged {
		if err := exporter.Repository.MarkApplying(ctx, policy.DesiredGeneration); err != nil {
			return err
		}
	}
	if !policy.Enabled {
		if err := cleanupManagedExports(exporter.Paths.Root, policy, exporter.now(), true); err != nil {
			return exporter.fail(ctx, policy.DesiredGeneration, err)
		}
		return exporter.Repository.MarkApplied(ctx, policy.DesiredGeneration, true)
	}
	entries, err := exporter.readEntries(ctx, policy)
	if err != nil {
		return exporter.fail(ctx, policy.DesiredGeneration, err)
	}
	now := exporter.now()
	maximum := policy.effectiveFileBytes()
	for _, category := range policy.Categories {
		content := renderExport(category, entries, now, maximum)
		if err := rotateAndWriteExport(exporter.Paths.Root, category, content, now, maximum); err != nil {
			return exporter.fail(ctx, policy.DesiredGeneration, err)
		}
	}
	if err := cleanupManagedExports(exporter.Paths.Root, policy, now, false); err != nil {
		return exporter.fail(ctx, policy.DesiredGeneration, err)
	}
	return exporter.Repository.MarkApplied(ctx, policy.DesiredGeneration, false)
}

func (exporter Exporter) readEntries(ctx context.Context, policy ExportPolicy) ([]JournalEntry, error) {
	arguments := []string{
		"--namespace=gateway-vpn", "--no-pager", "--quiet", "--output=json",
		"--output-fields=__CURSOR,__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,MESSAGE",
		"--reverse", "--truncate-newline", "--lines=" + strconv.Itoa(exportJournalLines),
		"--since=" + exporter.now().Add(-time.Duration(policy.RetentionDays)*24*time.Hour).Format(time.RFC3339Nano),
	}
	result, err := exporter.Executor.Run(ctx, platformexec.Request{Executable: exporter.Paths.Journalctl, Arguments: arguments, MaxOutputBytes: exportJournalInputBytes})
	if err != nil || int64(len(result.Stdout)) > exportJournalInputBytes {
		return nil, errors.New("bounded namespaced journal export failed")
	}
	entries := make([]JournalEntry, 0, exportJournalLines)
	scanner := bufio.NewScanner(strings.NewReader(result.Stdout))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	for scanner.Scan() {
		entry, err := parseJournalEntry(scanner.Bytes())
		if err != nil {
			return nil, errors.New("namespaced journal export contains an invalid entry")
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("namespaced journal export is oversized")
	}
	return entries, nil
}

func (exporter Exporter) fail(ctx context.Context, generation int64, cause error) error {
	markContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(cause, exporter.Repository.MarkFailed(markContext, generation))
}

func (exporter Exporter) now() time.Time {
	if exporter.Now != nil {
		return exporter.Now().UTC()
	}
	return time.Now().UTC()
}

func renderExport(category string, entries []JournalEntry, now time.Time, maximum int64) []byte {
	header := "# Gateway VPN redacted log export\n" +
		"# authoritative_source=systemd-journald namespace=gateway-vpn\n" +
		"# generated_at=" + now.Format(time.RFC3339Nano) + " category=" + category + " order=newest-first\n"
	buffer := bytes.NewBufferString(header)
	omitted := 0
	query := JournalQuery{Category: category}
	for _, entry := range entries {
		if !journalEntryMatches(entry, query) {
			continue
		}
		line := formatExportEntry(entry)
		if int64(buffer.Len()+len(line)) > maximum-128 {
			omitted++
			continue
		}
		buffer.WriteString(line)
	}
	if omitted != 0 {
		line := "# older_matching_records_omitted=" + strconv.Itoa(omitted) + "\n"
		if int64(buffer.Len()+len(line)) <= maximum {
			buffer.WriteString(line)
		}
	}
	return buffer.Bytes()
}

func formatExportEntry(entry JournalEntry) string {
	scope := make([]string, 0, 4)
	for key, value := range map[string]string{
		"modem": entry.ModemID, "subscription": entry.SubscriptionID,
		"path": entry.PathID, "correlation": entry.CorrelationID,
	} {
		if value != "" {
			scope = append(scope, key+"="+value)
		}
	}
	sort.Strings(scope)
	if entry.Suppressed > 0 {
		scope = append(scope, "suppressed="+strconv.FormatInt(entry.Suppressed, 10))
	}
	line := entry.OccurredAt + " [" + strings.ToUpper(entry.Severity) + "] [" + entry.Component + "] [" + entry.Unit + "] " + entry.Message
	if len(scope) != 0 {
		line += " | " + strings.Join(scope, " ")
	}
	return truncateUTF8Bytes(SanitizeText(line), 4094) + "\n"
}

func validateExportTree(root string) error {
	for _, directory := range []string{root, filepath.Join(root, "current"), filepath.Join(root, "archive"), filepath.Join(root, "diagnostics")} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("log export directory tree is unsafe")
		}
	}
	return nil
}

func rotateAndWriteExport(root, category string, content []byte, now time.Time, maximum int64) error {
	if !validCategory(category) || int64(len(content)) > maximum {
		return errors.New("rendered log export is invalid or oversized")
	}
	current := filepath.Join(root, "current", category+".log")
	if info, err := os.Lstat(current); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("current log export is unsafe")
		}
		if dateKey(info.ModTime().UTC()) != dateKey(now) && info.Size() > 0 && info.Size() <= maximum {
			previous, err := os.ReadFile(current)
			if err != nil || int64(len(previous)) != info.Size() {
				return errors.New("read previous log export failed")
			}
			archive := filepath.Join(root, "archive", category+"-"+dateKey(info.ModTime().UTC())+".log")
			if err := atomicExportWrite(archive, previous); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect current log export failed")
	}
	return atomicExportWrite(current, content)
}

type managedExportFile struct {
	path    string
	archive bool
	modTime time.Time
	size    int64
}

func cleanupManagedExports(root string, policy ExportPolicy, now time.Time, removeAll bool) error {
	selected := make(map[string]struct{}, len(policy.Categories))
	for _, category := range policy.Categories {
		selected[category] = struct{}{}
	}
	files, err := managedExports(root)
	if err != nil {
		return err
	}
	archives := make([]managedExportFile, 0)
	var total int64
	cutoff := now.Add(-time.Duration(policy.RetentionDays) * 24 * time.Hour)
	for _, file := range files {
		category := exportCategoryFromName(filepath.Base(file.path), file.archive)
		_, enabled := selected[category]
		if removeAll || !enabled || file.archive && file.modTime.Before(cutoff) {
			if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("remove expired managed log export failed")
			}
			continue
		}
		total += file.size
		if file.archive {
			archives = append(archives, file)
		}
	}
	sort.Slice(archives, func(left, right int) bool { return archives[left].modTime.Before(archives[right].modTime) })
	for len(archives) > policy.MaxArchiveFiles || total > policy.MaxTotalBytes {
		oldest := archives[0]
		archives = archives[1:]
		if err := os.Remove(oldest.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("enforce managed log export budget failed")
		}
		total -= oldest.size
	}
	if total > policy.MaxTotalBytes {
		return errors.New("current log exports exceed total disk budget")
	}
	return syncDirectory(filepath.Join(root, "archive"))
}

func managedExports(root string) ([]managedExportFile, error) {
	result := make([]managedExportFile, 0)
	for _, current := range []bool{true, false} {
		directory := filepath.Join(root, "archive")
		if current {
			directory = filepath.Join(root, "current")
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, errors.New("read managed log export directory failed")
		}
		for _, entry := range entries {
			name := entry.Name()
			category := exportCategoryFromName(name, !current)
			if category == "" {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, errors.New("managed log export is unsafe")
			}
			result = append(result, managedExportFile{path: filepath.Join(directory, name), archive: !current, modTime: info.ModTime().UTC(), size: info.Size()})
		}
	}
	return result, nil
}

func exportCategoryFromName(name string, archive bool) string {
	if !archive {
		category := strings.TrimSuffix(name, ".log")
		if category+".log" == name && validCategory(category) {
			return category
		}
		return ""
	}
	match := archiveLogName.FindStringSubmatch(name)
	if len(match) == 3 && validCategory(match[1]) {
		return match[1]
	}
	return ""
}

func atomicExportWrite(filename string, content []byte) error {
	if len(content) == 0 || !utf8.Valid(content) {
		return errors.New("log export content is invalid")
	}
	directory := filepath.Dir(filename)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("log export parent directory is unsafe")
	}
	if existing, err := os.Lstat(filename); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return errors.New("log export target is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect log export target failed")
	}
	temporary, err := os.CreateTemp(directory, ".gateway-vpn-log-*")
	if err != nil {
		return errors.New("create log export temporary file failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	fail := func(cause error) error {
		_ = temporary.Close()
		return cause
	}
	if err := temporary.Chmod(0o640); err != nil {
		return fail(errors.New("set log export permissions failed"))
	}
	if _, err := temporary.Write(content); err != nil {
		return fail(errors.New("write log export failed"))
	}
	if err := temporary.Sync(); err != nil {
		return fail(errors.New("sync log export failed"))
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close log export failed")
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		if removeErr := os.Remove(filename); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.New("replace log export failed")
		}
		if retryErr := os.Rename(temporaryName, filename); retryErr != nil {
			return errors.New("replace log export failed")
		}
	}
	return syncDirectory(directory)
}

func dateKey(value time.Time) string { return value.UTC().Format("20060102") }
