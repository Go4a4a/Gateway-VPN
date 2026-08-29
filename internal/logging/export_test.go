package logging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
)

type exportExecutor struct {
	result   platformexec.Result
	err      error
	requests []platformexec.Request
}

func (executor *exportExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return executor.result, executor.err
}

func TestExporterCreatesBoundedRedactedThematicSnapshots(t *testing.T) {
	ctx, repository, paths := exportFixture(t)
	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	lines := []string{
		journalJSON(t, "s=modem", now, "6", "gateway-vpn.service", `{"level":"INFO","msg":"modem https://example.net/check?token=private","component":"modem","modem_id":"modem-a"}`),
		journalJSON(t, "s=subscription", now.Add(-time.Second), "4", "gateway-vpn.service", `{"level":"WARN","msg":"subscription refresh failed password=hidden","component":"subscription","subscription_id":"sub-a"}`),
		journalJSON(t, "s=access", now.Add(-2*time.Second), "6", "gateway-vpn.service", `{"level":"INFO","msg":"path selected","component":"path_health","path_id":"path-a"}`),
		journalJSON(t, "s=watchdog", now.Add(-3*time.Second), "3", "gateway-vpn-watchdog.service", `watchdog recovered token=hidden`),
		journalJSON(t, "s=audit", now.Add(-4*time.Second), "6", "gateway-vpn.service", `{"level":"INFO","msg":"settings changed","component":"auth_audit","correlation_id":"corr-a"}`),
	}
	executor := &exportExecutor{result: platformexec.Result{Stdout: strings.Join(lines, "\n") + "\n"}}
	exporter := Exporter{Repository: repository, Executor: executor, Paths: paths, Now: func() time.Time { return now }}
	if err := exporter.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	all := readExport(t, paths.Root, "all")
	if strings.Contains(all, "private") || strings.Contains(all, "hidden") || !strings.Contains(all, "[REDACTED]") {
		t.Fatalf("all export redaction = %q", all)
	}
	if modem := readExport(t, paths.Root, "modems"); !strings.Contains(modem, "modem") || strings.Contains(modem, "subscription refresh") || !strings.Contains(modem, "modem=modem-a") {
		t.Fatalf("modem export = %q", modem)
	}
	if access := readExport(t, paths.Root, "access"); !strings.Contains(access, "path selected") || strings.Contains(access, "settings changed") {
		t.Fatalf("access export = %q", access)
	}
	if watchdog := readExport(t, paths.Root, "watchdog"); !strings.Contains(watchdog, "watchdog recovered") || strings.Contains(watchdog, "settings changed") {
		t.Fatalf("watchdog export = %q", watchdog)
	}
	if audit := readExport(t, paths.Root, "security-audit"); !strings.Contains(audit, "settings changed") || !strings.Contains(audit, "correlation=corr-a") {
		t.Fatalf("security audit export = %q", audit)
	}
	policy, err := repository.Get(ctx)
	if err != nil || policy.State != ExportApplied || policy.AppliedGeneration != policy.DesiredGeneration {
		t.Fatalf("applied export policy = %+v, %v", policy, err)
	}
	if len(executor.requests) != 1 || executor.requests[0].Executable != paths.Journalctl || executor.requests[0].MaxOutputBytes != exportJournalInputBytes {
		t.Fatalf("export command = %+v", executor.requests)
	}
	arguments := strings.Join(executor.requests[0].Arguments, " ")
	for _, required := range []string{"--namespace=gateway-vpn", "--output=json", "--reverse", "--lines=4096", "--since="} {
		if !strings.Contains(arguments, required) {
			t.Fatalf("export arguments missing %q: %s", required, arguments)
		}
	}
}

func TestExporterRotatesOncePerDayAndEnforcesGlobalArchiveCount(t *testing.T) {
	ctx, repository, paths := exportFixture(t)
	if _, err := repository.Database.ExecContext(ctx, `
UPDATE log_export_policy
SET categories_json='["all","modems"]', max_archive_files=1,
    desired_generation=desired_generation+1, state='PENDING'
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 8, 28, 23, 50, 0, 0, time.UTC)
	for _, category := range []string{"all", "modems"} {
		filename := filepath.Join(paths.Root, "current", category+".log")
		if err := os.WriteFile(filename, []byte("# previous "+category+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(filename, old, old); err != nil {
			t.Fatal(err)
		}
	}
	now := old.Add(20 * time.Minute)
	exporter := Exporter{Repository: repository, Executor: &exportExecutor{}, Paths: paths, Now: func() time.Time { return now }}
	if err := exporter.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	archives, err := os.ReadDir(filepath.Join(paths.Root, "archive"))
	if err != nil || len(archives) != 1 || !strings.HasSuffix(archives[0].Name(), "-20260828.log") {
		t.Fatalf("bounded daily archives = %+v, %v", archives, err)
	}
	for _, category := range []string{"all", "modems"} {
		if current := readExport(t, paths.Root, category); !strings.Contains(current, "generated_at=2026-08-29") {
			t.Fatalf("current %s export = %q", category, current)
		}
	}
}

func TestExporterRejectsSymlinkAndRecordsStableFailedState(t *testing.T) {
	ctx, repository, paths := exportFixture(t)
	target := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(paths.Root, "current", "all.log")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	exporter := Exporter{Repository: repository, Executor: &exportExecutor{}, Paths: paths}
	if err := exporter.Sync(ctx); err == nil {
		t.Fatal("symlink log export was accepted")
	}
	content, _ := os.ReadFile(target)
	if string(content) != "outside" {
		t.Fatalf("symlink target changed: %q", content)
	}
	policy, err := repository.Get(ctx)
	if err != nil || policy.State != ExportFailed {
		t.Fatalf("failed export state = %+v, %v", policy, err)
	}
}

func TestDisabledExporterRemovesOnlyManagedLogsWithoutQueryingJournal(t *testing.T) {
	ctx, repository, paths := exportFixture(t)
	if _, err := repository.Database.ExecContext(ctx, "UPDATE log_export_policy SET enabled=0, desired_generation=2, state='PENDING' WHERE singleton_id=1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Root, "current", "all.log"), []byte("managed"), 0o640); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(paths.Root, "current", "operator-note.txt")
	if err := os.WriteFile(foreign, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &exportExecutor{err: errors.New("journal must not be queried")}
	if err := (Exporter{Repository: repository, Executor: executor, Paths: paths}).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 0 {
		t.Fatalf("disabled exporter queried journal: %+v", executor.requests)
	}
	if _, err := os.Stat(filepath.Join(paths.Root, "current", "all.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed current file remains: %v", err)
	}
	if content, err := os.ReadFile(foreign); err != nil || string(content) != "preserve" {
		t.Fatalf("foreign file changed: %q, %v", content, err)
	}
	policy, err := repository.Get(ctx)
	if err != nil || policy.State != ExportDisabled || policy.AppliedGeneration != 2 {
		t.Fatalf("disabled export policy = %+v, %v", policy, err)
	}
}

func exportFixture(t *testing.T) (context.Context, ExportRepository, ExportPaths) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "gateway-vpn")
	for _, directory := range []string{root, filepath.Join(root, "current"), filepath.Join(root, "archive"), filepath.Join(root, "diagnostics")} {
		if err := os.Mkdir(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, ExportRepository{Database: database}, ExportPaths{Root: root, Journalctl: filepath.Join(t.TempDir(), "journalctl")}
}

func readExport(t *testing.T, root, category string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, "current", category+".log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
