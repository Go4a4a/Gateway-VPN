// Command webui-preview serves a loopback-only, disposable Gateway VPN UI
// with synthetic data. It never starts production workers or mutates host
// networking and exists solely for browser smoke tests during development.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/db"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/health"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/webapi"
)

const previewPassword = "gateway-vpn-preview-only"

type previewRefresher struct{}

func (previewRefresher) RefreshOne(_ context.Context, subscriptionID string, _ bool) (subscription.RefreshResult, error) {
	return subscription.RefreshResult{SubscriptionID: subscriptionID, VersionID: "preview-version"}, nil
}

func (previewRefresher) ReclassifyOne(_ context.Context, subscriptionID string) (subscription.RefreshResult, error) {
	return subscription.RefreshResult{SubscriptionID: subscriptionID, VersionID: "preview-version"}, nil
}

type previewRuntime struct{}

func (previewRuntime) BlockPath(context.Context) error     { return nil }
func (previewRuntime) SyncRouting(context.Context) error   { return nil }
func (previewRuntime) SyncWireGuard(context.Context) error { return nil }

type previewRestore struct {
	mutex     sync.Mutex
	operation backup.RestoreOperation
	pending   bool
}

func (restore *previewRestore) Stage(_ context.Context, reader io.Reader, passphrase string) (backup.RestoreOperation, error) {
	restore.mutex.Lock()
	defer restore.mutex.Unlock()
	if restore.pending {
		return backup.RestoreOperation{}, backup.ErrRestorePending
	}
	if err := backup.ValidatePassphrase(passphrase); err != nil {
		return backup.RestoreOperation{}, err
	}
	content, err := io.ReadAll(io.LimitReader(reader, backup.MaximumPortableBackupBytes+1))
	if err != nil || len(content) == 0 || int64(len(content)) > backup.MaximumPortableBackupBytes {
		return backup.RestoreOperation{}, errors.New("preview restore upload is invalid")
	}
	now := time.Now().UTC()
	restore.operation = backup.RestoreOperation{
		FormatVersion: backup.PortableFormatVersion, RestoreID: "restore-0123456789abcdef0123456789abcdef", State: backup.RestoreStateStaged,
		CreatedAt: now.Format(time.RFC3339Nano), SnapshotID: "preview-snapshot", SchemaVersion: 11, GatewayVersion: "gateway-vpn preview",
		PortableBytes: int64(len(content)), PortableSHA256: strings.Repeat("a", 64), ArchiveBytes: int64(len(content)), PayloadBytes: int64(len(content)), Files: 3,
	}
	restore.pending = true
	return restore.operation, nil
}

func (restore *previewRestore) Status() (backup.RestoreOperation, bool, error) {
	restore.mutex.Lock()
	defer restore.mutex.Unlock()
	return restore.operation, restore.pending, nil
}

func (restore *previewRestore) AuthorizeApply(restoreID string) (backup.RestoreOperation, error) {
	restore.mutex.Lock()
	defer restore.mutex.Unlock()
	if !restore.pending || restore.operation.RestoreID != restoreID || (restore.operation.State != backup.RestoreStateStaged && restore.operation.State != backup.RestoreStateApplyRequested) {
		return backup.RestoreOperation{}, backup.ErrRestoreNotPending
	}
	restore.operation.State = backup.RestoreStateApplyRequested
	restore.operation.ApplyErrorCode = ""
	return restore.operation, nil
}

func (restore *previewRestore) Discard(_ context.Context, restoreID string) error {
	restore.mutex.Lock()
	defer restore.mutex.Unlock()
	if !restore.pending || restore.operation.RestoreID != restoreID || restore.operation.State != backup.RestoreStateStaged {
		return backup.ErrRestoreNotPending
	}
	restore.pending = false
	return nil
}

type previewRestoreApply struct{}

func (previewRestoreApply) ApplyPendingRestore(context.Context) error { return nil }

type previewUpdate struct {
	mutex     sync.Mutex
	operation updatepkg.Operation
	pending   bool
}

func (update *previewUpdate) Stage(_ context.Context, reader io.Reader) (updatepkg.Operation, error) {
	update.mutex.Lock()
	defer update.mutex.Unlock()
	if update.pending {
		return updatepkg.Operation{}, updatepkg.ErrUpdatePending
	}
	content, err := io.ReadAll(io.LimitReader(reader, updatepkg.MaximumArchiveBytes+1))
	if err != nil || len(content) == 0 || int64(len(content)) > updatepkg.MaximumArchiveBytes {
		return updatepkg.Operation{}, errors.New("preview update upload is invalid")
	}
	update.operation = previewUpdateOperation(time.Now().UTC(), int64(len(content)))
	update.pending = true
	return update.operation, nil
}

func (update *previewUpdate) Status() (updatepkg.Operation, bool, error) {
	update.mutex.Lock()
	defer update.mutex.Unlock()
	return update.operation, update.pending, nil
}

func (update *previewUpdate) Discard(_ context.Context, updateID string) error {
	update.mutex.Lock()
	defer update.mutex.Unlock()
	if !update.pending || update.operation.UpdateID != updateID {
		return errors.New("preview update is not pending")
	}
	update.pending = false
	return nil
}

type previewUpdateApply struct {
	status networkapply.UpdateTransactionStatus
}

func (previewUpdateApply) ApplyPendingUpdate(context.Context) error { return nil }

func (update previewUpdateApply) UpdateStatus(context.Context) (networkapply.UpdateTransactionStatus, error) {
	return update.status, nil
}

func previewUpdateOperation(now time.Time, size int64) updatepkg.Operation {
	return updatepkg.Operation{
		FormatVersion: updatepkg.StagingFormatVersion, UpdateID: "update-20260825T000000Z-0123456789abcdef01234567", State: "STAGED",
		CreatedAt: now.Format(time.RFC3339Nano), GatewayVersion: "1.2.0", MihomoVersion: "v1.19.10",
		SignerKeySHA256: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), UncompressedBytes: size, FileCount: 12,
	}
}

type previewPathOperations struct{}

func (previewPathOperations) result(pathID, nodeID string, authoritative bool) candidateruntime.PathOperationResult {
	now := time.Now().UTC()
	return candidateruntime.PathOperationResult{
		PathID: pathID, NodeID: nodeID, Authoritative: authoritative,
		CheckedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Result: health.CellResult{
			PathID: pathID, ModemID: "modem-a", SubscriptionID: "sub-a",
			State: health.CellQualified, TransportState: health.ProbePassed,
			SelectedNodeID: nodeID, CandidateNodes: 1, QualifiedNodes: 1,
			RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 84,
			Nodes: []health.NodeResult{{
				NodeID: nodeID, State: health.NodeQualified,
				Transport:      health.ProbeResult{State: health.ProbePassed, LatencyMS: 18},
				RequiredPassed: 1, RequiredTotal: 1, AggregateLatencyMS: 84,
				Targets: []health.TargetResult{
					{TargetID: "target-required", Required: true, State: health.ProbePassed, LatencyMS: 31, HTTPStatus: 204},
					{TargetID: "target-optional", Required: false, State: health.ProbePassed, LatencyMS: 35, HTTPStatus: 200},
				},
			}},
		},
	}
}

func (operations previewPathOperations) ProbeNode(_ context.Context, pathID, nodeID string) (candidateruntime.PathOperationResult, error) {
	return operations.result(pathID, nodeID, false), nil
}

func (operations previewPathOperations) QualifyNode(_ context.Context, pathID, nodeID string) (candidateruntime.PathOperationResult, error) {
	return operations.result(pathID, nodeID, true), nil
}

func (operations previewPathOperations) QualifyPath(_ context.Context, pathID string) (candidateruntime.PathOperationResult, error) {
	return operations.result(pathID, "preview-node", true), nil
}

type previewPathActivator struct{}

func (previewPathActivator) ActivateExact(_ context.Context, pathID, nodeID string) (reconcile.Result, error) {
	return reconcile.Result{Action: "PATH_ACTIVATED", Candidate: reconcile.Candidate{PathID: pathID, ModemID: "modem-a", SubscriptionID: "sub-a", NodeID: nodeID}}, nil
}

type previewJournal struct{}

func (previewJournal) QueryLogs(_ context.Context, query loggingpkg.JournalQuery) (loggingpkg.JournalPage, error) {
	items := []loggingpkg.JournalEntry{
		{Cursor: "s=preview-newest", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Severity: loggingpkg.LevelInfo, Component: loggingpkg.ComponentPathHealth, Unit: "gateway-vpn.service", Message: "periodic path health cycle completed", ModemID: "modem-a", SubscriptionID: "sub-a", PathID: "path:modem-a:sub-a", CorrelationID: "preview-cycle"},
		{Cursor: "s=preview-older", OccurredAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), Severity: loggingpkg.LevelWarning, Component: loggingpkg.ComponentMihomo, Unit: "gateway-vpn-mihomo.service", Message: "synthetic preview warning without credentials"},
	}
	filtered := make([]loggingpkg.JournalEntry, 0, len(items))
	for _, item := range items {
		if query.Component != "" && query.Component != item.Component || query.Search != "" && !strings.Contains(strings.ToLower(item.Message), strings.ToLower(query.Search)) {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) > query.Limit {
		return loggingpkg.JournalPage{Items: filtered[:query.Limit], HasMore: true, NextCursor: filtered[query.Limit-1].Cursor}, nil
	}
	return loggingpkg.JournalPage{Items: filtered}, nil
}

type previewDiagnostics struct{}

func (previewDiagnostics) Describe(context.Context) (diagnostics.Description, error) {
	return diagnostics.Description{
		Available: true, Format: "zip", SchemaVersion: diagnostics.BundleSchemaVersion,
		DownloadEndpoint: "/api/v1/system/diagnostics", SecretsIncluded: false,
		MaximumArchiveBytes: diagnostics.MaximumBundleBytes, MaximumUncompressedBytes: diagnostics.MaximumBundleUncompressedBytes,
		ConfiguredJournalExcerptBytes: 1 << 20,
		Sections:                      []string{"versions", "sanitized_config", "host_network", "events", "journal", "sqlite_integrity"},
	}, nil
}

func (previewDiagnostics) Build(_ context.Context) (diagnostics.Bundle, error) {
	now := time.Now().UTC()
	manifest := diagnostics.Manifest{
		SchemaVersion: diagnostics.BundleSchemaVersion, GeneratedAt: now.Format(time.RFC3339Nano),
		GatewayVersion: "preview", Complete: true, SecretsIncluded: false,
		RedactionPolicy: "gateway-vpn-v1-double-pass", Files: []diagnostics.ManifestFile{},
		SectionErrors: []diagnostics.SectionError{}, SectionWarnings: []diagnostics.SectionError{},
	}
	payload, _ := json.MarshalIndent(manifest, "", "  ")
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "manifest.json", Method: zip.Deflate}
	header.SetMode(0o600)
	header.SetModTime(now)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return diagnostics.Bundle{}, err
	}
	if _, err := entry.Write(append(payload, '\n')); err != nil {
		return diagnostics.Bundle{}, err
	}
	if err := archive.Close(); err != nil {
		return diagnostics.Bundle{}, err
	}
	content := append([]byte(nil), buffer.Bytes()...)
	digest := sha256.Sum256(content)
	return diagnostics.Bundle{
		Filename: "gateway-vpn-diagnostics-" + now.Format("20060102T150405Z") + ".zip",
		Content:  content, SHA256: hex.EncodeToString(digest[:]), UncompressedSize: int64(len(payload) + 1), Manifest: manifest,
	}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "loopback preview address")
	restorePending := flag.Bool("restore-pending", false, "show a synthetic verified pending restore")
	updatePending := flag.Bool("update-pending", false, "show a synthetic verified pending signed update")
	mustChangePassword := flag.Bool("must-change-password", false, "show mandatory bootstrap password change")
	flag.Parse()
	if err := run(*listen, *restorePending, *updatePending, *mustChangePassword); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(address string, restorePending, updatePending, mustChangePassword bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse preview address: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("webui-preview only listens on a numeric loopback address")
	}
	root, err := os.MkdirTemp("", "gateway-vpn-webui-preview-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	secretRoot := filepath.Join(root, "secrets", "subscriptions")
	payloadRoot := filepath.Join(root, "subscriptions")
	if err := os.MkdirAll(secretRoot, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(payloadRoot, 0o700); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	database, err := db.Open(ctx, db.OpenOptions{Path: filepath.Join(root, "state.db")})
	if err != nil {
		return err
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		return err
	}
	authService := auth.Service{Database: database, Parameters: auth.Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}}
	if _, err := authService.CreateBootstrapAdmin(ctx, previewPassword); err != nil {
		return err
	}
	if !mustChangePassword {
		if _, err := database.ExecContext(ctx, "UPDATE users SET must_change_password=0 WHERE id='admin'"); err != nil {
			return err
		}
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	subscriptions := subscription.NewRepository(database)
	paths := pathmatrix.NewRepository(database)
	targets := bypass.NewRepository(database)
	matchers := subscription.NewMatcherRepository(database)
	if _, err := matchers.EnsureDefaults(ctx); err != nil {
		return err
	}
	if err := seed(ctx, database, modems, subscriptions, paths, targets, secretRoot); err != nil {
		return err
	}
	previewNow := time.Now().UTC()
	activePath, err := paths.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		return err
	}
	standbyPath, err := paths.Get(ctx, "modem-a", "sub-b")
	if err != nil {
		return err
	}
	periodicHealth := &health.PeriodicRepository{Database: database, Now: func() time.Time { return previewNow }}
	if err := periodicHealth.Reconcile(ctx, activePath.ID); err != nil {
		return err
	}
	if _, err := periodicHealth.Record(ctx, activePath.ID, health.PeriodicPassed, 10*time.Second, 0); err != nil {
		return err
	}
	if _, err := periodicHealth.Defer(ctx, standbyPath.ID, scheduler.DecisionDeferredBudget, time.Minute, 0); err != nil {
		return err
	}
	probeScheduler, err := scheduler.New(scheduler.DefaultConfig())
	if err != nil {
		return err
	}
	admission, err := probeScheduler.Acquire(ctx, scheduler.Request{ModemID: "modem-a", TargetID: "target-required", Class: scheduler.ClassActive, EstimatedBytes: 4096})
	if err != nil {
		return err
	}
	if admission.Permit != nil {
		admission.Permit.Release(3072)
	}
	loggingController, err := loggingpkg.NewController(loggingpkg.DefaultSettings(), nil)
	if err != nil {
		return err
	}
	if err := loggingController.Attach(ctx, database); err != nil {
		return err
	}
	backupManager, err := backup.NewManager(database, root, filepath.Join(root, "state.db"))
	if err != nil {
		return err
	}
	previewConfiguration := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(previewConfiguration, []byte("version: 1\n# synthetic preview configuration\n"), 0o600); err != nil {
		return err
	}
	portableBackups, err := backup.NewPortableManager(backupManager, root, previewConfiguration, "gateway-vpn preview")
	if err != nil {
		return err
	}
	restores := &previewRestore{}
	if restorePending {
		restores.pending = true
		restores.operation = backup.RestoreOperation{
			FormatVersion: backup.PortableFormatVersion, RestoreID: "restore-0123456789abcdef0123456789abcdef", State: backup.RestoreStateStaged,
			CreatedAt: previewNow.Format(time.RFC3339Nano), SnapshotID: "preview-snapshot", SchemaVersion: 11, GatewayVersion: "gateway-vpn preview",
			PortableBytes: 12 << 20, PortableSHA256: strings.Repeat("a", 64), ArchiveBytes: 20 << 20, PayloadBytes: 18 << 20, Files: 42,
		}
	}
	updates := &previewUpdate{}
	if updatePending {
		updates.pending = true
		updates.operation = previewUpdateOperation(previewNow, 42<<20)
	}
	api, err := webapi.New(webapi.Dependencies{
		Database: database, Auth: authService, State: state.NewRepository(database),
		Modems: modems, Subscriptions: subscriptions, Nodes: subscription.NewNodeRepository(database), Paths: paths, Targets: targets, Matchers: matchers,
		SubscriptionRefresh: previewRefresher{}, SubscriptionSecretRoot: secretRoot,
		SubscriptionPayloadRoot: payloadRoot, ModemRuntime: previewRuntime{},
		PathOperations: previewPathOperations{}, PathActivator: previewPathActivator{},
		PeriodicHealth: periodicHealth, PeriodicHealthConfig: candidateruntime.DefaultPeriodicConfig(), ProbeBudget: probeScheduler,
		Logging: loggingController,
		Journal: previewJournal{}, Diagnostics: previewDiagnostics{}, Backups: backupManager, PortableBackups: portableBackups,
		Restores: restores, RestoreApply: previewRestoreApply{}, Updates: updates, UpdateApply: previewUpdateApply{status: networkapply.UpdateTransactionStatus{
			Exists: true, UpdateID: "update-20260824T210000Z-fedcba9876543210fedcba98", State: "FINALIZED",
			StartedAt: previewNow.Add(-48 * time.Hour).Format(time.RFC3339Nano), UpdatedAt: previewNow.Add(-24 * time.Hour).Format(time.RFC3339Nano),
			OldVersion: "1.0.0", NewVersion: "1.1.0", StabilityDeadline: previewNow.Add(-24 * time.Hour).Format(time.RFC3339Nano),
		}},
	})
	if err != nil {
		return err
	}
	previewSession, err := authService.Login(ctx, "admin", previewPassword, "loopback-preview")
	if err != nil {
		return err
	}
	// Production cookies remain Secure-only. The disposable HTTP preview adds
	// its synthetic session server-side so browser smoke tests cannot weaken
	// the production authentication contract.
	previewHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Header.Set("Cookie", "gateway_vpn_session="+previewSession.Token)
		api.ServeHTTP(writer, request)
	})
	server := &http.Server{Addr: address, Handler: previewHandler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("Gateway VPN WebUI preview: http://%s/ (synthetic loopback session)\n", address)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func seed(ctx context.Context, database *sql.DB, modems *modem.Repository, subscriptions *subscription.Repository, paths *pathmatrix.Repository, targets *bypass.Repository, secretRoot string) error {
	versions := subscription.NewVersionRepository(database)
	for _, item := range []struct {
		id       string
		name     string
		operator string
	}{
		{id: "modem-a", name: "Основной LTE", operator: "Оператор A"},
		{id: "modem-b", name: "Резервный LTE", operator: "Оператор B"},
	} {
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: item.id, Name: item.name, OperatorLabel: item.operator, IdentityKind: "usb_serial_hash", IdentityHash: modemDigest(item.id)}); err != nil {
			return err
		}
	}
	if _, err := database.ExecContext(ctx, `
UPDATE modems
SET state='MODEM_READY', interface_name='enx001', management_cidr='192.168.8.100/24',
    gateway='192.168.8.1', observed_operator='Оператор A', management_reachability_state='REACHABLE'
WHERE id='modem-a'`); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, `
UPDATE modems
SET state='MODEM_CONFIGURED_OFFLINE', interface_name=NULL, management_cidr=NULL,
    gateway=NULL, observed_operator='Оператор B', management_reachability_state='UNTESTED'
WHERE id='modem-b'`); err != nil {
		return err
	}
	for _, item := range []struct {
		id       string
		name     string
		fallback bool
	}{
		{id: "sub-a", name: "Основная подписка", fallback: false},
		{id: "sub-b", name: "Резервная подписка", fallback: true},
	} {
		secretRef := filepath.Join(secretRoot, item.id+".url")
		if err := subscription.SaveURLSecret(secretRoot, secretRef, "https://subscriptions.example.com/"+item.id); err != nil {
			return err
		}
		if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: item.id, Name: item.name, SourceType: "url", SourceSecretRef: secretRef, RefreshInterval: time.Hour}); err != nil {
			return err
		}
		if err := subscriptions.Update(ctx, item.id, subscription.UpdateInput{Name: item.name, AutoRefresh: true, RefreshInterval: time.Hour, FallbackWhenNamedCandidatesFail: item.fallback}); err != nil {
			return err
		}
		payload := []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-" + item.id + "\n" +
			"vless://22222222-2222-2222-2222-222222222222@two.example:443#ordinary-" + item.id + "\n")
		staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-" + item.id, SubscriptionID: item.id, Payload: payload, Matchers: subscription.DefaultMatchers()})
		if err != nil {
			return err
		}
		if err := versions.Activate(ctx, staged.Version.ID); err != nil {
			return err
		}
	}
	if err := paths.ReconcileCells(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, input := range []bypass.CreateInput{
		{ID: "target-required", Name: "Обязательный доступ", Kind: bypass.KindDomain, Value: "example.com", Required: true, Timeout: 8 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse},
		{ID: "target-optional", Name: "Дополнительная проверка", Kind: bypass.KindURL, Value: "https://example.org/check", Required: false, Timeout: 8 * time.Second, SuccessMode: bypass.SuccessExpectedStatus, ExpectedStatus: "200-299"},
	} {
		if _, err := targets.Create(ctx, input); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		subscriptionID string
		qualified      bool
	}{
		{subscriptionID: "sub-a", qualified: true},
		{subscriptionID: "sub-b", qualified: false},
	} {
		subscriptionItem, err := subscriptions.Get(ctx, item.subscriptionID)
		if err != nil {
			return err
		}
		nodes, err := versions.ListNodes(ctx, subscriptionItem.ActiveVersionID, true)
		if err != nil {
			return fmt.Errorf("read preview candidate for %s: %w", item.subscriptionID, err)
		}
		if len(nodes) == 0 {
			return fmt.Errorf("preview subscription %s has no candidate node", item.subscriptionID)
		}
		cell, err := paths.Get(ctx, "modem-a", item.subscriptionID)
		if err != nil {
			return err
		}
		nodeState, cellState, selectedNodeID := pathmatrix.NodeBypassFailed, pathmatrix.StateFailed, ""
		passed, latency := int64(0), int64(141)
		targetEvidence := []pathmatrix.TargetEvidence{{TargetID: "target-required", State: health.ProbeFailed, ErrorCode: "PREVIEW_ACCESS_BLOCKED"}}
		if item.qualified {
			nodeState, cellState, selectedNodeID = pathmatrix.NodeBypassQualified, pathmatrix.StateQualified, nodes[0].ID
			passed, latency = 1, 84
			targetEvidence = []pathmatrix.TargetEvidence{{TargetID: "target-required", State: health.ProbePassed, LatencyMS: 31, HTTPStatus: 204}, {TargetID: "target-optional", State: health.ProbePassed, LatencyMS: 35, HTTPStatus: 200}}
		}
		if err := paths.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
			PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
			State: cellState, TransportState: health.ProbePassed, SelectedNodeID: selectedNodeID,
			RequiredTargetsPassed: passed, RequiredTargetsTotal: 1, LatencyMS: latency,
			CheckedAt: now, ExpiresAt: now.Add(5 * time.Minute),
			Nodes: []pathmatrix.NodeEvidence{{NodeID: nodes[0].ID, State: nodeState, LatencyMS: latency, ErrorCode: targetEvidence[0].ErrorCode, Targets: targetEvidence}},
		}); err != nil {
			return err
		}
	}
	if _, err := database.ExecContext(ctx, `
UPDATE subscriptions SET status='HEALTHY', last_refresh_at=?, last_success_at=? WHERE id='sub-a';
UPDATE subscriptions SET status='DEGRADED', last_refresh_at=?, last_success_at=? WHERE id='sub-b'`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return nil
}

func modemDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
