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

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/db"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/directprobe"
	"gateway-vpn/internal/health"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/updateautomation"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/watchdog"
	"gateway-vpn/internal/webapi"
	"gateway-vpn/internal/wgingress"
)

const previewPassword = "gateway-vpn-preview-only"

type previewRefresher struct{}

type previewDirectProbe struct{}

type previewRestorePoints struct {
	mutex sync.Mutex
	items []updatepkg.RestorePoint
}

func (points *previewRestorePoints) RestorePointInventory(context.Context) ([]updatepkg.RestorePoint, error) {
	points.mutex.Lock()
	defer points.mutex.Unlock()
	return append([]updatepkg.RestorePoint(nil), points.items...), nil
}

func (points *previewRestorePoints) DeleteRestorePoint(_ context.Context, pointID string) error {
	points.mutex.Lock()
	defer points.mutex.Unlock()
	for index, item := range points.items {
		if item.Manifest.PointID != pointID {
			continue
		}
		if item.Protected {
			return errors.New("preview restore point is protected")
		}
		points.items = append(points.items[:index], points.items[index+1:]...)
		return nil
	}
	return errors.New("preview restore point was not found")
}

func (points *previewRestorePoints) PruneRestorePoints(context.Context, updatepkg.RestorePointPolicy) ([]string, error) {
	points.mutex.Lock()
	defer points.mutex.Unlock()
	kept := points.items[:0]
	removed := make([]string, 0)
	for _, item := range points.items {
		if item.Protected {
			kept = append(kept, item)
			continue
		}
		removed = append(removed, item.Manifest.PointID)
	}
	points.items = kept
	return removed, nil
}

func (points *previewRestorePoints) RollbackToRestorePoint(_ context.Context, pointID string) error {
	points.mutex.Lock()
	defer points.mutex.Unlock()
	for _, item := range points.items {
		if item.Manifest.PointID == pointID && item.Compatible {
			return nil
		}
	}
	return errors.New("preview restore point is unavailable or incompatible")
}

func (previewDirectProbe) ProbeAllNow(context.Context) (directprobe.CycleResult, error) {
	return directprobe.CycleResult{Due: 5, Probed: 5, Published: 5, Errors: map[string]string{}}, nil
}

func (previewRefresher) RefreshOne(_ context.Context, subscriptionID string, _ bool) (subscription.RefreshResult, error) {
	return subscription.RefreshResult{SubscriptionID: subscriptionID, VersionID: "preview-version"}, nil
}

func (previewRefresher) ReclassifyOne(_ context.Context, subscriptionID string) (subscription.RefreshResult, error) {
	return subscription.RefreshResult{SubscriptionID: subscriptionID, VersionID: "preview-version"}, nil
}

type previewDispatcher struct {
	mutex      sync.Mutex
	sequence   int
	operations *operations.Repository
}

func (dispatcher *previewDispatcher) Enqueue(ctx context.Context, subscriptionID, requestedBy string) (subscription.DispatchResult, error) {
	dispatcher.mutex.Lock()
	defer dispatcher.mutex.Unlock()
	dispatcher.sequence++
	id := fmt.Sprintf("preview-refresh-%d", dispatcher.sequence)
	if _, err := dispatcher.operations.Create(ctx, operations.CreateInput{ID: id, Kind: "SUBSCRIPTION_REFRESH", ScopeType: "SUBSCRIPTION", ScopeID: subscriptionID, RequestedBy: requestedBy}); err != nil {
		return subscription.DispatchResult{}, err
	}
	if _, err := dispatcher.operations.Start(ctx, id, operations.StepInput{Severity: "INFO", Stage: "HTTP", Code: "FETCH_STARTED", Message: "Preview: источник подписки проверяется."}); err != nil {
		return subscription.DispatchResult{}, err
	}
	if _, err := dispatcher.operations.Finish(ctx, id, operations.StatusSucceeded, "REFRESH_COMPLETE", operations.StepInput{Severity: "INFO", Stage: "COMPLETE", Code: "REFRESH_COMPLETE", Message: "Preview: подписка проверена и активирована."}); err != nil {
		return subscription.DispatchResult{}, err
	}
	return subscription.DispatchResult{OperationID: id, SubscriptionID: subscriptionID}, nil
}

type previewRuntime struct{}

func (previewRuntime) BlockPath(context.Context) error            { return nil }
func (previewRuntime) SyncRouting(context.Context) error          { return nil }
func (previewRuntime) SyncWireGuard(context.Context) error        { return nil }
func (previewRuntime) SyncManagementFabric(context.Context) error { return nil }
func (previewRuntime) ManagementFabricStatus(context.Context) (networkapply.ManagementFabricStatus, error) {
	return networkapply.ManagementFabricStatus{}, nil
}
func (previewRuntime) ProbeManagementResource(_ context.Context, id string) (managementfabric.ResourceProbeResult, error) {
	return managementfabric.ResourceProbeResult{ResourceID: id, RouteGeneration: 1, State: "HEALTHY", ReasonCode: "RESOURCE_PROBE_PASSED", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}
func (previewRuntime) ConfigureAdminContour(context.Context, managementfabric.AdminContourRequest) (managementfabric.AdminContour, error) {
	return managementfabric.AdminContour{}, errors.New("preview administrator contour mutation is disabled")
}
func (previewRuntime) RotateAdminContourIdentity(context.Context) (managementfabric.AdminContour, error) {
	return managementfabric.AdminContour{}, errors.New("preview administrator contour rotation is disabled")
}

// previewNetworkBroker exposes the complete safe-apply WebUI without ever
// touching the developer workstation. It deliberately returns synthetic
// transactions and previews only; production uses the privileged broker.
type previewNetworkBroker struct{}

func (previewNetworkBroker) Stage(_ context.Context, candidate networkapply.Candidate) (networkapply.Prepared, error) {
	if candidate.Topology == nil && candidate.NewLANCIDR == "" {
		return networkapply.Prepared{}, errors.New("preview network candidate is empty")
	}
	return networkapply.Prepared{
		ApplyID:          "apply-0123456789abcdef0123456789abcdef",
		ConfirmToken:     strings.Repeat("c", 64),
		OldURL:           candidate.OldURL,
		NewURL:           candidate.NewURL,
		RollbackDeadline: time.Now().UTC().Add(time.Minute),
	}, nil
}

func (previewNetworkBroker) Apply(context.Context, string) error { return nil }

func (previewNetworkBroker) Confirm(context.Context, string, networkapply.ConfirmEvidence) error {
	return nil
}

func (previewNetworkBroker) PreviewTopology(_ context.Context, candidate networkapply.Candidate) (networkapply.TopologyPreview, error) {
	if candidate.Topology == nil {
		return networkapply.TopologyPreview{}, errors.New("preview topology candidate is missing")
	}
	mutation := candidate.Topology
	required := []string{"ACCEPT_TEMPORARY_DISCONNECT"}
	switch mutation.Profile {
	case networkapply.TopologyOneArmWireGuard:
		required = append(required, "CONFIGURE_KEENETIC_WIREGUARD", "VERIFY_UPSTREAM_RETURN_PATH")
	case networkapply.TopologyEthernetHiLink, networkapply.TopologyEthernetEthernet, networkapply.TopologyMixed:
		required = append(required, "MOVE_LAN_CABLES", "CONFIGURE_KEENETIC_WAN_DHCP")
	default:
		return networkapply.TopologyPreview{}, errors.New("preview topology profile is invalid")
	}
	acknowledged := make(map[string]struct{}, len(mutation.AcknowledgedPrerequisites))
	for _, item := range mutation.AcknowledgedPrerequisites {
		acknowledged[item] = struct{}{}
	}
	missing := make([]string, 0, len(required))
	for _, item := range required {
		if _, ok := acknowledged[item]; !ok {
			missing = append(missing, item)
		}
	}
	affectedSet := make(map[string]struct{})
	affected := make([]string, 0, len(mutation.LANInterfaceIDs)+len(mutation.ManagementInterfaceIDs)+len(mutation.WGEndpointInterfaceIDs)+1)
	for _, values := range [][]string{mutation.LANInterfaceIDs, mutation.ManagementInterfaceIDs, mutation.WGEndpointInterfaceIDs} {
		for _, item := range values {
			if _, exists := affectedSet[item]; exists {
				continue
			}
			affectedSet[item] = struct{}{}
			affected = append(affected, item)
		}
	}
	if mutation.SharedOneArmInterfaceID != "" {
		if _, exists := affectedSet[mutation.SharedOneArmInterfaceID]; !exists {
			affected = append(affected, mutation.SharedOneArmInterfaceID)
		}
	}
	return networkapply.TopologyPreview{
		CurrentProfile:               networkapply.TopologyEthernetHiLink,
		CandidateProfile:             mutation.Profile,
		CurrentDesiredGeneration:     mutation.ExpectedDesiredGeneration,
		CandidateDesiredGeneration:   mutation.ExpectedDesiredGeneration + 1,
		OldURL:                       candidate.OldURL,
		NewURL:                       candidate.NewURL,
		RequiredPrerequisites:        required,
		MissingPrerequisites:         missing,
		RequireWireGuardConfirmation: candidate.RequireWireGuardConfirmation,
		ManagementInterfaces:         append([]string(nil), mutation.ManagementInterfaceIDs...),
		AffectedInterfaces:           affected,
	}, nil
}

type previewIngressController struct{ backend *wgingress.Backend }

func (controller previewIngressController) SyncWireGuardIngress(ctx context.Context) error {
	return controller.backend.Sync(ctx)
}
func (controller previewIngressController) UpdateWireGuardIngressServer(ctx context.Context, input wgingress.ServerUpdate) (wgingress.Server, error) {
	return controller.backend.UpdateServer(ctx, input)
}
func (controller previewIngressController) RotateWireGuardIngressServer(ctx context.Context) (wgingress.Server, error) {
	return controller.backend.RotateServer(ctx)
}
func (controller previewIngressController) CreateWireGuardIngressPeer(ctx context.Context, input wgingress.PeerCreate) (wgingress.Peer, error) {
	return controller.backend.CreatePeer(ctx, input)
}
func (controller previewIngressController) UpdateWireGuardIngressPeer(ctx context.Context, id string, input wgingress.PeerUpdate) (wgingress.Peer, error) {
	return controller.backend.UpdatePeer(ctx, id, input)
}
func (controller previewIngressController) RevokeWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	return controller.backend.RevokePeer(ctx, id)
}
func (controller previewIngressController) DeleteWireGuardIngressPeer(ctx context.Context, id string) error {
	return controller.backend.DeletePeer(ctx, id)
}
func (controller previewIngressController) RotateWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	return controller.backend.RotatePeer(ctx, id)
}
func (controller previewIngressController) ProbeWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	return controller.backend.ProbePeer(ctx, id)
}
func (controller previewIngressController) ExportWireGuardIngressPeer(ctx context.Context, id string) (wgingress.ExportedConfig, error) {
	return controller.backend.ExportPeerConfig(ctx, id)
}

type previewNoCommandExecutor struct{}

func (previewNoCommandExecutor) Run(context.Context, platformexec.Request) (platformexec.Result, error) {
	return platformexec.Result{}, errors.New("preview host mutation is disabled")
}

type previewWatchdogStatus struct{}

func (previewWatchdogStatus) Read() (watchdog.Status, error) {
	now := time.Now().UTC()
	components := make([]watchdog.ComponentStatus, 0, len(watchdog.ComponentSpecs()))
	for _, spec := range watchdog.ComponentSpecs() {
		item := watchdog.ComponentStatus{
			ID: spec.ID, Label: spec.Label, State: watchdog.ComponentHealthy, Applicable: true,
			ConsecutiveSuccesses: 8, LastSuccessAt: now.Add(-5 * time.Second).Format(time.RFC3339Nano),
			Details: map[string]any{"preview": true},
		}
		if spec.ID == watchdog.ComponentWireGuardMgmt {
			item.State = watchdog.ComponentDegraded
			item.Classification = watchdog.ClassificationExternal
			item.ErrorCode = "WG_VPS_HANDSHAKE_STALE"
			item.ConsecutiveFailures = 2
			item.ConsecutiveSuccesses = 0
			item.LastFailureAt = now.Add(-10 * time.Second).Format(time.RFC3339Nano)
			item.RecoverySuppressed = true
			item.SuppressionReason = "EXTERNAL_CONNECTIVITY_FAILURE"
		}
		components = append(components, item)
	}
	return watchdog.Status{
		SchemaVersion: 1, SupervisorStartedAt: now.Add(-6 * time.Hour).Format(time.RFC3339Nano),
		ObservedAt: now.Format(time.RFC3339Nano), OverallState: watchdog.OverallRecoverySuppressed,
		ConnectivityState: "LIMITED", ConnectivityClass: watchdog.ClassificationExternal,
		PolicySource: "DATABASE", Components: components,
	}, nil
}

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

type previewUpdateAutomation struct {
	status updateautomation.Status
}

func (automation previewUpdateAutomation) Status(context.Context) (updateautomation.Status, error) {
	return automation.status, nil
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
	return runContext(context.Background(), address, restorePending, updatePending, mustChangePassword)
}

func runContext(parent context.Context, address string, restorePending, updatePending, mustChangePassword bool) error {
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
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
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
	uplinks := uplink.NewRepository(database, 1101, 0x1101)
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
	if _, err := uplinks.ObserveInterface(ctx, uplink.InterfaceObservation{
		ID: "netif:preview:ethernet", StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: strings.Repeat("e", 64), PermanentMAC: "02:00:00:12:34:56",
		TopologyPath: "pci-0000:03:00.0", CurrentIfname: "enp3s0", Driver: "igc",
		Vendor: "Intel", Model: "I225-V", CarrierState: "DOWN", Addresses: []string{},
	}); err != nil {
		return err
	}
	if _, err := uplinks.ObserveInterface(ctx, uplink.InterfaceObservation{
		ID: "netif:preview:lan", StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: strings.Repeat("a", 64), PermanentMAC: "02:00:00:65:43:21",
		TopologyPath: "pci-0000:02:00.0", CurrentIfname: "enp2s0", Driver: "r8169",
		Vendor: "Realtek", Model: "RTL8111/8168/8411", CarrierState: "UP", Addresses: []string{"192.168.200.1/24"},
	}); err != nil {
		return err
	}
	if _, err := uplinks.ObserveInterface(ctx, uplink.InterfaceObservation{
		ID: "netif:preview:spare", StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: strings.Repeat("b", 64), PermanentMAC: "02:00:00:aa:bb:cc",
		TopologyPath: "usb-0:4:1.0", CurrentIfname: "enp4s0", Driver: "r8152",
		Vendor: "Realtek", Model: "USB GbE", CarrierState: "DOWN", Addresses: []string{},
	}); err != nil {
		return err
	}
	if _, err := uplinks.SeedInitialLANRoles(ctx, "enp2s0", []uplink.InitialLANObservation{
		{NetworkInterfaceID: "netif:preview:lan", CurrentIfname: "enp2s0"},
		{NetworkInterfaceID: "netif:preview:ethernet", CurrentIfname: "enp3s0"},
		{NetworkInterfaceID: "netif:preview:spare", CurrentIfname: "enp4s0"},
	}); err != nil {
		return err
	}
	if _, err := uplinks.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-preview", Name: "Резервный Ethernet", NetworkInterfaceID: "netif:preview:ethernet",
		AddressMode: uplink.AddressDHCP, MTU: 1500,
	}); err != nil {
		return err
	}
	if _, err := uplinks.EnsureManagedLANInterface(ctx, "gateway-vpn-lan", "192.168.200.1/24"); err != nil {
		return err
	}
	if err := seedManagementFabric(ctx, database); err != nil {
		return err
	}
	ingressSecretRoot := filepath.Join(root, "secrets", "wireguard-ingress")
	ingressRepository := &wgingress.Repository{Database: database, SecretRoot: ingressSecretRoot, ReservedPrefixes: []netip.Prefix{netip.MustParsePrefix("192.168.200.0/24")}}
	ingressBackend := &wgingress.Backend{
		Repository: *ingressRepository, Keys: wgingress.KeyStore{Root: ingressSecretRoot}, Executor: previewNoCommandExecutor{},
		IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", Mutate: false,
	}
	if err := ingressBackend.Sync(ctx); err != nil {
		return err
	}
	if _, err := ingressBackend.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: false, Name: "WireGuard для клиентов", SubnetCIDR: "10.90.0.0/24",
		ListenPort: 51820, EndpointHost: "gateway.example.org", MTU: 1420, TopologyMode: "ROUTED",
		DNS: []string{"1.1.1.1"}, ListenInterfaces: []wgingress.ListenInterface{{
			NetworkInterfaceID: uplink.ManagedLANInterfaceID, ExposureMode: "LOCAL", Priority: 1,
		}},
	}); err != nil {
		return err
	}
	if _, err := ingressBackend.CreatePeer(ctx, wgingress.PeerCreate{
		Name: "Телефон — preview", PeerKind: "DEVICE", KeyMode: "MANAGED",
		PersistentKeepalive: 25, AccessPolicyMode: "AUTO", AllowWhitelistOnly: true,
		BlockWhenUnqualified: true, ClientDNSEnabled: true, ClientAllowedIPs: []string{"0.0.0.0/0"},
	}); err != nil {
		return err
	}
	if err := paths.ReconcileCells(ctx); err != nil {
		return err
	}
	previewNow := time.Now().UTC()
	directPaths := accesspolicy.NewDirectPathRepository(database)
	if err := directPaths.Reconcile(ctx); err != nil {
		return err
	}
	allDirectPaths, err := directPaths.List(ctx)
	if err != nil {
		return err
	}
	for _, path := range allDirectPaths {
		if path.UplinkID != "modem-a" {
			continue
		}
		if err := directPaths.Publish(ctx, accesspolicy.DirectResultUpdate{
			PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration, ExpectedRouteGeneration: path.RouteGeneration,
			TransportState: "PASSED", QualityClass: accesspolicy.QualityFull, FunctionalScore: 2002,
			RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, OptionalTargetsPassed: 1, OptionalTargetsTotal: 1,
			LatencyMS: 47, CheckedAt: previewNow, ExpiresAt: previewNow.Add(5 * time.Minute),
			Targets: []accesspolicy.DirectTargetResult{
				{TargetID: "target-required", TargetClass: "GLOBAL_REQUIRED", State: "PASSED", LatencyMS: 21, HTTPStatus: 204, CheckedAt: previewNow, ExpiresAt: previewNow.Add(5 * time.Minute)},
				{TargetID: "target-optional", TargetClass: "GLOBAL_OPTIONAL", State: "PASSED", LatencyMS: 26, HTTPStatus: 200, CheckedAt: previewNow, ExpiresAt: previewNow.Add(5 * time.Minute)},
			},
		}); err != nil {
			return err
		}
	}
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
	operationRepository := operations.NewRepository(database)
	watchdogRepository := &watchdog.Repository{Database: database}
	networkBroker := previewNetworkBroker{}
	updateRestorePoints := &previewRestorePoints{items: []updatepkg.RestorePoint{
		{
			Manifest: updatepkg.RestorePointManifest{
				FormatVersion: updatepkg.RestorePointFormatVersion, PointID: "point-20260830T030000Z-0123456789abcdef01234567", Kind: updatepkg.RestorePointKindPreUpdate,
				CreatedAt: previewNow.Add(-30 * time.Hour).Format(time.RFC3339Nano), GatewayVersion: "1.1.0", SchemaVersion: 33, TotalBytes: 780 << 20, Verification: "PASS",
			},
			Protected: true, Roles: []string{"CURRENT", "RECOVERY"}, Compatible: true,
		},
		{
			Manifest: updatepkg.RestorePointManifest{
				FormatVersion: updatepkg.RestorePointFormatVersion, PointID: "point-20260801T030000Z-89abcdef0123456789abcdef", Kind: updatepkg.RestorePointKindPreUpdate,
				CreatedAt: previewNow.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano), GatewayVersion: "1.0.0", SchemaVersion: 30, TotalBytes: 704 << 20, Verification: "PASS",
			},
			Compatible: false, CompatibilityReason: "HOST_CONTRACT_CHANGED",
		},
	}}
	api, err := webapi.New(webapi.Dependencies{
		Database: database, Auth: authService, State: state.NewRepository(database),
		Modems: modems, Uplinks: uplinks, Subscriptions: subscriptions, Nodes: subscription.NewNodeRepository(database), Paths: paths, Targets: targets, Matchers: matchers,
		WireGuardIngress: ingressRepository, WireGuardIngressAdmin: previewIngressController{backend: ingressBackend},
		ManagementFabric: managementfabric.NewRepository(database, nil), ManagementFabricAdmin: previewRuntime{},
		DirectPaths:         directPaths,
		DirectPathProbe:     previewDirectProbe{},
		SubscriptionRefresh: previewRefresher{}, SubscriptionDispatch: &previewDispatcher{operations: operationRepository}, Operations: operationRepository,
		BootIDReader: func() (string, error) { return "11111111-2222-3333-4444-555555555555", nil }, SubscriptionSecretRoot: secretRoot,
		SubscriptionPayloadRoot: payloadRoot, ModemRuntime: previewRuntime{},
		NetworkBroker: networkBroker,
		NetworkCandidate: func(_ context.Context, value string) (networkapply.Candidate, error) {
			prefix, parseErr := netip.ParsePrefix(value)
			if parseErr != nil || !prefix.Addr().Is4() {
				return networkapply.Candidate{}, errors.New("preview LAN address must be an IPv4 CIDR")
			}
			return networkapply.Candidate{
				InterfaceName: "gateway-vpn-lan", OldLANCIDR: "192.168.200.1/24", NewLANCIDR: prefix.String(),
				OldURL: "https://192.168.200.1:8443", NewURL: "https://" + net.JoinHostPort(prefix.Addr().String(), "8443"),
				ManagementDestinationIP: prefix.Addr().String(),
			}, nil
		},
		NetworkInterface: "gateway-vpn-lan", NetworkLANAddress: "192.168.200.1/24",
		PathOperations: previewPathOperations{}, PathActivator: previewPathActivator{},
		PeriodicHealth: periodicHealth, PeriodicHealthConfig: candidateruntime.DefaultPeriodicConfig(), ProbeBudget: probeScheduler,
		Logging:  loggingController,
		Watchdog: watchdogRepository, WatchdogStatus: previewWatchdogStatus{},
		Journal: previewJournal{}, Diagnostics: previewDiagnostics{}, Backups: backupManager, PortableBackups: portableBackups,
		Restores: restores, RestoreApply: previewRestoreApply{}, Updates: updates, UpdateApply: previewUpdateApply{status: networkapply.UpdateTransactionStatus{
			Exists: true, UpdateID: "update-20260824T210000Z-fedcba9876543210fedcba98", State: "FINALIZED",
			StartedAt: previewNow.Add(-48 * time.Hour).Format(time.RFC3339Nano), UpdatedAt: previewNow.Add(-24 * time.Hour).Format(time.RFC3339Nano),
			OldVersion: "1.0.0", NewVersion: "1.1.0", StabilityDeadline: previewNow.Add(-24 * time.Hour).Format(time.RFC3339Nano),
		}},
		UpdatePolicy: &updatepkg.AutomationPolicyRepository{Database: database, Now: func() time.Time { return previewNow }},
		UpdateAutomation: previewUpdateAutomation{status: updateautomation.Status{
			Phase: updateautomation.PhaseWaitingWindow, Channel: "stable", JitterOffsetMinutes: 17,
			NextCheckAt: previewNow.Add(6 * time.Hour).Format(time.RFC3339Nano), NextApplyAt: previewNow.Add(10 * time.Hour).Format(time.RFC3339Nano),
			CandidateVersion: "1.2.0", CandidateReference: "Go4a4a/Gateway-VPN#v1.2.0-" + strings.Repeat("signed-channel-reference-", 8),
			StagedUpdateID: "update-20260831T030000Z-0123456789abcdef01234567", StagedVersion: "1.2.0",
			LastAttemptAt: previewNow.Add(-10 * time.Minute).Format(time.RFC3339Nano), LastResultCode: "STAGED",
			ConsecutiveFailures: 0, UpdatedAt: previewNow.Format(time.RFC3339Nano),
		}},
		UpdateRestorePoints: updateRestorePoints,
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

func seedManagementFabric(ctx context.Context, database *sql.DB) error {
	repository := managementfabric.NewRepository(database, nil)
	if _, err := repository.EnsureLocalSite(ctx, "site:preview", "Домашний Gateway"); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for index, item := range []struct {
		vpsID, name, fingerprint, adminPool, aliasPool, subnet, local, remote, endpoint string
	}{
		{"vps:primary", "Основной VPS", strings.Repeat("a", 64), "10.81.0.0/24", "10.96.0.0/16", "10.82.0.0/24", "10.82.0.2", "10.82.0.1", "203.0.113.10"},
		{"vps:reserve", "Резервный VPS", strings.Repeat("b", 64), "10.83.0.0/24", "10.97.0.0/16", "10.84.0.0/24", "10.84.0.2", "10.84.0.1", "203.0.113.11"},
	} {
		vpsKeys, err := wgingress.GenerateKeyPair()
		if err != nil {
			return err
		}
		localKeys, err := wgingress.GenerateKeyPair()
		if err != nil {
			return err
		}
		vps, err := repository.CreateVPS(ctx, managementfabric.CreateVPSInput{
			ID: item.vpsID, Name: item.name, VerifiedFingerprint: item.fingerprint, PublicKey: vpsKeys.Public,
			AdminAddressPool: item.adminPool, ResourceAliasPool: item.aliasPool,
		})
		if err != nil {
			return err
		}
		link, err := repository.CreateLink(ctx, managementfabric.CreateLinkInput{
			ID: fmt.Sprintf("link:preview:%d", index+1), SiteID: "site:preview", VPSID: vps.ID, Enabled: true,
			ManagementSubnet: item.subnet, LocalAddress: item.local, RemoteAddress: item.remote,
			LocalPrivateKeySecretRef: fmt.Sprintf("/var/lib/gateway-vpn/secrets/management/preview-%d.key", index+1),
			LocalPublicKey:           localKeys.Public, RemotePublicKey: vpsKeys.Public,
			UplinkPolicy: managementfabric.UplinkAuto, PersistentKeepalive: 25,
			Endpoints: []managementfabric.EndpointSpec{{Host: item.endpoint, Port: 51821 + index}},
		})
		if err != nil {
			return err
		}
		if _, err := database.ExecContext(ctx, `UPDATE management_links SET selected_uplink_id='modem-a',state=? WHERE id=?`, map[bool]string{true: "REACHABLE", false: "DEGRADED"}[index == 0], link.ID); err != nil {
			return err
		}
	}
	adminKeys, err := wgingress.GenerateKeyPair()
	if err != nil {
		return err
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at) VALUES('admin:igor','Игорь','ADMIN',1,'ACTIVE',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_admin_vps_peers(id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at) VALUES('admin-peer:preview','admin:igor','vps:primary',?,'10.81.0.10','ACTIVE',1,1,?,?)`, []any{adminKeys.Public, stamp, stamp}},
		{`INSERT INTO management_resources(id,site_id,name,resource_kind,access_profile,local_destination,enabled,advanced_scope_acknowledged,desired_route_generation,applied_route_generation,health_state,health_reason_code,last_probe_at,last_probe_route_generation,probe_interface,created_at,updated_at) VALUES('resource:webui','site:preview','WebUI Gateway','GATEWAY_SERVICE','GATEWAY_ONLY','192.168.200.1',1,0,1,0,'HEALTHY','RESOURCE_PROBE_PASSED',?,1,'lo',?,?)`, []any{stamp, stamp, stamp}},
		{`INSERT INTO management_resource_ports(resource_id,protocol,port_start,port_end) VALUES('resource:webui','TCP',8443,8443)`, nil},
		{`INSERT INTO management_resource_publications(id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,desired_acl_generation,applied_acl_generation,state,created_at,updated_at) VALUES('publication:webui','resource:webui','link:preview:1','10.96.1.10/32',1,0,1,0,'PENDING',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_resource_acl(id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at) VALUES('acl:webui','admin:igor','resource:webui','TCP',8443,8443,1,1,?,?)`, []any{stamp, stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	contourKeys, err := wgingress.GenerateKeyPair()
	if err != nil {
		return err
	}
	if _, err := repository.ConfigureAdminContour(ctx, managementfabric.AdminContourRootInput{
		Enabled: true, InterfaceName: managementfabric.AdminInterfaceName,
		PrivateKeySecretRef: managementfabric.AdminPrivateKeySecretRef, PublicKey: contourKeys.Public,
		Subnet: "10.85.0.0/24", GatewayAddress: "10.85.0.1", ListenPort: managementfabric.AdminListenPort,
	}); err != nil {
		return err
	}
	if _, err := repository.CreateAdminRelay(ctx, managementfabric.AdminRelayInput{
		ID: "relay:preview", LinkID: "link:preview:1", Enabled: true,
		PublicEndpointHost: "relay.example.net", PublicBindAddress: "203.0.113.10", PublicUDPPort: 51830,
		RateLimitPerSecond: 100, BurstPackets: 200,
	}); err != nil {
		return err
	}
	if _, err := repository.CreateAdminTunnel(ctx, managementfabric.AdminTunnelInput{
		ID: "tunnel:preview", AdminID: "admin:igor", RelayID: "relay:preview",
		PublicKey: adminKeys.Public, AssignedAddress: "10.85.0.10",
	}); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, `
UPDATE management_admin_contour SET applied_generation=desired_generation,state='ACTIVE',last_error_code='';
UPDATE management_admin_relays SET applied_generation=desired_generation,state='ACTIVE',last_error_code='';
UPDATE management_admin_tunnels SET applied_generation=desired_generation,state='ACTIVE',latest_handshake_at=?,rx_bytes=524288,tx_bytes=262144,last_error_code=''
WHERE id='tunnel:preview'`, stamp); err != nil {
		return err
	}
	return nil
}

func modemDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
