package networkapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/diagnostics"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/modemrecovery"
	"gateway-vpn/internal/power"
	"gateway-vpn/internal/removal"
	"gateway-vpn/internal/traffic"
	"gateway-vpn/internal/wgingress"
)

const maxBrokerMessageBytes = 64 << 10

type BrokerServer struct {
	Engine           *Engine
	DataPlane        DataPlaneAdmin
	PathPlane        PathAdmin
	Routing          RoutingAdmin
	Bootstrap        BootstrapAdmin
	WireGuard        WireGuardAdmin
	Ingress          WireGuardIngressAdmin
	Logging          LoggingAdmin
	Journal          JournalAdmin
	Diagnostics      HostDiagnosticsAdmin
	Restore          RestoreAdmin
	Update           UpdateAdmin
	Traffic          TrafficAdmin
	Recovery         ModemRecoveryAdmin
	Power            PowerAdmin
	Removal          RemovalAdmin
	ManagementFabric ManagementFabricAdmin
	PortableBackup   PortableBackupAdmin
	Logger           *slog.Logger
	handler          http.Handler
}

// DataPlaneAdmin is the deliberately small privileged surface needed by the
// unprivileged control plane. Implementations may only operate fixed Gateway
// VPN systemd units; no unit name or command is accepted from HTTP input.
type DataPlaneAdmin interface {
	RestartMihomo(context.Context) error
	FailClosedMihomo(context.Context) error
}

type PathAdmin interface {
	ActivatePath(context.Context, uint32) error
	ActivateDirectPath(context.Context, string, int64) error
	BlockPath(context.Context) error
	ObservePath(context.Context) (dataplane.PathState, error)
}

// RoutingAdmin exposes one parameter-free reconciliation operation. The
// privileged implementation derives its complete desired state from SQLite.
type RoutingAdmin interface {
	SyncRouting(context.Context) error
}

type BootstrapAdmin interface {
	AuthorizeBootstrap(context.Context, dataplane.BootstrapAuthorization) error
	AuthorizeDirectProbe(context.Context, dataplane.DirectProbeAuthorization) error
	AuthorizeMihomoEndpoints(context.Context, dataplane.MihomoEndpointAuthorization) error
}

// WireGuardAdmin exposes only an input-free convergence operation. Endpoint,
// keys, modem identity and routing context are read by the root backend from
// protected configuration and SQLite rather than accepted across HTTP.
type WireGuardAdmin interface {
	SyncWireGuard(context.Context) error
}

// WireGuardIngressAdmin owns the root-only key files and kernel interface for
// the optional client/data-plane WireGuard server. Inputs are fixed typed
// domain objects; no path, executable, nft expression or command crosses the
// privilege boundary.
type WireGuardIngressAdmin interface {
	Sync(context.Context) error
	UpdateServer(context.Context, wgingress.ServerUpdate) (wgingress.Server, error)
	CreatePeer(context.Context, wgingress.PeerCreate) (wgingress.Peer, error)
	UpdatePeer(context.Context, string, wgingress.PeerUpdate) (wgingress.Peer, error)
	RevokePeer(context.Context, string) (wgingress.Peer, error)
	DeletePeer(context.Context, string) error
	RotatePeer(context.Context, string) (wgingress.Peer, error)
	RotateServer(context.Context) (wgingress.Server, error)
	ProbePeer(context.Context, string) (wgingress.Peer, error)
	ExportPeerConfig(context.Context, string) (wgingress.ExportedConfig, error)
}

// LoggingAdmin exposes only parameter-free convergence. The root
// implementation reads validated retention settings from SQLite and writes
// one fixed namespaced-journald drop-in.
type LoggingAdmin interface {
	SyncLogging(context.Context) error
}

type JournalAdmin interface {
	QueryLogs(context.Context, loggingpkg.JournalQuery) (loggingpkg.JournalPage, error)
}

type HostDiagnosticsAdmin interface {
	Collect(context.Context) (diagnostics.HostSnapshot, error)
}

// RestoreAdmin exposes one parameter-free operation. The privileged backend
// independently reads and verifies the one pending restore before starting a
// fixed systemd helper; no restore id, path, unit, or command is accepted.
type RestoreAdmin interface {
	ApplyPendingRestore(context.Context) error
}

// UpdateAdmin starts one fixed root update helper and returns a deliberately
// small, path-free view of its root-owned transaction journal. Candidate id,
// path, version and unit name are never accepted across the privilege boundary;
// the helper independently reads and re-verifies the single pending release.
type UpdateAdmin interface {
	ApplyPendingUpdate(context.Context) error
	UpdateStatus(context.Context) (UpdateTransactionStatus, error)
}

// TrafficAdmin exposes one read-only, parameter-free snapshot. The root
// implementation reads only the two named counters in the owned nftables
// table plus the boot/table epoch; callers cannot supply an nft object or
// executable across the privilege boundary.
type TrafficAdmin interface {
	ReadTrafficCounters(context.Context) (traffic.AuthoritativeSnapshot, error)
}

// ModemRecoveryAdmin accepts only a stable uplink id, a durable policy
// generation and an enum action. The root implementation independently reads
// the current interface, active attempt and physical identity context.
type ModemRecoveryAdmin interface {
	Execute(context.Context, modemrecovery.Command) error
}

// PowerAdmin is restricted to capability discovery and three typed actions.
// The root implementation independently blocks critical maintenance and never
// accepts a command, executable, unit name, or path from the caller.
type PowerAdmin interface {
	Capabilities(context.Context) (power.Capabilities, error)
	Execute(context.Context, power.Command) error
}

// RemovalAdmin exposes only an impact snapshot and one typed dispatch. The
// root implementation creates a durable marker and starts one fixed guardian;
// paths, unit names, commands and package-removal choices never cross HTTP.
type RemovalAdmin interface {
	Impact(context.Context) (removal.Impact, error)
	Dispatch(context.Context, removal.Request) error
}

// ManagementFabricAdmin exposes parameter-free convergence/status plus the
// single typed wg-admin identity operation. Interface name, listen port, key
// path, key bytes, routes and nft expressions never cross this boundary.
type ManagementFabricAdmin interface {
	Apply(context.Context) error
	NeedsApply(context.Context) (bool, string, error)
	ConfigureAdminContour(context.Context, managementfabric.AdminContourRequest) (managementfabric.AdminContour, error)
	RotateAdminContourIdentity(context.Context) (managementfabric.AdminContour, error)
}

// PortableBackupAdmin is implemented only by the root broker. It reads the
// fixed Gateway state/config trees, including root-owned Management Fabric
// keys, and exposes only the final encrypted .gvpn stream to the control plane.
type PortableBackupAdmin interface {
	Build(context.Context, string) (backup.PortableArtifact, error)
	Open(backup.PortableArtifact) (io.ReadCloser, error)
	Remove(backup.PortableArtifact) error
}

type ManagementFabricStatus struct {
	NeedsApply bool   `json:"needs_apply"`
	Reason     string `json:"reason"`
}

// UpdateTransactionStatus is the only update-journal information exposed to
// the unprivileged control plane. It intentionally omits filesystem paths,
// database hashes, snapshot identifiers and service-manager diagnostics.
type UpdateTransactionStatus struct {
	Exists            bool   `json:"exists"`
	UpdateID          string `json:"update_id,omitempty"`
	State             string `json:"state,omitempty"`
	StartedAt         string `json:"started_at,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	OldVersion        string `json:"old_version,omitempty"`
	NewVersion        string `json:"new_version,omitempty"`
	StabilityDeadline string `json:"stability_deadline,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
}

type brokerApplyRequest struct {
	ApplyID string `json:"apply_id"`
}

type brokerConfirmRequest struct {
	ApplyID            string `json:"apply_id"`
	Token              string `json:"token"`
	LocalDestinationIP string `json:"local_destination_ip"`
	ViaWireGuard       bool   `json:"via_wireguard"`
}

func NewBrokerServer(engine *Engine) (*BrokerServer, error) {
	return NewBrokerServerWithDataPlane(engine, nil)
}

func NewBrokerServerWithDataPlane(engine *Engine, dataPlane DataPlaneAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithRuntime(engine, dataPlane, nil)
}

func NewBrokerServerWithRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithNetworkRuntime(engine, dataPlane, pathPlane, nil)
}

func NewBrokerServerWithNetworkRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithServiceRuntime(engine, dataPlane, pathPlane, routingAdmin, nil)
}

func NewBrokerServerWithServiceRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithManagementRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, nil)
}

func NewBrokerServerWithManagementRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithLoggingRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, wireGuardAdmin, nil, nil)
}

func NewBrokerServerWithLoggingRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin, loggingAdmin LoggingAdmin, journalAdmin JournalAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithDiagnosticsRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, wireGuardAdmin, loggingAdmin, journalAdmin, nil)
}

func NewBrokerServerWithDiagnosticsRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin, loggingAdmin LoggingAdmin, journalAdmin JournalAdmin, diagnosticsAdmin HostDiagnosticsAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithRestoreRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, wireGuardAdmin, loggingAdmin, journalAdmin, diagnosticsAdmin, nil)
}

func NewBrokerServerWithRestoreRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin, loggingAdmin LoggingAdmin, journalAdmin JournalAdmin, diagnosticsAdmin HostDiagnosticsAdmin, restoreAdmin RestoreAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithUpdateRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, wireGuardAdmin, loggingAdmin, journalAdmin, diagnosticsAdmin, restoreAdmin, nil)
}

func NewBrokerServerWithUpdateRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin, loggingAdmin LoggingAdmin, journalAdmin JournalAdmin, diagnosticsAdmin HostDiagnosticsAdmin, restoreAdmin RestoreAdmin, updateAdmin UpdateAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithTrafficRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, wireGuardAdmin, loggingAdmin, journalAdmin, diagnosticsAdmin, restoreAdmin, updateAdmin, nil)
}

func NewBrokerServerWithTrafficRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin, loggingAdmin LoggingAdmin, journalAdmin JournalAdmin, diagnosticsAdmin HostDiagnosticsAdmin, restoreAdmin RestoreAdmin, updateAdmin UpdateAdmin, trafficAdmin TrafficAdmin) (*BrokerServer, error) {
	return NewBrokerServerWithFullRuntime(engine, dataPlane, pathPlane, routingAdmin, bootstrapAdmin, wireGuardAdmin, loggingAdmin, journalAdmin, diagnosticsAdmin, restoreAdmin, updateAdmin, trafficAdmin, nil)
}

func NewBrokerServerWithFullRuntime(engine *Engine, dataPlane DataPlaneAdmin, pathPlane PathAdmin, routingAdmin RoutingAdmin, bootstrapAdmin BootstrapAdmin, wireGuardAdmin WireGuardAdmin, loggingAdmin LoggingAdmin, journalAdmin JournalAdmin, diagnosticsAdmin HostDiagnosticsAdmin, restoreAdmin RestoreAdmin, updateAdmin UpdateAdmin, trafficAdmin TrafficAdmin, recoveryAdmin ModemRecoveryAdmin) (*BrokerServer, error) {
	if engine == nil {
		return nil, errors.New("network apply engine is required")
	}
	server := &BrokerServer{Engine: engine, DataPlane: dataPlane, PathPlane: pathPlane, Routing: routingAdmin, Bootstrap: bootstrapAdmin, WireGuard: wireGuardAdmin, Logging: loggingAdmin, Journal: journalAdmin, Diagnostics: diagnosticsAdmin, Restore: restoreAdmin, Update: updateAdmin, Traffic: trafficAdmin, Recovery: recoveryAdmin}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/stage", server.stage)
	mux.HandleFunc("POST /v1/apply", server.apply)
	mux.HandleFunc("POST /v1/confirm", server.confirm)
	mux.HandleFunc("POST /v1/recover", server.recover)
	if dataPlane != nil {
		mux.HandleFunc("POST /v1/mihomo/restart", server.restartMihomo)
		mux.HandleFunc("POST /v1/mihomo/fail-closed", server.failClosedMihomo)
	}
	if pathPlane != nil {
		mux.HandleFunc("POST /v1/path/activate", server.activatePath)
		mux.HandleFunc("POST /v1/path/direct/activate", server.activateDirectPath)
		mux.HandleFunc("POST /v1/path/block", server.blockPath)
		mux.HandleFunc("POST /v1/path/observe", server.observePath)
	}
	if routingAdmin != nil {
		mux.HandleFunc("POST /v1/routing/sync", server.syncRouting)
	}
	if bootstrapAdmin != nil {
		mux.HandleFunc("POST /v1/bootstrap/authorize", server.authorizeBootstrap)
		mux.HandleFunc("POST /v1/direct-probe/authorize", server.authorizeDirectProbe)
		mux.HandleFunc("POST /v1/mihomo/endpoints/authorize", server.authorizeMihomoEndpoints)
	}
	if wireGuardAdmin != nil {
		mux.HandleFunc("POST /v1/wireguard/sync", server.syncWireGuard)
	}
	mux.HandleFunc("POST /v1/wireguard/ingress/sync", server.syncWireGuardIngress)
	mux.HandleFunc("POST /v1/wireguard/ingress/server/update", server.updateWireGuardIngressServer)
	mux.HandleFunc("POST /v1/wireguard/ingress/server/rotate", server.rotateWireGuardIngressServer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/create", server.createWireGuardIngressPeer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/update", server.updateWireGuardIngressPeer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/revoke", server.revokeWireGuardIngressPeer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/delete", server.deleteWireGuardIngressPeer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/rotate", server.rotateWireGuardIngressPeer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/probe", server.probeWireGuardIngressPeer)
	mux.HandleFunc("POST /v1/wireguard/ingress/peers/export", server.exportWireGuardIngressPeer)
	if loggingAdmin != nil {
		mux.HandleFunc("POST /v1/logging/sync", server.syncLogging)
	}
	if journalAdmin != nil {
		mux.HandleFunc("POST /v1/logging/query", server.queryLogs)
	}
	if diagnosticsAdmin != nil {
		mux.HandleFunc("POST /v1/diagnostics/host", server.hostDiagnostics)
	}
	if restoreAdmin != nil {
		mux.HandleFunc("POST /v1/restore/apply", server.applyPendingRestore)
	}
	if updateAdmin != nil {
		mux.HandleFunc("POST /v1/update/apply", server.applyPendingUpdate)
		mux.HandleFunc("POST /v1/update/status", server.updateTransactionStatus)
	}
	if trafficAdmin != nil {
		mux.HandleFunc("POST /v1/traffic/counters", server.readTrafficCounters)
	}
	if recoveryAdmin != nil {
		mux.HandleFunc("POST /v1/modem/recovery/execute", server.executeModemRecovery)
	}
	mux.HandleFunc("POST /v1/power/capabilities", server.powerCapabilities)
	mux.HandleFunc("POST /v1/power/execute", server.executePower)
	mux.HandleFunc("POST /v1/uninstall/impact", server.uninstallImpact)
	mux.HandleFunc("POST /v1/uninstall/dispatch", server.dispatchUninstall)
	mux.HandleFunc("POST /v1/management-fabric/sync", server.syncManagementFabric)
	mux.HandleFunc("POST /v1/management-fabric/status", server.managementFabricStatus)
	mux.HandleFunc("POST /v1/management-fabric/admin-contour/configure", server.configureAdminContour)
	mux.HandleFunc("POST /v1/management-fabric/admin-contour/rotate", server.rotateAdminContour)
	mux.HandleFunc("POST /v1/backup/export", server.exportPortableBackup)
	server.handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(writer, request)
	})
	return server, nil
}

func (server *BrokerServer) exportPortableBackup(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeBrokerJSON(request, &input); err != nil || backup.ValidatePassphrase(input.Passphrase) != nil {
		input.Passphrase = ""
		writeBrokerError(writer, http.StatusBadRequest, "BACKUP_PASSPHRASE_INVALID")
		return
	}
	if server.PortableBackup == nil {
		input.Passphrase = ""
		writeBrokerError(writer, http.StatusServiceUnavailable, "PORTABLE_BACKUP_UNAVAILABLE")
		return
	}
	passphrase := input.Passphrase
	input.Passphrase = ""
	artifact, err := server.PortableBackup.Build(request.Context(), passphrase)
	passphrase = ""
	if err != nil {
		server.logPrivilegedFailure("portable_backup_export", err)
		writeBrokerError(writer, http.StatusConflict, "PORTABLE_BACKUP_BUILD_FAILED")
		return
	}
	defer server.PortableBackup.Remove(artifact)
	if artifact.Path == "" {
		server.logPrivilegedFailure("portable_backup_export", errors.New("portable backup builder returned no managed path"))
		writeBrokerError(writer, http.StatusInternalServerError, "PORTABLE_BACKUP_INVALID")
		return
	}
	streamMetadata := artifact
	streamMetadata.Path = ""
	if err := backup.ValidatePortableArtifactMetadata(streamMetadata); err != nil {
		server.logPrivilegedFailure("portable_backup_export", err)
		writeBrokerError(writer, http.StatusInternalServerError, "PORTABLE_BACKUP_INVALID")
		return
	}
	reader, err := server.PortableBackup.Open(artifact)
	if err != nil {
		server.logPrivilegedFailure("portable_backup_export", err)
		writeBrokerError(writer, http.StatusInternalServerError, "PORTABLE_BACKUP_VERIFY_FAILED")
		return
	}
	defer reader.Close()
	writer.Header().Set("Content-Type", "application/vnd.gateway-vpn.backup.encrypted")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", artifact.Bytes))
	writer.Header().Set("X-Gateway-VPN-Backup-Filename", artifact.Filename)
	writer.Header().Set("X-Gateway-VPN-Backup-SHA256", artifact.SHA256)
	writer.Header().Set("X-Gateway-VPN-Backup-Snapshot", artifact.SnapshotID)
	writer.WriteHeader(http.StatusOK)
	written, copyErr := io.CopyN(writer, reader, artifact.Bytes)
	if copyErr != nil || written != artifact.Bytes {
		server.logPrivilegedFailure("portable_backup_stream", errors.New("encrypted portable backup stream was interrupted"))
	}
}

func (server *BrokerServer) syncManagementFabric(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.ManagementFabric == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "MANAGEMENT_FABRIC_UNAVAILABLE")
		return
	}
	if err := server.ManagementFabric.Apply(request.Context()); err != nil {
		server.logPrivilegedFailure("management_fabric_sync", err)
		writeBrokerError(writer, http.StatusConflict, "MANAGEMENT_FABRIC_SYNC_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) managementFabricStatus(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.ManagementFabric == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "MANAGEMENT_FABRIC_UNAVAILABLE")
		return
	}
	needed, reason, err := server.ManagementFabric.NeedsApply(request.Context())
	if err != nil {
		server.logPrivilegedFailure("management_fabric_status", err)
		writeBrokerError(writer, http.StatusServiceUnavailable, "MANAGEMENT_FABRIC_STATUS_FAILED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, ManagementFabricStatus{NeedsApply: needed, Reason: reason})
}

func (server *BrokerServer) configureAdminContour(writer http.ResponseWriter, request *http.Request) {
	var input managementfabric.AdminContourRequest
	if err := decodeBrokerJSON(request, &input); err != nil || managementfabric.ValidateAdminContourRequest(input) != nil {
		writeBrokerError(writer, http.StatusBadRequest, "ADMIN_CONTOUR_REQUEST_INVALID")
		return
	}
	if server.ManagementFabric == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "MANAGEMENT_FABRIC_UNAVAILABLE")
		return
	}
	item, err := server.ManagementFabric.ConfigureAdminContour(request.Context(), input)
	if err != nil {
		server.logPrivilegedFailure("management_admin_contour_configure", err)
		writeBrokerError(writer, http.StatusConflict, "ADMIN_CONTOUR_CONFIGURE_FAILED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

func (server *BrokerServer) rotateAdminContour(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.ManagementFabric == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "MANAGEMENT_FABRIC_UNAVAILABLE")
		return
	}
	item, err := server.ManagementFabric.RotateAdminContourIdentity(request.Context())
	if err != nil {
		server.logPrivilegedFailure("management_admin_contour_rotate", err)
		writeBrokerError(writer, http.StatusConflict, "ADMIN_CONTOUR_ROTATE_FAILED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

func (server *BrokerServer) uninstallImpact(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.Removal == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "UNINSTALL_CONTROLLER_UNAVAILABLE")
		return
	}
	impact, err := server.Removal.Impact(request.Context())
	if err != nil {
		server.logPrivilegedFailure("uninstall-impact", err)
		writeBrokerError(writer, http.StatusServiceUnavailable, "UNINSTALL_IMPACT_UNAVAILABLE")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, impact)
}

func (server *BrokerServer) dispatchUninstall(writer http.ResponseWriter, request *http.Request) {
	var input removal.Request
	if err := decodeBrokerJSON(request, &input); err != nil || input.Validate() != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_UNINSTALL_REQUEST")
		return
	}
	if server.Removal == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "UNINSTALL_CONTROLLER_UNAVAILABLE")
		return
	}
	err := server.Removal.Dispatch(request.Context(), input)
	switch {
	case err == nil:
		writer.WriteHeader(http.StatusNoContent)
	case errors.Is(err, removal.ErrMaintenanceActive):
		writeBrokerError(writer, http.StatusConflict, "UNINSTALL_BLOCKED_BY_MAINTENANCE")
	case errors.Is(err, removal.ErrOperationInProgress):
		writeBrokerError(writer, http.StatusConflict, "UNINSTALL_OPERATION_IN_PROGRESS")
	case errors.Is(err, removal.ErrUnavailable):
		writeBrokerError(writer, http.StatusConflict, "UNINSTALL_UNAVAILABLE")
	case errors.Is(err, removal.ErrInvalidRequest):
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_UNINSTALL_REQUEST")
	default:
		server.logPrivilegedFailure("uninstall-dispatch", err)
		writeBrokerError(writer, http.StatusServiceUnavailable, "UNINSTALL_DISPATCH_FAILED")
	}
}

func (server *BrokerServer) powerCapabilities(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.Power == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "POWER_CONTROLLER_UNAVAILABLE")
		return
	}
	capabilities, err := server.Power.Capabilities(request.Context())
	if err != nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "POWER_CAPABILITIES_UNAVAILABLE")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, capabilities)
}

func (server *BrokerServer) executePower(writer http.ResponseWriter, request *http.Request) {
	var command power.Command
	if err := decodeBrokerJSON(request, &command); err != nil || command.Validate() != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_POWER_COMMAND")
		return
	}
	if server.Power == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "POWER_CONTROLLER_UNAVAILABLE")
		return
	}
	err := server.Power.Execute(request.Context(), command)
	switch {
	case err == nil:
		writer.WriteHeader(http.StatusNoContent)
	case errors.Is(err, power.ErrMaintenanceActive):
		writeBrokerError(writer, http.StatusConflict, "POWER_BLOCKED_BY_MAINTENANCE")
	case errors.Is(err, power.ErrOperationInProgress):
		writeBrokerError(writer, http.StatusConflict, "POWER_OPERATION_IN_PROGRESS")
	case errors.Is(err, power.ErrUnavailable):
		writeBrokerError(writer, http.StatusConflict, "POWER_ACTION_UNAVAILABLE")
	case errors.Is(err, power.ErrInvalidCommand):
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_POWER_COMMAND")
	default:
		writeBrokerError(writer, http.StatusServiceUnavailable, "POWER_ACTION_FAILED")
	}
}

func (server *BrokerServer) executeModemRecovery(writer http.ResponseWriter, request *http.Request) {
	var input modemrecovery.Command
	if err := decodeBrokerJSON(request, &input); err != nil || modemrecovery.ValidateCommand(input) != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	err := server.Recovery.Execute(request.Context(), input)
	switch {
	case err == nil:
		writer.WriteHeader(http.StatusNoContent)
	case errors.Is(err, modemrecovery.ErrActionUnsupported):
		writeBrokerError(writer, http.StatusConflict, "RECOVERY_ACTION_NOT_SUPPORTED")
	case errors.Is(err, modemrecovery.ErrDeviceRemoved):
		writeBrokerError(writer, http.StatusConflict, "RECOVERY_DEVICE_REMOVED")
	case errors.Is(err, modemrecovery.ErrStaleGeneration):
		writeBrokerError(writer, http.StatusConflict, "RECOVERY_STALE_GENERATION")
	default:
		writeBrokerError(writer, http.StatusServiceUnavailable, "RECOVERY_ACTION_FAILED")
	}
}

func (server *BrokerServer) activateDirectPath(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		ModemID         string `json:"modem_id"`
		RouteGeneration int64  `json:"route_generation"`
	}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if strings.TrimSpace(input.ModemID) == "" || len(input.ModemID) > 128 || input.RouteGeneration <= 0 || input.RouteGeneration > math.MaxUint32 {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.PathPlane.ActivateDirectPath(request.Context(), input.ModemID, input.RouteGeneration); err != nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "DIRECT_PATH_ACTIVATION_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) readTrafficCounters(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	snapshot, err := server.Traffic.ReadTrafficCounters(request.Context())
	if err != nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "TRAFFIC_COUNTERS_UNAVAILABLE")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, snapshot)
}

func (server *BrokerServer) applyPendingUpdate(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Update.ApplyPendingUpdate(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "UPDATE_APPLY_START_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) updateTransactionStatus(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	status, err := server.Update.UpdateStatus(request.Context())
	if err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "UPDATE_STATUS_FAILED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, status)
}

func (server *BrokerServer) applyPendingRestore(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Restore.ApplyPendingRestore(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "RESTORE_APPLY_START_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) hostDiagnostics(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	snapshot, err := server.Diagnostics.Collect(request.Context())
	if err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "HOST_DIAGNOSTICS_FAILED")
		return
	}
	payload, err := json.Marshal(snapshot)
	if err != nil || len(payload) > diagnostics.MaximumHostSnapshotBytes || len(payload) > maxBrokerMessageBytes {
		writeBrokerError(writer, http.StatusInternalServerError, "HOST_DIAGNOSTICS_RESPONSE_INVALID")
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(payload)
}

func (server *BrokerServer) queryLogs(writer http.ResponseWriter, request *http.Request) {
	var input loggingpkg.JournalQuery
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	page, err := server.Journal.QueryLogs(request.Context(), input)
	if err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "JOURNAL_QUERY_FAILED")
		return
	}
	payload, err := json.Marshal(page)
	if err != nil || len(payload) > maxBrokerMessageBytes {
		writeBrokerError(writer, http.StatusInternalServerError, "JOURNAL_RESPONSE_INVALID")
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(payload)
}

func (server *BrokerServer) syncLogging(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Logging.SyncLogging(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "LOGGING_SYNC_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) syncWireGuard(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.WireGuard.SyncWireGuard(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "WIREGUARD_SYNC_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) authorizeMihomoEndpoints(writer http.ResponseWriter, request *http.Request) {
	var input dataplane.MihomoEndpointAuthorization
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Bootstrap.AuthorizeMihomoEndpoints(request.Context(), input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "MIHOMO_ENDPOINT_AUTHORIZATION_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) authorizeBootstrap(writer http.ResponseWriter, request *http.Request) {
	var input dataplane.BootstrapAuthorization
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Bootstrap.AuthorizeBootstrap(request.Context(), input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "BOOTSTRAP_AUTHORIZATION_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) authorizeDirectProbe(writer http.ResponseWriter, request *http.Request) {
	var input dataplane.DirectProbeAuthorization
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Bootstrap.AuthorizeDirectProbe(request.Context(), input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "DIRECT_PROBE_AUTHORIZATION_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) syncRouting(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Routing.SyncRouting(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "ROUTING_SYNC_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) activatePath(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Generation uint32 `json:"generation"`
	}
	if err := decodeBrokerJSON(request, &input); err != nil || input.Generation == 0 {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.PathPlane.ActivatePath(request.Context(), input.Generation); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "PATH_ACTIVATION_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) blockPath(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.PathPlane.BlockPath(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "PATH_BLOCK_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) observePath(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	state, err := server.PathPlane.ObservePath(request.Context())
	if err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "PATH_OBSERVATION_FAILED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, state)
}

func (server *BrokerServer) restartMihomo(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.DataPlane.RestartMihomo(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "MIHOMO_RESTART_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) failClosedMihomo(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.DataPlane.FailClosedMihomo(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "MIHOMO_FAIL_CLOSED_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func (server *BrokerServer) stage(writer http.ResponseWriter, request *http.Request) {
	var candidate Candidate
	if err := decodeBrokerJSON(request, &candidate); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	prepared, err := server.Engine.Stage(request.Context(), candidate)
	if err != nil {
		writeBrokerDomainError(writer, err)
		return
	}
	writeBrokerJSON(writer, http.StatusCreated, prepared)
}

func (server *BrokerServer) apply(writer http.ResponseWriter, request *http.Request) {
	var input brokerApplyRequest
	if err := decodeBrokerJSON(request, &input); err != nil || !safeID(input.ApplyID) {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Engine.Apply(request.Context(), input.ApplyID); err != nil {
		writeBrokerDomainError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) confirm(writer http.ResponseWriter, request *http.Request) {
	var input brokerConfirmRequest
	if err := decodeBrokerJSON(request, &input); err != nil || !safeID(input.ApplyID) || len(input.Token) != 64 {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	err := server.Engine.Confirm(request.Context(), input.ApplyID, ConfirmEvidence{Token: input.Token, LocalDestinationIP: input.LocalDestinationIP, ViaWireGuard: input.ViaWireGuard})
	if err != nil {
		writeBrokerDomainError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) recover(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := server.Engine.Recover(request.Context()); err != nil {
		writeBrokerError(writer, http.StatusInternalServerError, "RECOVERY_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) syncWireGuardIngress(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	if err := server.Ingress.Sync(request.Context()); err != nil {
		server.logPrivilegedFailure("wireguard_ingress_sync", err)
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_SYNC_FAILED")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *BrokerServer) updateWireGuardIngressServer(writer http.ResponseWriter, request *http.Request) {
	var input wgingress.ServerUpdate
	if err := decodeBrokerJSON(request, &input); err != nil || wgingress.ValidateServerUpdate(input) != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_SERVER")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	item, err := server.Ingress.UpdateServer(request.Context(), input)
	if err != nil {
		server.logPrivilegedFailure("wireguard_ingress_server_update", err)
		writeBrokerError(writer, http.StatusConflict, "WIREGUARD_INGRESS_SERVER_REJECTED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

func (server *BrokerServer) rotateWireGuardIngressServer(writer http.ResponseWriter, request *http.Request) {
	var input struct{}
	if err := decodeBrokerJSON(request, &input); err != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	item, err := server.Ingress.RotateServer(request.Context())
	if err != nil {
		server.logPrivilegedFailure("wireguard_ingress_server_rotate", err)
		writeBrokerError(writer, http.StatusConflict, "WIREGUARD_INGRESS_ROTATION_FAILED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

func (server *BrokerServer) createWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	var input wgingress.PeerCreate
	if err := decodeBrokerJSON(request, &input); err != nil || wgingress.ValidatePeerCreate(input) != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_PEER")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	item, err := server.Ingress.CreatePeer(request.Context(), input)
	if err != nil {
		server.logPrivilegedFailure("wireguard_ingress_peer_create", err)
		writeBrokerError(writer, http.StatusConflict, "WIREGUARD_INGRESS_PEER_REJECTED")
		return
	}
	writeBrokerJSON(writer, http.StatusCreated, item)
}

type wireGuardIngressPeerMutation struct {
	PeerID string                `json:"peer_id"`
	Update *wgingress.PeerUpdate `json:"update,omitempty"`
}

func (server *BrokerServer) updateWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	var input wireGuardIngressPeerMutation
	if err := decodeBrokerJSON(request, &input); err != nil || !safeID(input.PeerID) || input.Update == nil || wgingress.ValidatePeerUpdate(*input.Update) != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_PEER")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	item, err := server.Ingress.UpdatePeer(request.Context(), input.PeerID, *input.Update)
	if err != nil {
		server.logPrivilegedFailure("wireguard_ingress_peer_update", err)
		writeBrokerError(writer, http.StatusConflict, "WIREGUARD_INGRESS_PEER_REJECTED")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

func (server *BrokerServer) revokeWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	server.wireGuardIngressPeerAction(writer, request, "REVOKE")
}

func (server *BrokerServer) deleteWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	server.wireGuardIngressPeerAction(writer, request, "DELETE")
}

func (server *BrokerServer) rotateWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	server.wireGuardIngressPeerAction(writer, request, "ROTATE")
}

func (server *BrokerServer) probeWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	server.wireGuardIngressPeerAction(writer, request, "PROBE")
}

func (server *BrokerServer) exportWireGuardIngressPeer(writer http.ResponseWriter, request *http.Request) {
	var input wireGuardIngressPeerMutation
	if err := decodeBrokerJSON(request, &input); err != nil || !safeID(input.PeerID) || input.Update != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_PEER")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	item, err := server.Ingress.ExportPeerConfig(request.Context(), input.PeerID)
	if err != nil {
		server.logPrivilegedFailure("wireguard_ingress_peer_export", err)
		writeBrokerError(writer, http.StatusConflict, "WIREGUARD_INGRESS_CONFIG_UNAVAILABLE")
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

func (server *BrokerServer) wireGuardIngressPeerAction(writer http.ResponseWriter, request *http.Request, action string) {
	var input wireGuardIngressPeerMutation
	if err := decodeBrokerJSON(request, &input); err != nil || !safeID(input.PeerID) || input.Update != nil {
		writeBrokerError(writer, http.StatusBadRequest, "INVALID_WIREGUARD_INGRESS_PEER")
		return
	}
	if server.Ingress == nil {
		writeBrokerError(writer, http.StatusServiceUnavailable, "WIREGUARD_INGRESS_UNAVAILABLE")
		return
	}
	var item wgingress.Peer
	var err error
	switch action {
	case "REVOKE":
		item, err = server.Ingress.RevokePeer(request.Context(), input.PeerID)
	case "DELETE":
		err = server.Ingress.DeletePeer(request.Context(), input.PeerID)
	case "ROTATE":
		item, err = server.Ingress.RotatePeer(request.Context(), input.PeerID)
	case "PROBE":
		item, err = server.Ingress.ProbePeer(request.Context(), input.PeerID)
	default:
		err = errors.New("unsupported WireGuard ingress action")
	}
	if err != nil {
		server.logPrivilegedFailure("wireguard_ingress_peer_"+strings.ToLower(action), err)
		writeBrokerError(writer, http.StatusConflict, "WIREGUARD_INGRESS_PEER_ACTION_FAILED")
		return
	}
	if action == "DELETE" {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writeBrokerJSON(writer, http.StatusOK, item)
}

// logPrivilegedFailure keeps the actionable root cause in the root broker's
// bounded journal while the Unix-socket client receives only a stable public
// error code. Typed inputs and secret material are deliberately never logged.
func (server *BrokerServer) logPrivilegedFailure(operation string, err error) {
	logger := server.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("Gateway VPN privileged broker operation failed", "operation", operation, "error", err)
}

type BrokerClient struct {
	client *http.Client
}

func NewBrokerClient(socketPath string) (*BrokerClient, error) {
	if strings.TrimSpace(socketPath) == "" || len(socketPath) > 4096 || socketPath[0] != '/' {
		return nil, errors.New("absolute broker Unix socket path is required")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		MaxIdleConns:       2,
		IdleConnTimeout:    30 * time.Second,
	}
	return &BrokerClient{client: &http.Client{Transport: transport, Timeout: 45 * time.Second}}, nil
}

func newBrokerClientForHTTP(client *http.Client) *BrokerClient {
	return &BrokerClient{client: client}
}

func (client *BrokerClient) Stage(ctx context.Context, candidate Candidate) (Prepared, error) {
	var result Prepared
	err := client.call(ctx, "/v1/stage", candidate, http.StatusCreated, &result)
	return result, err
}

func (client *BrokerClient) Apply(ctx context.Context, applyID string) error {
	return client.call(ctx, "/v1/apply", brokerApplyRequest{ApplyID: applyID}, http.StatusNoContent, nil)
}

func (client *BrokerClient) Confirm(ctx context.Context, applyID string, evidence ConfirmEvidence) error {
	return client.call(ctx, "/v1/confirm", brokerConfirmRequest{ApplyID: applyID, Token: evidence.Token, LocalDestinationIP: evidence.LocalDestinationIP, ViaWireGuard: evidence.ViaWireGuard}, http.StatusNoContent, nil)
}

func (client *BrokerClient) Recover(ctx context.Context) error {
	return client.call(ctx, "/v1/recover", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) RestartMihomo(ctx context.Context) error {
	return client.call(ctx, "/v1/mihomo/restart", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) FailClosedMihomo(ctx context.Context) error {
	return client.call(ctx, "/v1/mihomo/fail-closed", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) ActivatePath(ctx context.Context, generation uint32) error {
	return client.call(ctx, "/v1/path/activate", map[string]uint32{"generation": generation}, http.StatusNoContent, nil)
}

func (client *BrokerClient) ActivateDirectPath(ctx context.Context, modemID string, routeGeneration int64) error {
	return client.call(ctx, "/v1/path/direct/activate", struct {
		ModemID         string `json:"modem_id"`
		RouteGeneration int64  `json:"route_generation"`
	}{ModemID: modemID, RouteGeneration: routeGeneration}, http.StatusNoContent, nil)
}

func (client *BrokerClient) BlockPath(ctx context.Context) error {
	return client.call(ctx, "/v1/path/block", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) ObservePath(ctx context.Context) (dataplane.PathState, error) {
	var state dataplane.PathState
	err := client.call(ctx, "/v1/path/observe", struct{}{}, http.StatusOK, &state)
	return state, err
}

func (client *BrokerClient) SyncRouting(ctx context.Context) error {
	return client.call(ctx, "/v1/routing/sync", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) SyncWireGuard(ctx context.Context) error {
	return client.call(ctx, "/v1/wireguard/sync", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) SyncManagementFabric(ctx context.Context) error {
	return client.call(ctx, "/v1/management-fabric/sync", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) ManagementFabricStatus(ctx context.Context) (ManagementFabricStatus, error) {
	var status ManagementFabricStatus
	err := client.call(ctx, "/v1/management-fabric/status", struct{}{}, http.StatusOK, &status)
	return status, err
}

func (client *BrokerClient) ConfigureAdminContour(ctx context.Context, input managementfabric.AdminContourRequest) (managementfabric.AdminContour, error) {
	var item managementfabric.AdminContour
	err := client.call(ctx, "/v1/management-fabric/admin-contour/configure", input, http.StatusOK, &item)
	return item, err
}

func (client *BrokerClient) RotateAdminContourIdentity(ctx context.Context) (managementfabric.AdminContour, error) {
	var item managementfabric.AdminContour
	err := client.call(ctx, "/v1/management-fabric/admin-contour/rotate", struct{}{}, http.StatusOK, &item)
	return item, err
}

// ExportPortableBackup requests a root-built encrypted backup. The passphrase
// is carried only in the body of the UID-restricted Unix-socket request; it is
// never placed in argv, environment, a trigger file, SQLite or a journal.
func (client *BrokerClient) ExportPortableBackup(ctx context.Context, passphrase string) (backup.PortableArtifact, io.ReadCloser, error) {
	if client == nil || client.client == nil {
		return backup.PortableArtifact{}, nil, errors.New("network broker client is not configured")
	}
	if err := backup.ValidatePassphrase(passphrase); err != nil {
		return backup.PortableArtifact{}, nil, err
	}
	payload, err := json.Marshal(struct {
		Passphrase string `json:"passphrase"`
	}{Passphrase: passphrase})
	passphrase = ""
	if err != nil {
		return backup.PortableArtifact{}, nil, errors.New("encode portable backup request failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/backup/export", bytes.NewReader(payload))
	if err != nil {
		for index := range payload {
			payload[index] = 0
		}
		return backup.PortableArtifact{}, nil, errors.New("create portable backup request failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/vnd.gateway-vpn.backup.encrypted")
	streamClient := *client.client
	streamClient.Timeout = 10 * time.Minute
	response, err := streamClient.Do(request)
	for index := range payload {
		payload[index] = 0
	}
	if err != nil {
		return backup.PortableArtifact{}, nil, errors.New("network broker is unavailable")
	}
	fail := func(message string) (backup.PortableArtifact, io.ReadCloser, error) {
		response.Body.Close()
		return backup.PortableArtifact{}, nil, errors.New(message)
	}
	if response.StatusCode != http.StatusOK {
		content, readErr := io.ReadAll(io.LimitReader(response.Body, maxBrokerMessageBytes+1))
		if readErr != nil || len(content) > maxBrokerMessageBytes {
			return fail("network broker backup response is invalid")
		}
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(content, &envelope) != nil || envelope.Error.Code == "" {
			return fail(fmt.Sprintf("network broker returned HTTP %d", response.StatusCode))
		}
		return fail("network broker rejected backup request (" + envelope.Error.Code + ")")
	}
	if response.Header.Get("Content-Type") != "application/vnd.gateway-vpn.backup.encrypted" {
		return fail("network broker backup media type is invalid")
	}
	bytesCount, parseErr := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	artifact := backup.PortableArtifact{
		Filename:   response.Header.Get("X-Gateway-VPN-Backup-Filename"),
		Bytes:      bytesCount,
		SHA256:     response.Header.Get("X-Gateway-VPN-Backup-SHA256"),
		SnapshotID: response.Header.Get("X-Gateway-VPN-Backup-Snapshot"),
	}
	if parseErr != nil || response.ContentLength != artifact.Bytes || backup.ValidatePortableArtifactMetadata(artifact) != nil {
		return fail("network broker backup metadata is invalid")
	}
	return artifact, response.Body, nil
}

func (client *BrokerClient) SyncWireGuardIngress(ctx context.Context) error {
	return client.call(ctx, "/v1/wireguard/ingress/sync", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) UpdateWireGuardIngressServer(ctx context.Context, input wgingress.ServerUpdate) (wgingress.Server, error) {
	var result wgingress.Server
	err := client.call(ctx, "/v1/wireguard/ingress/server/update", input, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) RotateWireGuardIngressServer(ctx context.Context) (wgingress.Server, error) {
	var result wgingress.Server
	err := client.call(ctx, "/v1/wireguard/ingress/server/rotate", struct{}{}, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) CreateWireGuardIngressPeer(ctx context.Context, input wgingress.PeerCreate) (wgingress.Peer, error) {
	var result wgingress.Peer
	err := client.call(ctx, "/v1/wireguard/ingress/peers/create", input, http.StatusCreated, &result)
	return result, err
}

func (client *BrokerClient) UpdateWireGuardIngressPeer(ctx context.Context, id string, input wgingress.PeerUpdate) (wgingress.Peer, error) {
	var result wgingress.Peer
	err := client.call(ctx, "/v1/wireguard/ingress/peers/update", wireGuardIngressPeerMutation{PeerID: id, Update: &input}, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) RevokeWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	var result wgingress.Peer
	err := client.call(ctx, "/v1/wireguard/ingress/peers/revoke", wireGuardIngressPeerMutation{PeerID: id}, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) DeleteWireGuardIngressPeer(ctx context.Context, id string) error {
	return client.call(ctx, "/v1/wireguard/ingress/peers/delete", wireGuardIngressPeerMutation{PeerID: id}, http.StatusNoContent, nil)
}

func (client *BrokerClient) RotateWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	var result wgingress.Peer
	err := client.call(ctx, "/v1/wireguard/ingress/peers/rotate", wireGuardIngressPeerMutation{PeerID: id}, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) ProbeWireGuardIngressPeer(ctx context.Context, id string) (wgingress.Peer, error) {
	var result wgingress.Peer
	err := client.call(ctx, "/v1/wireguard/ingress/peers/probe", wireGuardIngressPeerMutation{PeerID: id}, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) ExportWireGuardIngressPeer(ctx context.Context, id string) (wgingress.ExportedConfig, error) {
	var result wgingress.ExportedConfig
	err := client.call(ctx, "/v1/wireguard/ingress/peers/export", wireGuardIngressPeerMutation{PeerID: id}, http.StatusOK, &result)
	return result, err
}

func (client *BrokerClient) SyncLogging(ctx context.Context) error {
	return client.call(ctx, "/v1/logging/sync", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) QueryLogs(ctx context.Context, query loggingpkg.JournalQuery) (loggingpkg.JournalPage, error) {
	var page loggingpkg.JournalPage
	err := client.call(ctx, "/v1/logging/query", query, http.StatusOK, &page)
	return page, err
}

func (client *BrokerClient) CollectHostDiagnostics(ctx context.Context) (diagnostics.HostSnapshot, error) {
	var snapshot diagnostics.HostSnapshot
	err := client.call(ctx, "/v1/diagnostics/host", struct{}{}, http.StatusOK, &snapshot)
	return snapshot, err
}

func (client *BrokerClient) ApplyPendingRestore(ctx context.Context) error {
	return client.call(ctx, "/v1/restore/apply", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) ApplyPendingUpdate(ctx context.Context) error {
	return client.call(ctx, "/v1/update/apply", struct{}{}, http.StatusNoContent, nil)
}

func (client *BrokerClient) UpdateStatus(ctx context.Context) (UpdateTransactionStatus, error) {
	var status UpdateTransactionStatus
	err := client.call(ctx, "/v1/update/status", struct{}{}, http.StatusOK, &status)
	return status, err
}

func (client *BrokerClient) AuthorizeBootstrap(ctx context.Context, authorization dataplane.BootstrapAuthorization) error {
	return client.call(ctx, "/v1/bootstrap/authorize", authorization, http.StatusNoContent, nil)
}

func (client *BrokerClient) AuthorizeSubscriptionBootstrap(ctx context.Context, modemID, subscriptionID string, addresses []string, port uint16) error {
	return client.AuthorizeBootstrap(ctx, dataplane.BootstrapAuthorization{ModemID: modemID, SubscriptionID: subscriptionID, Addresses: append([]string(nil), addresses...), Port: port})
}

func (client *BrokerClient) AuthorizeDirectProbe(ctx context.Context, modemID, targetID string, addresses []string, port uint16) error {
	return client.call(ctx, "/v1/direct-probe/authorize", dataplane.DirectProbeAuthorization{ModemID: modemID, TargetID: targetID, Addresses: append([]string(nil), addresses...), Port: port}, http.StatusNoContent, nil)
}

func (client *BrokerClient) AuthorizeMihomoVersions(ctx context.Context, versionIDs []string) error {
	return client.call(ctx, "/v1/mihomo/endpoints/authorize", dataplane.MihomoEndpointAuthorization{VersionIDs: append([]string(nil), versionIDs...)}, http.StatusNoContent, nil)
}

func (client *BrokerClient) ReadTrafficCounters(ctx context.Context) (traffic.AuthoritativeSnapshot, error) {
	var snapshot traffic.AuthoritativeSnapshot
	err := client.call(ctx, "/v1/traffic/counters", struct{}{}, http.StatusOK, &snapshot)
	return snapshot, err
}

func (client *BrokerClient) Execute(ctx context.Context, command modemrecovery.Command) error {
	err := client.call(ctx, "/v1/modem/recovery/execute", command, http.StatusNoContent, nil)
	if err == nil {
		return nil
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "RECOVERY_ACTION_NOT_SUPPORTED"):
		return modemrecovery.ErrActionUnsupported
	case strings.Contains(message, "RECOVERY_DEVICE_REMOVED"):
		return modemrecovery.ErrDeviceRemoved
	case strings.Contains(message, "RECOVERY_STALE_GENERATION"):
		return modemrecovery.ErrStaleGeneration
	default:
		return err
	}
}

func (client *BrokerClient) PowerCapabilities(ctx context.Context) (power.Capabilities, error) {
	var capabilities power.Capabilities
	err := client.call(ctx, "/v1/power/capabilities", struct{}{}, http.StatusOK, &capabilities)
	return capabilities, err
}

func (client *BrokerClient) ExecutePower(ctx context.Context, command power.Command) error {
	err := client.call(ctx, "/v1/power/execute", command, http.StatusNoContent, nil)
	if err == nil {
		return nil
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "POWER_BLOCKED_BY_MAINTENANCE"):
		return power.ErrMaintenanceActive
	case strings.Contains(message, "POWER_OPERATION_IN_PROGRESS"):
		return power.ErrOperationInProgress
	case strings.Contains(message, "POWER_ACTION_UNAVAILABLE"):
		return power.ErrUnavailable
	case strings.Contains(message, "INVALID_POWER_COMMAND"):
		return power.ErrInvalidCommand
	default:
		return err
	}
}

func (client *BrokerClient) UninstallImpact(ctx context.Context) (removal.Impact, error) {
	var impact removal.Impact
	err := client.call(ctx, "/v1/uninstall/impact", struct{}{}, http.StatusOK, &impact)
	return impact, err
}

func (client *BrokerClient) DispatchUninstall(ctx context.Context, request removal.Request) error {
	err := client.call(ctx, "/v1/uninstall/dispatch", request, http.StatusNoContent, nil)
	if err == nil {
		return nil
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "UNINSTALL_BLOCKED_BY_MAINTENANCE"):
		return removal.ErrMaintenanceActive
	case strings.Contains(message, "UNINSTALL_OPERATION_IN_PROGRESS"):
		return removal.ErrOperationInProgress
	case strings.Contains(message, "UNINSTALL_UNAVAILABLE"):
		return removal.ErrUnavailable
	case strings.Contains(message, "INVALID_UNINSTALL_REQUEST"):
		return removal.ErrInvalidRequest
	default:
		return err
	}
}

func (client *BrokerClient) call(ctx context.Context, endpoint string, input any, expectedStatus int, output any) error {
	if client == nil || client.client == nil {
		return errors.New("network broker client is not configured")
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return errors.New("encode network broker request failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("create network broker request failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return errors.New("network broker is unavailable")
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxBrokerMessageBytes+1))
	if err != nil || len(content) > maxBrokerMessageBytes {
		return errors.New("network broker response is invalid")
	}
	if response.StatusCode != expectedStatus {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(content, &envelope); err != nil || envelope.Error.Code == "" {
			return fmt.Errorf("network broker returned HTTP %d", response.StatusCode)
		}
		return fmt.Errorf("network broker rejected request (%s)", envelope.Error.Code)
	}
	if output != nil {
		if err := json.Unmarshal(content, output); err != nil {
			return errors.New("decode network broker response failed")
		}
	}
	return nil
}

func decodeBrokerJSON(request *http.Request, destination any) error {
	if request.Header.Get("Content-Type") != "application/json" || request.ContentLength > maxBrokerMessageBytes {
		return errors.New("broker request must be bounded JSON")
	}
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxBrokerMessageBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("broker request must contain one JSON value")
	}
	return nil
}

func writeBrokerDomainError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrApplyInProgress), errors.Is(err, ErrApplyState):
		writeBrokerError(writer, http.StatusConflict, "APPLY_CONFLICT")
	case errors.Is(err, ErrApplyExpired):
		writeBrokerError(writer, http.StatusConflict, "APPLY_EXPIRED")
	case errors.Is(err, ErrConfirmToken), errors.Is(err, ErrConfirmSource):
		writeBrokerError(writer, http.StatusForbidden, "CONFIRMATION_REJECTED")
	default:
		// Errors may contain filesystem or command details. The privileged
		// boundary returns only stable reason codes to the control plane.
		writeBrokerError(writer, http.StatusBadRequest, "APPLY_REJECTED")
	}
}

func writeBrokerError(writer http.ResponseWriter, status int, code string) {
	writeBrokerJSON(writer, status, map[string]any{"error": map[string]string{"code": code}})
}

func writeBrokerJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
