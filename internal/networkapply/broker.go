package networkapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/diagnostics"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/traffic"
)

const maxBrokerMessageBytes = 64 << 10

type BrokerServer struct {
	Engine      *Engine
	DataPlane   DataPlaneAdmin
	PathPlane   PathAdmin
	Routing     RoutingAdmin
	Bootstrap   BootstrapAdmin
	WireGuard   WireGuardAdmin
	Logging     LoggingAdmin
	Journal     JournalAdmin
	Diagnostics HostDiagnosticsAdmin
	Restore     RestoreAdmin
	Update      UpdateAdmin
	Traffic     TrafficAdmin
	handler     http.Handler
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
	if engine == nil {
		return nil, errors.New("network apply engine is required")
	}
	server := &BrokerServer{Engine: engine, DataPlane: dataPlane, PathPlane: pathPlane, Routing: routingAdmin, Bootstrap: bootstrapAdmin, WireGuard: wireGuardAdmin, Logging: loggingAdmin, Journal: journalAdmin, Diagnostics: diagnosticsAdmin, Restore: restoreAdmin, Update: updateAdmin, Traffic: trafficAdmin}
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
	server.handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(writer, request)
	})
	return server, nil
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
