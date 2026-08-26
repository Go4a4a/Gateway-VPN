package networkapply

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/diagnostics"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/traffic"
)

type fakeDataPlaneAdmin struct {
	restarts int
	blocks   int
	err      error
}

type fakePathAdmin struct {
	activations []uint32
	blocks      int
	state       dataplane.PathState
	err         error
}

type fakeRoutingAdmin struct {
	calls int
	err   error
}

type fakeWireGuardAdmin struct {
	calls int
	err   error
}

type fakeLoggingAdmin struct {
	calls int
	err   error
}

type fakeJournalAdmin struct {
	queries []loggingpkg.JournalQuery
	page    loggingpkg.JournalPage
	err     error
}

type fakeHostDiagnosticsAdmin struct {
	calls    int
	snapshot diagnostics.HostSnapshot
	err      error
}

type fakeRestoreAdmin struct {
	calls int
	err   error
}

type fakeUpdateAdmin struct {
	calls     int
	err       error
	status    UpdateTransactionStatus
	statusErr error
}

type fakeTrafficAdmin struct {
	calls    int
	snapshot traffic.AuthoritativeSnapshot
	err      error
}

func (admin *fakeTrafficAdmin) ReadTrafficCounters(context.Context) (traffic.AuthoritativeSnapshot, error) {
	admin.calls++
	return admin.snapshot, admin.err
}

func (admin *fakeUpdateAdmin) ApplyPendingUpdate(context.Context) error {
	admin.calls++
	return admin.err
}

func (admin *fakeUpdateAdmin) UpdateStatus(context.Context) (UpdateTransactionStatus, error) {
	return admin.status, admin.statusErr
}

func (admin *fakeRestoreAdmin) ApplyPendingRestore(context.Context) error {
	admin.calls++
	return admin.err
}

func (admin *fakeHostDiagnosticsAdmin) Collect(context.Context) (diagnostics.HostSnapshot, error) {
	admin.calls++
	return admin.snapshot, admin.err
}

func (admin *fakeJournalAdmin) QueryLogs(_ context.Context, query loggingpkg.JournalQuery) (loggingpkg.JournalPage, error) {
	admin.queries = append(admin.queries, query)
	return admin.page, admin.err
}

func (admin *fakeLoggingAdmin) SyncLogging(context.Context) error {
	admin.calls++
	return admin.err
}

func (admin *fakeWireGuardAdmin) SyncWireGuard(context.Context) error {
	admin.calls++
	return admin.err
}

type fakeBootstrapAdmin struct {
	requests []dataplane.BootstrapAuthorization
	mihomo   []dataplane.MihomoEndpointAuthorization
	err      error
}

func (admin *fakeBootstrapAdmin) AuthorizeMihomoEndpoints(_ context.Context, input dataplane.MihomoEndpointAuthorization) error {
	admin.mihomo = append(admin.mihomo, input)
	return admin.err
}

func (admin *fakeBootstrapAdmin) AuthorizeBootstrap(_ context.Context, input dataplane.BootstrapAuthorization) error {
	admin.requests = append(admin.requests, input)
	return admin.err
}

func (admin *fakeRoutingAdmin) SyncRouting(context.Context) error {
	admin.calls++
	return admin.err
}

func (admin *fakePathAdmin) ActivatePath(_ context.Context, generation uint32) error {
	admin.activations = append(admin.activations, generation)
	if admin.err == nil {
		admin.state = dataplane.PathState{Active: true, Generation: generation}
	}
	return admin.err
}

func (admin *fakePathAdmin) BlockPath(context.Context) error {
	admin.blocks++
	if admin.err == nil {
		admin.state = dataplane.PathState{}
	}
	return admin.err
}

func (admin *fakePathAdmin) ObservePath(context.Context) (dataplane.PathState, error) {
	return admin.state, admin.err
}

func (admin *fakeDataPlaneAdmin) RestartMihomo(context.Context) error {
	admin.restarts++
	return admin.err
}

func (admin *fakeDataPlaneAdmin) FailClosedMihomo(context.Context) error {
	admin.blocks++
	return admin.err
}

func TestBrokerStageApplyConfirmRoundTripDoesNotExposeEngineDetails(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	server, err := NewBrokerServer(engine)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	// The test client normally uses a fixed http://unix origin. Point requests
	// at httptest while exercising the same bounded JSON protocol.
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}

	prepared, err := client.Stage(ctx, validCandidate())
	if err != nil || prepared.ConfirmToken == "" {
		t.Fatalf("Stage() = %+v, %v", prepared, err)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm" {
		t.Fatalf("broker Stage calls = %s", got)
	}
	if err := client.Apply(ctx, prepared.ApplyID); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := client.Confirm(ctx, prepared.ApplyID, ConfirmEvidence{Token: prepared.ConfirmToken, LocalDestinationIP: "192.168.210.1"}); err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm,apply,disarm,commit" {
		t.Fatalf("broker operation calls = %s", got)
	}
}

func TestBrokerRejectsUnknownJSONAndRedactsPrivilegedFailure(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	backend.snapshotErr = errors.New("private filesystem detail /root/secret")
	server, _ := NewBrokerServer(engine)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/stage", strings.NewReader(`{"interface_name":"enp2s0","unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown JSON status = %d", response.StatusCode)
	}

	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	_, err = client.Stage(ctx, validCandidate())
	if err == nil || strings.Contains(err.Error(), "/root/secret") || strings.Contains(err.Error(), "filesystem detail") {
		t.Fatalf("redacted Stage() error = %v", err)
	}
}

func TestBrokerExposesOnlyFixedMihomoRestartAndFailClosedOperations(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeDataPlaneAdmin{}
	server, err := NewBrokerServerWithDataPlane(engine, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.RestartMihomo(ctx); err != nil {
		t.Fatalf("RestartMihomo() error = %v", err)
	}
	if err := client.FailClosedMihomo(ctx); err != nil {
		t.Fatalf("FailClosedMihomo() error = %v", err)
	}
	if admin.restarts != 1 || admin.blocks != 1 {
		t.Fatalf("data-plane admin calls = restart %d block %d", admin.restarts, admin.blocks)
	}
	admin.err = errors.New("private systemd detail")
	if err := client.RestartMihomo(ctx); err == nil || strings.Contains(err.Error(), "systemd detail") {
		t.Fatalf("redacted RestartMihomo() error = %v", err)
	}
}

func TestBrokerPathOperationsCarryOnlyGenerationAndRedactBackendErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	pathAdmin := &fakePathAdmin{}
	server, err := NewBrokerServerWithRuntime(engine, &fakeDataPlaneAdmin{}, pathAdmin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.ActivatePath(ctx, 17); err != nil {
		t.Fatalf("ActivatePath() error = %v", err)
	}
	state, err := client.ObservePath(ctx)
	if err != nil || state != (dataplane.PathState{Active: true, Generation: 17}) {
		t.Fatalf("ObservePath() = %+v, %v", state, err)
	}
	if err := client.BlockPath(ctx); err != nil {
		t.Fatalf("BlockPath() error = %v", err)
	}
	if len(pathAdmin.activations) != 1 || pathAdmin.activations[0] != 17 || pathAdmin.blocks != 1 {
		t.Fatalf("path admin calls = %v/%d", pathAdmin.activations, pathAdmin.blocks)
	}
	pathAdmin.err = errors.New("private nftables command detail")
	if err := client.ActivatePath(ctx, 18); err == nil || strings.Contains(err.Error(), "nftables command") {
		t.Fatalf("redacted ActivatePath() error = %v", err)
	}
}

func TestBrokerRoutingSyncHasNoParametersAndRedactsBackendErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	routingAdmin := &fakeRoutingAdmin{}
	server, err := NewBrokerServerWithNetworkRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, routingAdmin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.SyncRouting(ctx); err != nil {
		t.Fatalf("SyncRouting() error = %v", err)
	}
	if routingAdmin.calls != 1 {
		t.Fatalf("routing sync calls = %d", routingAdmin.calls)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/routing/sync", strings.NewReader(`{"table":1101}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || routingAdmin.calls != 1 {
		t.Fatalf("parameterized routing sync status/calls = %d/%d", response.StatusCode, routingAdmin.calls)
	}

	routingAdmin.err = errors.New("private iproute detail")
	if err := client.SyncRouting(ctx); err == nil || strings.Contains(err.Error(), "iproute detail") {
		t.Fatalf("redacted SyncRouting() error = %v", err)
	}
}

func TestBrokerBootstrapAuthorizationUsesTypedBoundedRequest(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeBootstrapAdmin{}
	server, err := NewBrokerServerWithServiceRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	input := dataplane.BootstrapAuthorization{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"203.0.113.10"}, Port: 443}
	if err := client.AuthorizeBootstrap(ctx, input); err != nil {
		t.Fatalf("AuthorizeBootstrap() error = %v", err)
	}
	if len(admin.requests) != 1 || admin.requests[0].ModemID != "modem-a" || admin.requests[0].Port != 443 {
		t.Fatalf("bootstrap admin requests = %+v", admin.requests)
	}
	admin.err = errors.New("private nft set detail")
	if err := client.AuthorizeBootstrap(ctx, input); err == nil || strings.Contains(err.Error(), "nft set detail") {
		t.Fatalf("redacted AuthorizeBootstrap() error = %v", err)
	}
	admin.err = nil
	if err := client.AuthorizeMihomoVersions(ctx, []string{"version-a", "version-b"}); err != nil {
		t.Fatalf("AuthorizeMihomoVersions() error = %v", err)
	}
	if len(admin.mihomo) != 1 || len(admin.mihomo[0].VersionIDs) != 2 {
		t.Fatalf("Mihomo endpoint requests = %+v", admin.mihomo)
	}
}

func TestBrokerWireGuardSyncHasNoParametersAndRedactsBackendErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeWireGuardAdmin{}
	server, err := NewBrokerServerWithManagementRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.SyncWireGuard(ctx); err != nil {
		t.Fatalf("SyncWireGuard() error = %v", err)
	}
	if admin.calls != 1 {
		t.Fatalf("WireGuard sync calls = %d", admin.calls)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/wireguard/sync", strings.NewReader(`{"modem_id":"modem-a"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || admin.calls != 1 {
		t.Fatalf("parameterized WireGuard sync status/calls = %d/%d", response.StatusCode, admin.calls)
	}

	admin.err = errors.New("private WireGuard key and command detail")
	if err := client.SyncWireGuard(ctx); err == nil || strings.Contains(err.Error(), "key and command") {
		t.Fatalf("redacted SyncWireGuard() error = %v", err)
	}
}

func TestBrokerLoggingSyncHasNoParametersAndRedactsBackendErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeLoggingAdmin{}
	server, err := NewBrokerServerWithLoggingRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, &fakeWireGuardAdmin{}, admin, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.SyncLogging(ctx); err != nil || admin.calls != 1 {
		t.Fatalf("SyncLogging() calls=%d error=%v", admin.calls, err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/logging/sync", strings.NewReader(`{"retention_days":1}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || admin.calls != 1 {
		t.Fatalf("parameterized logging sync status/calls = %d/%d", response.StatusCode, admin.calls)
	}
	admin.err = errors.New("private journald filesystem and command detail")
	if err := client.SyncLogging(ctx); err == nil || strings.Contains(err.Error(), "filesystem") || strings.Contains(err.Error(), "command detail") {
		t.Fatalf("redacted SyncLogging() error = %v", err)
	}
}

func TestBrokerJournalQueryIsTypedBoundedAndRedactsBackendErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeJournalAdmin{page: loggingpkg.JournalPage{Items: []loggingpkg.JournalEntry{{Cursor: "s=one", Message: "safe"}}}}
	server, err := NewBrokerServerWithLoggingRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, &fakeWireGuardAdmin{}, &fakeLoggingAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	query := loggingpkg.JournalQuery{Limit: 10, Component: loggingpkg.ComponentPathHealth, Search: "failed"}
	page, err := client.QueryLogs(ctx, query)
	if err != nil || len(page.Items) != 1 || len(admin.queries) != 1 || admin.queries[0].Limit != query.Limit || admin.queries[0].Component != query.Component || admin.queries[0].Search != query.Search {
		t.Fatalf("QueryLogs() = %+v queries=%+v error=%v", page, admin.queries, err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/logging/query", strings.NewReader(`{"limit":10,"unknown":"value"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || len(admin.queries) != 1 {
		t.Fatalf("unknown journal query status/calls = %d/%d", response.StatusCode, len(admin.queries))
	}
	admin.err = errors.New("private journal output and command detail")
	if _, err := client.QueryLogs(ctx, query); err == nil || strings.Contains(err.Error(), "journal output") || strings.Contains(err.Error(), "command detail") {
		t.Fatalf("redacted QueryLogs() error = %v", err)
	}
	admin.err = nil
	admin.page.Items = make([]loggingpkg.JournalEntry, 25)
	for index := range admin.page.Items {
		admin.page.Items[index] = loggingpkg.JournalEntry{Cursor: "s=oversized", Message: strings.Repeat("x", 4096)}
	}
	if _, err := client.QueryLogs(ctx, query); err == nil || !strings.Contains(err.Error(), "JOURNAL_RESPONSE_INVALID") {
		t.Fatalf("oversized QueryLogs() error = %v", err)
	}
}

func TestBrokerHostDiagnosticsIsParameterFreeBoundedAndRedactsErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeHostDiagnosticsAdmin{snapshot: diagnostics.HostSnapshot{SchemaVersion: diagnostics.HostSnapshotSchemaVersion, CollectedAt: "2026-08-24T18:00:00Z", OwnedRoutes: []byte("[]"), OwnedRules: []byte("[]"), Nftables: []byte("{}")}}
	server, err := NewBrokerServerWithDiagnosticsRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, &fakeWireGuardAdmin{}, &fakeLoggingAdmin{}, &fakeJournalAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	snapshot, err := client.CollectHostDiagnostics(ctx)
	if err != nil || snapshot.SchemaVersion != diagnostics.HostSnapshotSchemaVersion || admin.calls != 1 {
		t.Fatalf("CollectHostDiagnostics() = %+v calls=%d error=%v", snapshot, admin.calls, err)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/diagnostics/host", strings.NewReader(`{"command":"ip addr"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || admin.calls != 1 {
		t.Fatalf("parameterized host diagnostics status/calls = %d/%d", response.StatusCode, admin.calls)
	}

	admin.err = errors.New("private /root path and host command output")
	if _, err := client.CollectHostDiagnostics(ctx); err == nil || strings.Contains(err.Error(), "/root") || strings.Contains(err.Error(), "command output") {
		t.Fatalf("redacted host diagnostics error = %v", err)
	}
	admin.err = nil
	admin.snapshot.MihomoVersion = strings.Repeat("x", diagnostics.MaximumHostSnapshotBytes)
	if _, err := client.CollectHostDiagnostics(ctx); err == nil || !strings.Contains(err.Error(), "HOST_DIAGNOSTICS_RESPONSE_INVALID") {
		t.Fatalf("oversized host diagnostics error = %v", err)
	}
}

func TestBrokerRestoreApplyIsParameterFreeAndRedactsErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeRestoreAdmin{}
	server, err := NewBrokerServerWithRestoreRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, &fakeWireGuardAdmin{}, &fakeLoggingAdmin{}, &fakeJournalAdmin{}, &fakeHostDiagnosticsAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.ApplyPendingRestore(ctx); err != nil || admin.calls != 1 {
		t.Fatalf("ApplyPendingRestore() calls=%d error=%v", admin.calls, err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/restore/apply", strings.NewReader(`{"restore_id":"restore-attacker"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || admin.calls != 1 {
		t.Fatalf("parameterized restore apply status/calls = %d/%d", response.StatusCode, admin.calls)
	}
	admin.err = errors.New("private pending restore path and systemd detail")
	if err := client.ApplyPendingRestore(ctx); err == nil || strings.Contains(err.Error(), "pending restore path") || strings.Contains(err.Error(), "systemd detail") {
		t.Fatalf("redacted restore apply error = %v", err)
	}
}

func TestBrokerUpdateApplyIsParameterFreeAndRedactsErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeUpdateAdmin{}
	server, err := NewBrokerServerWithUpdateRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, &fakeWireGuardAdmin{}, &fakeLoggingAdmin{}, &fakeJournalAdmin{}, &fakeHostDiagnosticsAdmin{}, &fakeRestoreAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	if err := client.ApplyPendingUpdate(ctx); err != nil || admin.calls != 1 {
		t.Fatalf("ApplyPendingUpdate() calls=%d error=%v", admin.calls, err)
	}
	admin.status = UpdateTransactionStatus{Exists: true, UpdateID: "update-20260824T220000Z-0123456789abcdef01234567", State: "ROLLED_BACK", OldVersion: "1.1.0", NewVersion: "1.2.0", ErrorCode: "NEW_RELEASE_HEALTH_FAILED"}
	status, err := client.UpdateStatus(ctx)
	if err != nil || status != admin.status {
		t.Fatalf("UpdateStatus() = %+v,%v", status, err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/update/status", strings.NewReader(`{"update_id":"attacker-path"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("parameterized update status = %d", response.StatusCode)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/update/apply", strings.NewReader(`{"update_id":"attacker-path"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err = httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || admin.calls != 1 {
		t.Fatalf("parameterized update apply status/calls = %d/%d", response.StatusCode, admin.calls)
	}
	admin.err = errors.New("private staged release path and systemd detail")
	if err := client.ApplyPendingUpdate(ctx); err == nil || strings.Contains(err.Error(), "staged release path") || strings.Contains(err.Error(), "systemd detail") {
		t.Fatalf("redacted update apply error = %v", err)
	}
}

func TestBrokerTrafficCountersAreParameterFreeAndRedactRootErrors(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	admin := &fakeTrafficAdmin{snapshot: traffic.AuthoritativeSnapshot{
		Counters: traffic.Counters{UploadBytes: 123, DownloadBytes: 456, ServiceUploadBytes: 12, ServiceDownloadBytes: 34},
		BootID:   "11111111-2222-3333-4444-555555555555", FirewallGeneration: 19,
	}}
	server, err := NewBrokerServerWithTrafficRuntime(engine, &fakeDataPlaneAdmin{}, &fakePathAdmin{}, &fakeRoutingAdmin{}, &fakeBootstrapAdmin{}, &fakeWireGuardAdmin{}, &fakeLoggingAdmin{}, &fakeJournalAdmin{}, &fakeHostDiagnosticsAdmin{}, &fakeRestoreAdmin{}, &fakeUpdateAdmin{}, admin)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newBrokerClientForHTTP(httpServer.Client())
	client.client.Transport = rewriteOriginTransport{base: httpServer.URL, next: httpServer.Client().Transport}
	snapshot, err := client.ReadTrafficCounters(ctx)
	if err != nil || snapshot != admin.snapshot || admin.calls != 1 {
		t.Fatalf("ReadTrafficCounters() = %+v calls=%d error=%v", snapshot, admin.calls, err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/v1/traffic/counters", strings.NewReader(`{"table":"attacker"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || admin.calls != 1 {
		t.Fatalf("parameterized traffic status/calls = %d/%d", response.StatusCode, admin.calls)
	}
	admin.err = errors.New("private nftables command and namespace detail")
	if _, err := client.ReadTrafficCounters(ctx); err == nil || strings.Contains(err.Error(), "nftables command") || strings.Contains(err.Error(), "namespace detail") {
		t.Fatalf("redacted traffic error = %v", err)
	}
}

func TestPeerAuthorizingListenerDropsWrongUIDBeforeAcceptingAllowedPeer(t *testing.T) {
	unauthorizedServer, unauthorizedClient := net.Pipe()
	authorizedServer, authorizedClient := net.Pipe()
	defer unauthorizedClient.Close()
	defer authorizedClient.Close()
	base := &scriptedListener{connections: []net.Conn{unauthorizedServer, authorizedServer}}
	uids := map[net.Conn]uint32{unauthorizedServer: 1001, authorizedServer: 1002}
	listener := &PeerAuthorizingListener{Listener: base, AllowedUID: 1002, PeerUID: func(connection net.Conn) (uint32, error) { return uids[connection], nil }}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer accepted.Close()
	if accepted != authorizedServer {
		t.Fatal("listener accepted unauthorized peer")
	}
	_ = unauthorizedClient.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := unauthorizedClient.Read(buffer); err == nil {
		t.Fatal("unauthorized connection remained open")
	}
}

type rewriteOriginTransport struct {
	base string
	next http.RoundTripper
}

func (transport rewriteOriginTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(transport.base, "http://")
	return transport.next.RoundTrip(clone)
}

type scriptedListener struct {
	connections []net.Conn
	index       int
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	if listener.index >= len(listener.connections) {
		return nil, errors.New("no more scripted connections")
	}
	connection := listener.connections[listener.index]
	listener.index++
	return connection, nil
}

func (*scriptedListener) Close() error   { return nil }
func (*scriptedListener) Addr() net.Addr { return fakeAddr("broker") }

type fakeAddr string

func (address fakeAddr) Network() string { return string(address) }
func (address fakeAddr) String() string  { return string(address) }
