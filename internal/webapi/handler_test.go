package webapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	runtimepkg "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/hilink"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
	updatepkg "gateway-vpn/internal/update"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

func TestAPIRequiresSessionAndCSRFAndRedactsSecrets(t *testing.T) {
	server, ctx := testServer(t)
	unauthenticated := httptest.NewRecorder()
	server.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/gateway/status", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	cookie, csrf := login(t, server)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/subscriptions", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "/secret/sub-a") || strings.Contains(response.Body.String(), "SourceSecretRef") {
		t.Fatalf("subscriptions response = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/modems", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), strings.Repeat("a", 64)) || strings.Contains(response.Body.String(), "IdentityHash") {
		t.Fatalf("modems response leaks identity: %d %s", response.Code, response.Body.String())
	}

	body := []byte(`{"name":"Check","kind":"domain","value":"example.com","required":true,"timeout_seconds":8,"success_mode":"any_http_response"}`)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/bypass-targets", bytes.NewReader(body))
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/bypass-targets", bytes.NewReader(body))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("POST with CSRF = %d %s", response.Code, response.Body.String())
	}
	var count int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM bypass_probe_targets").Scan(&count); err != nil || count != 1 {
		t.Fatalf("target count = %d, %v", count, err)
	}
}

func TestRuntimeMetricsRequiresSessionAndExposesOnlyBoundedProcessCounters(t *testing.T) {
	server, _ := testServer(t)
	server.startedAt = time.Now().UTC().Add(-2 * time.Minute)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime-metrics", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated runtime metrics = %d %s", response.Code, response.Body.String())
	}

	cookie, _ := login(t, server)
	request = httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime-metrics", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("runtime metrics = %d %s", response.Code, response.Body.String())
	}
	var metrics map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"schema_version": true, "collected_at": true, "uptime_seconds": true,
		"goroutines": true, "heap_alloc_bytes": true, "heap_inuse_bytes": true,
		"stack_inuse_bytes": true, "go_runtime_sys_bytes": true,
		"mallocs_total": true, "frees_total": true, "live_heap_objects": true,
		"gc_cycles_total": true, "gc_pause_total_nanoseconds": true,
		"process_rss_bytes": true, "open_file_descriptors": true,
	}
	for key := range metrics {
		if !allowed[key] {
			t.Errorf("unexpected runtime metric %q", key)
		}
	}
	for _, required := range []string{
		"schema_version", "collected_at", "uptime_seconds", "goroutines",
		"heap_alloc_bytes", "heap_inuse_bytes", "stack_inuse_bytes",
		"go_runtime_sys_bytes", "mallocs_total", "frees_total",
		"live_heap_objects", "gc_cycles_total", "gc_pause_total_nanoseconds",
	} {
		if _, exists := metrics[required]; !exists {
			t.Errorf("runtime metrics missing %q: %s", required, response.Body.String())
		}
	}
	if metrics["schema_version"] != float64(1) || metrics["uptime_seconds"].(float64) < 100 || metrics["goroutines"].(float64) < 1 || metrics["heap_alloc_bytes"].(float64) < 1 {
		t.Fatalf("invalid runtime metric values: %s", response.Body.String())
	}
	if _, err := time.Parse(time.RFC3339Nano, metrics["collected_at"].(string)); err != nil {
		t.Fatalf("runtime collected_at = %v", metrics["collected_at"])
	}
	if runtimepkg.GOOS == "linux" {
		rss, hasRSS := metrics["process_rss_bytes"].(float64)
		fds, hasFDs := metrics["open_file_descriptors"].(float64)
		if !hasRSS || !hasFDs || rss < 1 || fds < 1 {
			t.Fatalf("Linux process metrics missing: %s", response.Body.String())
		}
	} else if metrics["process_rss_bytes"] != nil || metrics["open_file_descriptors"] != nil {
		t.Fatalf("unsupported host exposed Linux process metrics: %s", response.Body.String())
	}
	for index := 1; index < journalQueryLimit; index++ {
		request = httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime-metrics", nil)
		request.AddCookie(cookie)
		response = httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("runtime metrics request %d = %d %s", index+1, response.Code, response.Body.String())
		}
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime-metrics", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || !strings.Contains(response.Body.String(), "RUNTIME_METRICS_RATE_LIMITED") {
		t.Fatalf("runtime metrics rate limit = %d retry=%q %s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
}

func TestBootstrapPasswordMustBeChangedBeforeAnyOtherAPI(t *testing.T) {
	server, ctx := testServer(t)
	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE users SET must_change_password=1 WHERE id='admin'"); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := login(t, server)

	blocked := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/status", nil)
	blocked.AddCookie(cookie)
	blockedResponse := httptest.NewRecorder()
	server.ServeHTTP(blockedResponse, blocked)
	if blockedResponse.Code != http.StatusForbidden || !strings.Contains(blockedResponse.Body.String(), "PASSWORD_CHANGE_REQUIRED") {
		t.Fatalf("temporary password protected API = %d %s", blockedResponse.Code, blockedResponse.Body.String())
	}

	withoutCSRF := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"correct horse battery staple","new_password":"new secure password 123","password_confirmation":"new secure password 123"}`))
	withoutCSRF.AddCookie(cookie)
	withoutCSRFResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden || !strings.Contains(withoutCSRFResponse.Body.String(), "CSRF_INVALID") {
		t.Fatalf("password change without CSRF = %d %s", withoutCSRFResponse.Code, withoutCSRFResponse.Body.String())
	}

	change := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"correct horse battery staple","new_password":"new secure password 123","password_confirmation":"new secure password 123"}`))
	change.AddCookie(cookie)
	change.Header.Set("X-CSRF-Token", csrf)
	changeResponse := httptest.NewRecorder()
	server.ServeHTTP(changeResponse, change)
	if changeResponse.Code != http.StatusNoContent {
		t.Fatalf("mandatory password change = %d %s", changeResponse.Code, changeResponse.Body.String())
	}

	allowed := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/status", nil)
	allowed.AddCookie(cookie)
	allowedResponse := httptest.NewRecorder()
	server.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusOK {
		t.Fatalf("API after password change = %d %s", allowedResponse.Code, allowedResponse.Body.String())
	}
	if _, err := server.dependencies.Auth.Login(ctx, "admin", "correct horse battery staple", "old-password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old bootstrap password Login() error = %v", err)
	}
	if _, err := server.dependencies.Auth.Login(ctx, "admin", "new secure password 123", "new-password"); err != nil {
		t.Fatal(err)
	}
}

func TestAdministratorUsersAndSessionsAPIIsAuditedAndSecretFree(t *testing.T) {
	server, _ := testServer(t)
	firstCookie, firstCSRF := login(t, server)
	create := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users", strings.NewReader(`{"username":"support-admin","password":"temporary support password 123","password_confirmation":"temporary support password 123"}`))
	create.AddCookie(firstCookie)
	create.Header.Set("X-CSRF-Token", firstCSRF)
	createResponse := httptest.NewRecorder()
	server.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated || strings.Contains(createResponse.Body.String(), "temporary support") || strings.Contains(createResponse.Body.String(), "password_hash") {
		t.Fatalf("create user = %d %s", createResponse.Code, createResponse.Body.String())
	}
	var created auth.User
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil || created.ID == "" || !created.MustChangePassword {
		t.Fatalf("created user = %+v, %v", created, err)
	}

	userLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"support-admin","password":"temporary support password 123"}`))
	userLogin.RemoteAddr = "192.168.200.3:12345"
	userLoginResponse := httptest.NewRecorder()
	server.ServeHTTP(userLoginResponse, userLogin)
	if userLoginResponse.Code != http.StatusOK || !strings.Contains(userLoginResponse.Body.String(), `"must_change_password":true`) {
		t.Fatalf("new user login = %d %s", userLoginResponse.Code, userLoginResponse.Body.String())
	}
	userCookies := userLoginResponse.Result().Cookies()
	var userLoginPayload struct {
		CSRF string `json:"csrf_token"`
	}
	if len(userCookies) != 1 || json.Unmarshal(userLoginResponse.Body.Bytes(), &userLoginPayload) != nil {
		t.Fatalf("new user session = %+v %s", userCookies, userLoginResponse.Body.String())
	}
	blocked := httptest.NewRequest(http.MethodGet, "/api/v1/auth/users", nil)
	blocked.AddCookie(userCookies[0])
	blockedResponse := httptest.NewRecorder()
	server.ServeHTTP(blockedResponse, blocked)
	if blockedResponse.Code != http.StatusForbidden || !strings.Contains(blockedResponse.Body.String(), "PASSWORD_CHANGE_REQUIRED") {
		t.Fatalf("new temporary user protected API = %d %s", blockedResponse.Code, blockedResponse.Body.String())
	}
	change := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", strings.NewReader(`{"current_password":"temporary support password 123","new_password":"permanent support password 123","password_confirmation":"permanent support password 123"}`))
	change.AddCookie(userCookies[0])
	change.Header.Set("X-CSRF-Token", userLoginPayload.CSRF)
	changeResponse := httptest.NewRecorder()
	server.ServeHTTP(changeResponse, change)
	if changeResponse.Code != http.StatusNoContent {
		t.Fatalf("new user mandatory password change = %d %s", changeResponse.Code, changeResponse.Body.String())
	}

	usersRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/users", nil)
	usersRequest.AddCookie(firstCookie)
	usersResponse := httptest.NewRecorder()
	server.ServeHTTP(usersResponse, usersRequest)
	if usersResponse.Code != http.StatusOK || !strings.Contains(usersResponse.Body.String(), "all_local_users_are_administrators") || strings.Contains(usersResponse.Body.String(), "password_hash") || strings.Contains(usersResponse.Body.String(), "permanent support") {
		t.Fatalf("users list = %d %s", usersResponse.Code, usersResponse.Body.String())
	}

	disable := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/users/"+created.ID, strings.NewReader(`{"enabled":false}`))
	disable.AddCookie(firstCookie)
	disable.Header.Set("X-CSRF-Token", firstCSRF)
	disableResponse := httptest.NewRecorder()
	server.ServeHTTP(disableResponse, disable)
	if disableResponse.Code != http.StatusOK || !strings.Contains(disableResponse.Body.String(), `"enabled":false`) {
		t.Fatalf("disable user = %d %s", disableResponse.Code, disableResponse.Body.String())
	}

	deleteWithoutConfirmation := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/"+created.ID, nil)
	deleteWithoutConfirmation.AddCookie(firstCookie)
	deleteWithoutConfirmation.Header.Set("X-CSRF-Token", firstCSRF)
	deleteWithoutConfirmationResponse := httptest.NewRecorder()
	server.ServeHTTP(deleteWithoutConfirmationResponse, deleteWithoutConfirmation)
	if deleteWithoutConfirmationResponse.Code != http.StatusConflict {
		t.Fatalf("delete user without confirmation = %d %s", deleteWithoutConfirmationResponse.Code, deleteWithoutConfirmationResponse.Body.String())
	}
	deleteUser := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users/"+created.ID, nil)
	deleteUser.AddCookie(firstCookie)
	deleteUser.Header.Set("X-CSRF-Token", firstCSRF)
	deleteUser.Header.Set("X-Confirm-Destructive", "delete-disabled-user")
	deleteUserResponse := httptest.NewRecorder()
	server.ServeHTTP(deleteUserResponse, deleteUser)
	if deleteUserResponse.Code != http.StatusNoContent {
		t.Fatalf("delete disabled user = %d %s", deleteUserResponse.Code, deleteUserResponse.Body.String())
	}

	secondCookie, secondCSRF := login(t, server)
	sessionsRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	sessionsRequest.AddCookie(secondCookie)
	sessionsResponse := httptest.NewRecorder()
	server.ServeHTTP(sessionsResponse, sessionsRequest)
	var sessionsPayload struct {
		Items []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"items"`
	}
	if sessionsResponse.Code != http.StatusOK || json.Unmarshal(sessionsResponse.Body.Bytes(), &sessionsPayload) != nil || len(sessionsPayload.Items) != 2 {
		t.Fatalf("sessions list = %d %s", sessionsResponse.Code, sessionsResponse.Body.String())
	}
	var oldSessionID string
	for _, item := range sessionsPayload.Items {
		if !item.Current {
			oldSessionID = item.ID
		}
	}
	if oldSessionID == "" {
		t.Fatalf("sessions current marker = %+v", sessionsPayload.Items)
	}
	revoke := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/sessions/"+oldSessionID, nil)
	revoke.AddCookie(secondCookie)
	revoke.Header.Set("X-CSRF-Token", secondCSRF)
	revokeResponse := httptest.NewRecorder()
	server.ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke old session = %d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	oldSessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	oldSessionRequest.AddCookie(firstCookie)
	oldSessionResponse := httptest.NewRecorder()
	server.ServeHTTP(oldSessionResponse, oldSessionRequest)
	if oldSessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked old session = %d %s", oldSessionResponse.Code, oldSessionResponse.Body.String())
	}
}

func TestPeriodicHealthAPIReportsDurableScheduleAndPerModemBudget(t *testing.T) {
	server, ctx := testServer(t)
	now := time.Now().UTC()
	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY' WHERE id='modem-a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := server.dependencies.Database.ExecContext(ctx, `
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at, activated_at)
VALUES ('version-a', 'sub-a', ?, 0, 'LKG', ?, ?)`, hex.EncodeToString(make([]byte, 32)), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='version-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	cell, err := server.dependencies.Paths.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	repository := &health.PeriodicRepository{Database: server.dependencies.Database, Now: func() time.Time { return now }}
	if err := repository.Reconcile(ctx, cell.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Record(ctx, cell.ID, health.PeriodicFailed, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := repository.Defer(ctx, cell.ID, scheduler.DecisionDeferredBudget, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	probeScheduler, err := scheduler.New(scheduler.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	admission, err := probeScheduler.Acquire(ctx, scheduler.Request{ModemID: "modem-a", TargetID: "target-a", Class: scheduler.ClassActive, EstimatedBytes: 1024})
	if err != nil || admission.Permit == nil {
		t.Fatalf("probe budget admission = %+v, %v", admission, err)
	}
	admission.Permit.Release(512)
	server.dependencies.PeriodicHealth = repository
	server.dependencies.PeriodicHealthConfig = candidateruntime.DefaultPeriodicConfig()
	server.dependencies.ProbeBudget = probeScheduler
	cookie, _ := login(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health/periodic", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("periodic health status = %d %s", response.Code, response.Body.String())
	}
	var payload struct {
		Items []struct {
			PathID         string `json:"path_id"`
			ProbeClass     string `json:"probe_class"`
			LastResult     string `json:"last_result"`
			Failures       int    `json:"consecutive_failures"`
			DeferredReason string `json:"deferred_reason"`
			ModemID        string `json:"modem_id"`
			SubscriptionID string `json:"subscription_id"`
		} `json:"items"`
		Budgets []struct {
			ModemID       string `json:"modem_id"`
			ObservedBytes int64  `json:"observed_bytes"`
			Requests      int64  `json:"requests"`
		} `json:"budgets"`
		Config struct {
			ActiveInterval   int64 `json:"active_interval_seconds"`
			FailureThreshold int   `json:"failure_threshold"`
		} `json:"config"`
		BudgetPolicy struct {
			DailySoftLimit int64 `json:"daily_soft_limit_bytes"`
			StandbyLimit   int64 `json:"standby_limit_bytes"`
		} `json:"budget_policy"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 1 || payload.Items[0].PathID != cell.ID || payload.Items[0].ProbeClass != health.ProbeClassActive || payload.Items[0].LastResult != health.PeriodicDeferred || payload.Items[0].Failures != 1 || payload.Items[0].DeferredReason != scheduler.DecisionDeferredBudget || payload.Items[0].ModemID != "modem-a" || payload.Items[0].SubscriptionID != "sub-a" {
		t.Fatalf("periodic health items = %+v", payload.Items)
	}
	if len(payload.Budgets) != 1 || payload.Budgets[0].ModemID != "modem-a" || payload.Budgets[0].ObservedBytes != 512 || payload.Budgets[0].Requests != 1 || payload.Config.ActiveInterval != 10 || payload.Config.FailureThreshold != 3 || payload.BudgetPolicy.DailySoftLimit == 0 || payload.BudgetPolicy.StandbyLimit >= payload.BudgetPolicy.DailySoftLimit {
		t.Fatalf("periodic health policy/budgets = %+v %+v %+v", payload.Config, payload.BudgetPolicy, payload.Budgets)
	}
}

func TestLoggingSettingsAPIAppliesDynamicLevelsTTLAndAudit(t *testing.T) {
	server, ctx := testServer(t)
	clock := time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC)
	controller, err := loggingpkg.NewController(loggingpkg.DefaultSettings(), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Attach(ctx, server.dependencies.Database); err != nil {
		t.Fatal(err)
	}
	server.dependencies.Logging = controller
	loggingSync := &fakeLoggingSynchronizer{err: errors.New("broker unavailable")}
	server.dependencies.LoggingSync = loggingSync
	server.dependencies.Now = func() time.Time { return clock }
	cookie, csrf := login(t, server)

	get := httptest.NewRequest(http.MethodGet, "/api/v1/settings/logging", nil)
	get.AddCookie(cookie)
	getResponse := httptest.NewRecorder()
	server.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), `"global_level":"info"`) || !strings.Contains(getResponse.Body.String(), `"audit_minimum_level":"info"`) {
		t.Fatalf("get logging settings = %d %s", getResponse.Code, getResponse.Body.String())
	}

	payload := `{
  "global_level":"warning",
  "component_levels":{"subscription":"error","auth_audit":"info"},
  "debug_components":["path_health"],
  "debug_ttl_seconds":300,
  "retention_days":30,
  "max_disk_usage_bytes":536870912,
  "diagnostic_excerpt_bytes":2097152,
  "health_error_aggregation_seconds":90
}`
	withoutCSRF := httptest.NewRequest(http.MethodPut, "/api/v1/settings/logging", strings.NewReader(payload))
	withoutCSRF.AddCookie(cookie)
	withoutCSRFResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("logging PUT without CSRF = %d", withoutCSRFResponse.Code)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/settings/logging", strings.NewReader(payload))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update logging settings = %d %s", response.Code, response.Body.String())
	}
	var result struct {
		GlobalLevel           string            `json:"global_level"`
		EffectiveLevels       map[string]string `json:"effective_levels"`
		DebugRemainingSeconds int64             `json:"debug_remaining_seconds"`
		RetentionApplyState   string            `json:"retention_apply_state"`
		RetentionSyncRequest  string            `json:"retention_sync_request"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.GlobalLevel != loggingpkg.LevelWarning || result.EffectiveLevels[loggingpkg.ComponentPathHealth] != loggingpkg.LevelDebug || result.EffectiveLevels[loggingpkg.ComponentSubscription] != loggingpkg.LevelError || result.EffectiveLevels[loggingpkg.ComponentAuthAudit] != loggingpkg.LevelInfo || result.DebugRemainingSeconds != 300 || result.RetentionApplyState != loggingpkg.RetentionPending || result.RetentionSyncRequest != "RETRY_PENDING" || loggingSync.calls != 1 {
		t.Fatalf("updated logging response = %+v", result)
	}
	var auditCount int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='LOGGING_SETTINGS_CHANGED' AND severity='INFO'").Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("logging settings audit count = %d, %v", auditCount, err)
	}

	invalid := strings.Replace(payload, `"global_level":"warning"`, `"global_level":"debug"`, 1)
	invalidRequest := httptest.NewRequest(http.MethodPut, "/api/v1/settings/logging", strings.NewReader(invalid))
	invalidRequest.AddCookie(cookie)
	invalidRequest.Header.Set("X-CSRF-Token", csrf)
	invalidResponse := httptest.NewRecorder()
	server.ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusBadRequest || !strings.Contains(invalidResponse.Body.String(), "temporary") && !strings.Contains(invalidResponse.Body.String(), "global logging level") {
		t.Fatalf("permanent debug response = %d %s", invalidResponse.Code, invalidResponse.Body.String())
	}
}

func TestJournalAPIUsesAllowlistedFiltersPaginationAndSessionRateLimit(t *testing.T) {
	server, _ := testServer(t)
	journal := &fakeJournalReader{page: loggingpkg.JournalPage{
		Items:   []loggingpkg.JournalEntry{{Cursor: "s=one", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Severity: loggingpkg.LevelWarning, Component: loggingpkg.ComponentPathHealth, Message: "safe failure", PathID: "path-a"}},
		HasMore: true, NextCursor: "s=one",
	}}
	server.dependencies.Journal = journal
	cookie, _ := login(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=10&level=warning&level=error&component=path_health&path_id=path-a&search=failure", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"next_cursor":"s=one"`) || len(journal.queries) != 1 {
		t.Fatalf("journal query = %d queries=%+v %s", response.Code, journal.queries, response.Body.String())
	}
	query := journal.queries[0]
	if query.Limit != 10 || len(query.Levels) != 2 || query.Levels[0] != loggingpkg.LevelWarning || query.Levels[1] != loggingpkg.LevelError || query.Component != loggingpkg.ComponentPathHealth || query.PathID != "path-a" || query.Search != "failure" {
		t.Fatalf("normalized journal query = %+v", query)
	}
	unknown := httptest.NewRequest(http.MethodGet, "/api/v1/logs?journalctl_argument=--all", nil)
	unknown.AddCookie(cookie)
	unknownResponse := httptest.NewRecorder()
	server.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusBadRequest || len(journal.queries) != 1 {
		t.Fatalf("unknown journal filter = %d calls=%d", unknownResponse.Code, len(journal.queries))
	}
	unsafe := httptest.NewRequest(http.MethodGet, "/api/v1/logs?cursor=%24%28command%29", nil)
	unsafe.AddCookie(cookie)
	unsafeResponse := httptest.NewRecorder()
	server.ServeHTTP(unsafeResponse, unsafe)
	if unsafeResponse.Code != http.StatusBadRequest || len(journal.queries) != 1 {
		t.Fatalf("unsafe journal cursor = %d calls=%d", unsafeResponse.Code, len(journal.queries))
	}
	// Three requests above already consumed the intentionally strict session
	// budget. Fill the remaining slots and verify the next request is rejected
	// without reaching the privileged reader.
	for index := 3; index < journalQueryLimit; index++ {
		current := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=1", nil)
		current.AddCookie(cookie)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, current)
		if recorder.Code != http.StatusOK {
			t.Fatalf("journal request %d = %d", index+1, recorder.Code)
		}
	}
	callsBeforeLimit := len(journal.queries)
	limited := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=1", nil)
	limited.AddCookie(cookie)
	limitedResponse := httptest.NewRecorder()
	server.ServeHTTP(limitedResponse, limited)
	if limitedResponse.Code != http.StatusTooManyRequests || limitedResponse.Header().Get("Retry-After") == "" || len(journal.queries) != callsBeforeLimit {
		t.Fatalf("journal rate limit = %d retry=%q calls=%d/%d", limitedResponse.Code, limitedResponse.Header().Get("Retry-After"), len(journal.queries), callsBeforeLimit)
	}
}

func TestDiagnosticBundleAPIRequiresCSRFReturnsAttachmentAuditsAndRateLimits(t *testing.T) {
	server, ctx := testServer(t)
	now := time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC)
	server.dependencies.Now = func() time.Time { return now }
	content := []byte("PK-safe-diagnostic")
	digest := sha256.Sum256(content)
	bundler := &fakeDiagnosticBundler{
		description: diagnostics.Description{Available: true, Format: "zip", SchemaVersion: 1, DownloadEndpoint: "/api/v1/system/diagnostics", SecretsIncluded: false, ConfiguredJournalExcerptBytes: 1 << 20},
		bundle: diagnostics.Bundle{
			Filename: "gateway-vpn-diagnostics-20260824T180000Z.zip", Content: content,
			SHA256: hex.EncodeToString(digest[:]), UncompressedSize: 1024,
			Manifest: diagnostics.Manifest{SchemaVersion: 1, Complete: false, SectionErrors: []diagnostics.SectionError{{Section: "host/wireguard", Code: "WIREGUARD_SUMMARY_UNAVAILABLE"}}, SectionWarnings: []diagnostics.SectionError{}},
		},
	}
	server.dependencies.Diagnostics = bundler
	cookie, csrf := login(t, server)

	descriptionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/diagnostics", nil)
	descriptionRequest.AddCookie(cookie)
	descriptionResponse := httptest.NewRecorder()
	server.ServeHTTP(descriptionResponse, descriptionRequest)
	if descriptionResponse.Code != http.StatusOK || !strings.Contains(descriptionResponse.Body.String(), `"secrets_included":false`) || !strings.Contains(descriptionResponse.Body.String(), `"format":"zip"`) {
		t.Fatalf("diagnostic description = %d %s", descriptionResponse.Code, descriptionResponse.Body.String())
	}

	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/system/diagnostics", nil)
	withoutCSRF.AddCookie(cookie)
	withoutCSRFResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden || bundler.builds != 0 {
		t.Fatalf("diagnostic without CSRF = %d builds=%d", withoutCSRFResponse.Code, bundler.builds)
	}

	parameterized := httptest.NewRequest(http.MethodPost, "/api/v1/system/diagnostics", strings.NewReader(`{"include_secrets":true}`))
	parameterized.AddCookie(cookie)
	parameterized.Header.Set("X-CSRF-Token", csrf)
	parameterizedResponse := httptest.NewRecorder()
	server.ServeHTTP(parameterizedResponse, parameterized)
	if parameterizedResponse.Code != http.StatusBadRequest || bundler.builds != 0 {
		t.Fatalf("parameterized diagnostic = %d builds=%d", parameterizedResponse.Code, bundler.builds)
	}

	for index := 0; index < diagnosticBundleLimit; index++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/system/diagnostics", nil)
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), content) || response.Header().Get("Content-Type") != "application/zip" || response.Header().Get("Content-Disposition") != `attachment; filename="gateway-vpn-diagnostics-20260824T180000Z.zip"` || response.Header().Get("X-Content-SHA256") != hex.EncodeToString(digest[:]) || response.Header().Get("X-Diagnostic-Complete") != "false" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("diagnostic download %d = %d headers=%v body=%q", index, response.Code, response.Header(), response.Body.Bytes())
		}
	}
	rateLimited := httptest.NewRequest(http.MethodPost, "/api/v1/system/diagnostics", nil)
	rateLimited.AddCookie(cookie)
	rateLimited.Header.Set("X-CSRF-Token", csrf)
	rateLimitedResponse := httptest.NewRecorder()
	server.ServeHTTP(rateLimitedResponse, rateLimited)
	if rateLimitedResponse.Code != http.StatusTooManyRequests || rateLimitedResponse.Header().Get("Retry-After") == "" || bundler.builds != diagnosticBundleLimit {
		t.Fatalf("diagnostic rate limit = %d retry=%q builds=%d", rateLimitedResponse.Code, rateLimitedResponse.Header().Get("Retry-After"), bundler.builds)
	}
	var auditCount int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='DIAGNOSTIC_BUNDLE_CREATED' AND severity='INFO'").Scan(&auditCount); err != nil || auditCount != diagnosticBundleLimit {
		t.Fatalf("diagnostic audit count = %d, %v", auditCount, err)
	}
	var details string
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT details_json FROM events WHERE type='DIAGNOSTIC_BUNDLE_CREATED' ORDER BY id DESC LIMIT 1").Scan(&details); err != nil || !strings.Contains(details, hex.EncodeToString(digest[:])) || !strings.Contains(details, "WIREGUARD_SUMMARY_UNAVAILABLE") || strings.Contains(details, "session") {
		t.Fatalf("diagnostic audit details = %q, %v", details, err)
	}
}

func TestManualDatabaseSnapshotsRequireCSRFVerifyBeforeAuditAndRateLimit(t *testing.T) {
	server, ctx := testServer(t)
	var sequence int
	var databaseName, databasePath string
	if err := server.dependencies.Database.QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &databaseName, &databasePath); err != nil {
		t.Fatal(err)
	}
	manager, err := backup.NewManager(server.dependencies.Database, filepath.Dir(databasePath), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	server.dependencies.Backups = manager
	cookie, csrf := login(t, server)

	get := httptest.NewRequest(http.MethodGet, "/api/v1/system/backups", nil)
	get.AddCookie(cookie)
	getResponse := httptest.NewRecorder()
	server.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), `"verified_count":0`) || !strings.Contains(getResponse.Body.String(), `"portable_encrypted_backup_available":false`) {
		t.Fatalf("initial backup inventory = %d %s", getResponse.Code, getResponse.Body.String())
	}

	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/system/backups/snapshot", nil)
	withoutCSRF.AddCookie(cookie)
	withoutCSRFResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("snapshot without CSRF = %d", withoutCSRFResponse.Code)
	}
	parameterized := httptest.NewRequest(http.MethodPost, "/api/v1/system/backups/snapshot", strings.NewReader(`{}`))
	parameterized.AddCookie(cookie)
	parameterized.Header.Set("X-CSRF-Token", csrf)
	parameterizedResponse := httptest.NewRecorder()
	server.ServeHTTP(parameterizedResponse, parameterized)
	if parameterizedResponse.Code != http.StatusBadRequest {
		t.Fatalf("parameterized snapshot = %d %s", parameterizedResponse.Code, parameterizedResponse.Body.String())
	}

	ids := []string{}
	for index := 0; index < diagnosticBundleLimit; index++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/system/backups/snapshot", nil)
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"verified":true`) || strings.Contains(response.Body.String(), manager.Root) {
			t.Fatalf("snapshot %d = %d %s", index, response.Code, response.Body.String())
		}
		var item backup.InventoryItem
		if err := json.Unmarshal(response.Body.Bytes(), &item); err != nil || item.SnapshotID == "" || item.SHA256 == "" {
			t.Fatalf("snapshot response = %+v, %v", item, err)
		}
		ids = append(ids, item.SnapshotID)
	}
	rateLimited := httptest.NewRequest(http.MethodPost, "/api/v1/system/backups/snapshot", nil)
	rateLimited.AddCookie(cookie)
	rateLimited.Header.Set("X-CSRF-Token", csrf)
	rateLimitedResponse := httptest.NewRecorder()
	server.ServeHTTP(rateLimitedResponse, rateLimited)
	if rateLimitedResponse.Code != http.StatusTooManyRequests || rateLimitedResponse.Header().Get("Retry-After") == "" {
		t.Fatalf("snapshot rate limit = %d %s", rateLimitedResponse.Code, rateLimitedResponse.Body.String())
	}
	var audits int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='DATABASE_MANUAL_SNAPSHOT_CREATED'").Scan(&audits); err != nil || audits != diagnosticBundleLimit {
		t.Fatalf("manual snapshot audit count = %d, %v", audits, err)
	}
	get = httptest.NewRequest(http.MethodGet, "/api/v1/system/backups", nil)
	get.AddCookie(cookie)
	getResponse = httptest.NewRecorder()
	server.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), ids[0]) || !strings.Contains(getResponse.Body.String(), `"verified_count":3`) {
		t.Fatalf("final backup inventory = %d %s", getResponse.Code, getResponse.Body.String())
	}
}

func TestPortableEncryptedBackupRequiresPassphraseCSRFStreamsAuditsAndCleansUp(t *testing.T) {
	server, ctx := testServer(t)
	content := []byte("encrypted-portable-backup-without-plaintext-secrets")
	digest := sha256.Sum256(content)
	portable := &fakePortableBackups{content: content, artifact: backup.PortableArtifact{
		Filename: "gateway-vpn-backup-20260824T190000Z-0123456789abcdef01234567.gvpn",
		Path:     "fake-managed-artifact", Bytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), SnapshotID: "snapshot-safe-id",
	}}
	server.dependencies.PortableBackups = portable
	cookie, csrf := login(t, server)

	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/system/backup", strings.NewReader(`{"passphrase":"correct horse battery staple","passphrase_confirmation":"correct horse battery staple"}`))
	withoutCSRF.AddCookie(cookie)
	withoutCSRFResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden || portable.builds != 0 {
		t.Fatalf("portable backup without CSRF = %d builds=%d", withoutCSRFResponse.Code, portable.builds)
	}
	mismatch := httptest.NewRequest(http.MethodPost, "/api/v1/system/backup", strings.NewReader(`{"passphrase":"correct horse battery staple","passphrase_confirmation":"different passphrase value"}`))
	mismatch.AddCookie(cookie)
	mismatch.Header.Set("X-CSRF-Token", csrf)
	mismatchResponse := httptest.NewRecorder()
	server.ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusBadRequest || portable.builds != 0 || strings.Contains(mismatchResponse.Body.String(), "correct horse") {
		t.Fatalf("mismatched passphrase = %d %s", mismatchResponse.Code, mismatchResponse.Body.String())
	}

	for index := 0; index < diagnosticBundleLimit; index++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/system/backup", strings.NewReader(`{"passphrase":"correct horse battery staple","passphrase_confirmation":"correct horse battery staple"}`))
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), content) || response.Header().Get("Content-Type") != "application/vnd.gateway-vpn.backup" || response.Header().Get("Content-Length") != strconv.Itoa(len(content)) || response.Header().Get("X-Content-SHA256") != portable.artifact.SHA256 || response.Header().Get("X-Backup-Snapshot") != portable.artifact.SnapshotID || !strings.Contains(response.Header().Get("Content-Disposition"), portable.artifact.Filename) {
			t.Fatalf("portable download %d = %d headers=%v body=%q", index, response.Code, response.Header(), response.Body.String())
		}
	}
	rateLimited := httptest.NewRequest(http.MethodPost, "/api/v1/system/backup", strings.NewReader(`{"passphrase":"correct horse battery staple","passphrase_confirmation":"correct horse battery staple"}`))
	rateLimited.AddCookie(cookie)
	rateLimited.Header.Set("X-CSRF-Token", csrf)
	rateLimitedResponse := httptest.NewRecorder()
	server.ServeHTTP(rateLimitedResponse, rateLimited)
	if rateLimitedResponse.Code != http.StatusTooManyRequests || portable.builds != diagnosticBundleLimit || portable.opens != diagnosticBundleLimit || portable.removes != diagnosticBundleLimit {
		t.Fatalf("portable rate/cleanup = %d builds=%d opens=%d removes=%d", rateLimitedResponse.Code, portable.builds, portable.opens, portable.removes)
	}
	var audits int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='PORTABLE_ENCRYPTED_BACKUP_CREATED'").Scan(&audits); err != nil || audits != diagnosticBundleLimit {
		t.Fatalf("portable backup audit count = %d, %v", audits, err)
	}
	var details string
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT details_json FROM events WHERE type='PORTABLE_ENCRYPTED_BACKUP_CREATED' ORDER BY id DESC LIMIT 1").Scan(&details); err != nil || !strings.Contains(details, portable.artifact.SHA256) || strings.Contains(details, "correct horse") || strings.Contains(details, "passphrase") {
		t.Fatalf("portable backup audit details = %q, %v", details, err)
	}
}

func TestRestoreUploadRequiresOrderedMultipartCSRFAndAuditsWithoutPassphrase(t *testing.T) {
	server, ctx := testServer(t)
	operation := backup.RestoreOperation{
		FormatVersion: backup.PortableFormatVersion,
		RestoreID:     "restore-0123456789abcdef0123456789abcdef", State: "STAGED",
		CreatedAt: "2026-08-24T19:00:00Z", SnapshotID: "snapshot-a", SchemaVersion: 10,
		GatewayVersion: "gateway-vpn test", PortableBytes: 16, PortableSHA256: strings.Repeat("a", 64), PayloadBytes: 32, Files: 3,
	}
	stager := &fakeRestoreStager{operation: operation}
	server.dependencies.Restores = stager
	cookie, csrf := login(t, server)

	body, contentType := restoreMultipart(t, []restoreMultipartPart{
		{name: "passphrase", content: []byte("correct horse battery staple")},
		{name: "backup", filename: "backup.gvpn", content: []byte("encrypted-backup")},
	})
	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore", bytes.NewReader(body))
	withoutCSRF.Header.Set("Content-Type", contentType)
	withoutCSRF.AddCookie(cookie)
	withoutCSRFResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden || stager.stages != 0 {
		t.Fatalf("restore without CSRF = %d stages=%d", withoutCSRFResponse.Code, stager.stages)
	}

	reversed, reversedType := restoreMultipart(t, []restoreMultipartPart{
		{name: "backup", filename: "backup.gvpn", content: []byte("encrypted-backup")},
		{name: "passphrase", content: []byte("correct horse battery staple")},
	})
	reversedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore", bytes.NewReader(reversed))
	reversedRequest.Header.Set("Content-Type", reversedType)
	reversedRequest.Header.Set("X-CSRF-Token", csrf)
	reversedRequest.AddCookie(cookie)
	reversedResponse := httptest.NewRecorder()
	server.ServeHTTP(reversedResponse, reversedRequest)
	if reversedResponse.Code != http.StatusBadRequest || stager.stages != 0 {
		t.Fatalf("reversed restore multipart = %d stages=%d", reversedResponse.Code, stager.stages)
	}

	oversizedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore", bytes.NewReader(body))
	oversizedRequest.Header.Set("Content-Type", contentType)
	oversizedRequest.Header.Set("X-CSRF-Token", csrf)
	oversizedRequest.AddCookie(cookie)
	oversizedRequest.ContentLength = backup.MaximumPortableBackupBytes + (1 << 20) + 1
	oversizedResponse := httptest.NewRecorder()
	server.ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge || stager.stages != 0 {
		t.Fatalf("oversized restore = %d stages=%d", oversizedResponse.Code, stager.stages)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore", bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || stager.stages != 1 || stager.passphrase != "correct horse battery staple" || string(stager.content) != "encrypted-backup" {
		t.Fatalf("restore staging = %d stages=%d passphrase=%q content=%q body=%s", response.Code, stager.stages, stager.passphrase, stager.content, response.Body.String())
	}
	var details string
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT details_json FROM events WHERE type='RESTORE_STAGED' ORDER BY id DESC LIMIT 1").Scan(&details); err != nil || !strings.Contains(details, operation.RestoreID) || strings.Contains(details, "correct horse") || strings.Contains(details, "passphrase") {
		t.Fatalf("restore staged audit = %q, %v", details, err)
	}

	stager.stageErr = backup.ErrRestorePending
	duplicateRequest := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore", bytes.NewReader(body))
	duplicateRequest.Header.Set("Content-Type", contentType)
	duplicateRequest.Header.Set("X-CSRF-Token", csrf)
	duplicateRequest.AddCookie(cookie)
	duplicateResponse := httptest.NewRecorder()
	server.ServeHTTP(duplicateResponse, duplicateRequest)
	if duplicateResponse.Code != http.StatusConflict || !strings.Contains(duplicateResponse.Body.String(), "RESTORE_ALREADY_PENDING") {
		t.Fatalf("duplicate pending restore = %d %s", duplicateResponse.Code, duplicateResponse.Body.String())
	}
}

func TestRestoreTrailingMultipartIsCompensatedBeforeAudit(t *testing.T) {
	server, ctx := testServer(t)
	operation := backup.RestoreOperation{FormatVersion: 1, RestoreID: "restore-abcdefabcdefabcdefabcdefabcdefab", State: "STAGED", PortableSHA256: strings.Repeat("b", 64)}
	stager := &fakeRestoreStager{operation: operation}
	server.dependencies.Restores = stager
	cookie, csrf := login(t, server)
	body, contentType := restoreMultipart(t, []restoreMultipartPart{
		{name: "passphrase", content: []byte("correct horse battery staple")},
		{name: "backup", filename: "backup.gvpn", content: []byte("encrypted-backup")},
		{name: "unexpected", content: []byte("must-not-be-accepted")},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore", bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	var audits int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='RESTORE_STAGED'").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest || stager.discards != 1 || stager.pending || audits != 0 {
		t.Fatalf("trailing restore multipart = %d discards=%d pending=%t audits=%d %s", response.Code, stager.discards, stager.pending, audits, response.Body.String())
	}
}

func TestRestoreStatusAndApplyAreFailClosedBeforePrivilegedTrigger(t *testing.T) {
	server, ctx := testServer(t)
	operation := backup.RestoreOperation{FormatVersion: 1, RestoreID: "restore-11111111111111111111111111111111", State: "STAGED", SnapshotID: "snapshot-a", PortableSHA256: strings.Repeat("c", 64)}
	stager := &fakeRestoreStager{operation: operation, pending: true}
	runtime := &fakeModemRuntime{}
	sequence := []string{}
	runtime.onBlock = func() { sequence = append(sequence, "firewall-block") }
	stager.onAuthorize = func() {
		var audit int
		if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='RESTORE_APPLY_REQUESTED'").Scan(&audit); err != nil || audit != 1 {
			t.Errorf("restore apply audit was not committed before authorization: count=%d error=%v", audit, err)
		}
		sequence = append(sequence, "apply-authorized")
	}
	trigger := &fakeRestoreApplyTrigger{onApply: func() error {
		current, err := server.dependencies.State.Get(ctx)
		if err != nil {
			return err
		}
		if current.GatewayState != state.GatewayBlocked || current.PathState != state.PathBlocked {
			return errors.New("runtime was not durably blocked before restore trigger")
		}
		if stager.operation.State != backup.RestoreStateApplyRequested {
			return errors.New("restore apply was not durably authorized before trigger")
		}
		var audit int
		if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='RESTORE_APPLY_REQUESTED'").Scan(&audit); err != nil || audit != 1 {
			return errors.New("restore apply audit was not committed before trigger")
		}
		sequence = append(sequence, "privileged-trigger")
		return nil
	}}
	server.dependencies.Restores = stager
	server.dependencies.ModemRuntime = runtime
	server.dependencies.RestoreApply = trigger
	cookie, csrf := login(t, server)

	statusRequest := httptest.NewRequest(http.MethodGet, "/api/v1/system/restore", nil)
	statusRequest.AddCookie(cookie)
	statusResponse := httptest.NewRecorder()
	server.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"pending":true`) || !strings.Contains(statusResponse.Body.String(), `"apply_available":true`) || !strings.Contains(statusResponse.Body.String(), operation.RestoreID) {
		t.Fatalf("restore status = %d %s", statusResponse.Code, statusResponse.Body.String())
	}

	withoutConfirmation := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore/apply", strings.NewReader(`{"restore_id":"`+operation.RestoreID+`"}`))
	withoutConfirmation.Header.Set("Content-Type", "application/json")
	withoutConfirmation.Header.Set("X-CSRF-Token", csrf)
	withoutConfirmation.AddCookie(cookie)
	withoutConfirmationResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutConfirmationResponse, withoutConfirmation)
	if withoutConfirmationResponse.Code != http.StatusConflict || runtime.blocks != 0 || stager.authorizations != 0 || trigger.calls != 0 {
		t.Fatalf("restore apply without confirmation = %d blocks=%d authorizations=%d triggers=%d", withoutConfirmationResponse.Code, runtime.blocks, stager.authorizations, trigger.calls)
	}

	applyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore/apply", strings.NewReader(`{"restore_id":"`+operation.RestoreID+`"}`))
	applyRequest.Header.Set("Content-Type", "application/json")
	applyRequest.Header.Set("X-CSRF-Token", csrf)
	applyRequest.Header.Set("X-Confirm-Destructive", "apply-verified-restore")
	applyRequest.AddCookie(cookie)
	applyResponse := httptest.NewRecorder()
	server.ServeHTTP(applyResponse, applyRequest)
	if applyResponse.Code != http.StatusAccepted || runtime.blocks != 1 || stager.authorizations != 1 || trigger.calls != 1 || strings.Join(sequence, ",") != "firewall-block,apply-authorized,privileged-trigger" || !strings.Contains(applyResponse.Body.String(), `"management_reconnect_required":true`) {
		t.Fatalf("restore apply = %d blocks=%d authorizations=%d triggers=%d sequence=%v %s", applyResponse.Code, runtime.blocks, stager.authorizations, trigger.calls, sequence, applyResponse.Body.String())
	}
	authorizedStatus := httptest.NewRequest(http.MethodGet, "/api/v1/system/restore", nil)
	authorizedStatus.AddCookie(cookie)
	authorizedResponse := httptest.NewRecorder()
	server.ServeHTTP(authorizedResponse, authorizedStatus)
	if authorizedResponse.Code != http.StatusOK || !strings.Contains(authorizedResponse.Body.String(), `"state":"APPLY_REQUESTED"`) || strings.Contains(authorizedResponse.Body.String(), "apply_authorization") || strings.Contains(authorizedResponse.Body.String(), strings.Repeat("a", 64)) {
		t.Fatalf("authorized restore status leaked root nonce = %d %s", authorizedResponse.Code, authorizedResponse.Body.String())
	}
}

func TestRestoreDiscardRequiresExactConfirmationAndAudits(t *testing.T) {
	server, ctx := testServer(t)
	operation := backup.RestoreOperation{FormatVersion: 1, RestoreID: "restore-22222222222222222222222222222222", State: "STAGED", SnapshotID: "snapshot-b", PortableSHA256: strings.Repeat("d", 64)}
	stager := &fakeRestoreStager{operation: operation, pending: true}
	server.dependencies.Restores = stager
	cookie, csrf := login(t, server)
	call := func(confirmation, restoreID string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodDelete, "/api/v1/system/restore", strings.NewReader(`{"restore_id":"`+restoreID+`"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		if confirmation != "" {
			request.Header.Set("X-Confirm-Destructive", confirmation)
		}
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}
	if response := call("", operation.RestoreID); response.Code != http.StatusConflict || stager.discards != 0 {
		t.Fatalf("restore discard without confirmation = %d discards=%d", response.Code, stager.discards)
	}
	if response := call("discard-staged-restore", "restore-33333333333333333333333333333333"); response.Code != http.StatusConflict || stager.discards != 0 {
		t.Fatalf("restore discard wrong id = %d discards=%d", response.Code, stager.discards)
	}
	if response := call("discard-staged-restore", operation.RestoreID); response.Code != http.StatusNoContent || stager.discards != 1 || stager.pending {
		t.Fatalf("restore discard = %d discards=%d pending=%t %s", response.Code, stager.discards, stager.pending, response.Body.String())
	}
	var details string
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT details_json FROM events WHERE type='RESTORE_DISCARDED'").Scan(&details); err != nil || !strings.Contains(details, operation.RestoreID) || strings.Contains(details, "passphrase") {
		t.Fatalf("restore discard audit = %q, %v", details, err)
	}
}

func TestRestoreApplyTriggerFailureLeavesRuntimeDurablyBlocked(t *testing.T) {
	server, ctx := testServer(t)
	operation := backup.RestoreOperation{FormatVersion: 1, RestoreID: "restore-44444444444444444444444444444444", State: "STAGED", SnapshotID: "snapshot-c", PortableSHA256: strings.Repeat("e", 64)}
	stager := &fakeRestoreStager{operation: operation, pending: true}
	runtime := &fakeModemRuntime{}
	trigger := &fakeRestoreApplyTrigger{err: errors.New("private systemd failure detail")}
	server.dependencies.Restores = stager
	server.dependencies.ModemRuntime = runtime
	server.dependencies.RestoreApply = trigger
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore/apply", strings.NewReader(`{"restore_id":"`+operation.RestoreID+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Confirm-Destructive", "apply-verified-restore")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	current, err := server.dependencies.State.Get(ctx)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "systemd failure") || runtime.blocks != 1 || stager.authorizations != 1 || stager.operation.State != backup.RestoreStateApplyRequested || trigger.calls != 1 || err != nil || current.GatewayState != state.GatewayBlocked || current.PathState != state.PathBlocked {
		t.Fatalf("failed restore trigger = %d blocks=%d authorizations=%d restore_state=%s triggers=%d state=%+v error=%v %s", response.Code, runtime.blocks, stager.authorizations, stager.operation.State, trigger.calls, current, err, response.Body.String())
	}
}

func TestRestoreAuthorizationFailureNeverStartsPrivilegedApply(t *testing.T) {
	server, ctx := testServer(t)
	operation := backup.RestoreOperation{FormatVersion: 1, RestoreID: "restore-55555555555555555555555555555555", State: backup.RestoreStateStaged, SnapshotID: "snapshot-d", PortableSHA256: strings.Repeat("f", 64)}
	stager := &fakeRestoreStager{operation: operation, pending: true, authorizeErr: errors.New("injected durable write failure")}
	runtime := &fakeModemRuntime{}
	trigger := &fakeRestoreApplyTrigger{}
	server.dependencies.Restores = stager
	server.dependencies.ModemRuntime = runtime
	server.dependencies.RestoreApply = trigger
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/system/restore/apply", strings.NewReader(`{"restore_id":"`+operation.RestoreID+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.Header.Set("X-Confirm-Destructive", "apply-verified-restore")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	current, err := server.dependencies.State.Get(ctx)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "RESTORE_APPLY_AUTHORIZATION_FAILED") || strings.Contains(response.Body.String(), "durable write") || runtime.blocks != 1 || stager.authorizations != 1 || trigger.calls != 0 || err != nil || current.PathState != state.PathBlocked {
		t.Fatalf("failed restore authorization = %d blocks=%d authorizations=%d triggers=%d state=%+v error=%v %s", response.Code, runtime.blocks, stager.authorizations, trigger.calls, current, err, response.Body.String())
	}
}

func TestSignedUpdateUploadApplyAndDiscardAreExactAuditedAndFailClosed(t *testing.T) {
	server, ctx := testServer(t)
	operation := updatepkg.Operation{
		FormatVersion: 1, UpdateID: "update-20260824T230000Z-0123456789abcdef01234567", State: "STAGED",
		CreatedAt: "2026-08-24T23:00:00Z", GatewayVersion: "1.2.0", MihomoVersion: "v1.19.10",
		SignerKeySHA256: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), UncompressedBytes: 4096, FileCount: 7,
	}
	stager := &fakeUpdateStager{operation: operation}
	server.dependencies.Updates = stager
	cookie, csrf := login(t, server)
	body, contentType := restoreMultipart(t, []restoreMultipartPart{{name: "release", filename: "gateway-vpn-1.2.0-linux-amd64.tar.gz", content: []byte("signed archive")}})
	upload := httptest.NewRequest(http.MethodPost, "/api/v1/system/update", bytes.NewReader(body))
	upload.Header.Set("Content-Type", contentType)
	upload.Header.Set("X-CSRF-Token", csrf)
	upload.AddCookie(cookie)
	uploadResponse := httptest.NewRecorder()
	server.ServeHTTP(uploadResponse, upload)
	if uploadResponse.Code != http.StatusCreated || stager.stages != 1 || string(stager.content) != "signed archive" || !strings.Contains(uploadResponse.Body.String(), operation.SignerKeySHA256) {
		t.Fatalf("stage signed update = %d stages=%d content=%q %s", uploadResponse.Code, stager.stages, stager.content, uploadResponse.Body.String())
	}
	var stagedAudit int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SIGNED_UPDATE_STAGED'").Scan(&stagedAudit); err != nil || stagedAudit != 1 {
		t.Fatalf("signed update staged audit = %d,%v", stagedAudit, err)
	}

	runtime := &fakeModemRuntime{}
	sequence := []string{}
	runtime.onBlock = func() { sequence = append(sequence, "firewall-block") }
	trigger := &fakeUpdateApplyTrigger{status: networkapply.UpdateTransactionStatus{
		Exists: true, UpdateID: "update-20260823T230000Z-fedcba9876543210fedcba98", State: "ROLLED_BACK",
		StartedAt: "2026-08-23T23:00:00Z", UpdatedAt: "2026-08-24T00:00:00Z",
		OldVersion: "1.0.0", NewVersion: "1.1.0", ErrorCode: "NEW_RELEASE_HEALTH_FAILED",
	}, onApply: func() error {
		current, err := server.dependencies.State.Get(ctx)
		if err != nil || current.GatewayState != state.GatewayBlocked || current.PathState != state.PathBlocked {
			return errors.New("runtime was not durably blocked before update trigger")
		}
		var audit int
		if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SIGNED_UPDATE_APPLY_REQUESTED'").Scan(&audit); err != nil || audit != 1 {
			return errors.New("update audit was not committed before root trigger")
		}
		sequence = append(sequence, "privileged-trigger")
		return nil
	}}
	server.dependencies.ModemRuntime = runtime
	server.dependencies.UpdateApply = trigger
	statusRequest := httptest.NewRequest(http.MethodGet, "/api/v1/system/update", nil)
	statusRequest.AddCookie(cookie)
	statusResponse := httptest.NewRecorder()
	server.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"transaction_query_state":"AVAILABLE"`) || !strings.Contains(statusResponse.Body.String(), `"state":"ROLLED_BACK"`) || !strings.Contains(statusResponse.Body.String(), `"error_code":"NEW_RELEASE_HEALTH_FAILED"`) || strings.Contains(statusResponse.Body.String(), "snapshot") || strings.Contains(statusResponse.Body.String(), "path") {
		t.Fatalf("signed update combined status = %d %s", statusResponse.Code, statusResponse.Body.String())
	}
	withoutConfirm := httptest.NewRequest(http.MethodPost, "/api/v1/system/update/apply", strings.NewReader(`{"update_id":"`+operation.UpdateID+`"}`))
	withoutConfirm.Header.Set("Content-Type", "application/json")
	withoutConfirm.Header.Set("X-CSRF-Token", csrf)
	withoutConfirm.AddCookie(cookie)
	withoutConfirmResponse := httptest.NewRecorder()
	server.ServeHTTP(withoutConfirmResponse, withoutConfirm)
	if withoutConfirmResponse.Code != http.StatusConflict || runtime.blocks != 0 || trigger.calls != 0 {
		t.Fatalf("update without confirmation = %d blocks=%d triggers=%d", withoutConfirmResponse.Code, runtime.blocks, trigger.calls)
	}
	apply := httptest.NewRequest(http.MethodPost, "/api/v1/system/update/apply", strings.NewReader(`{"update_id":"`+operation.UpdateID+`"}`))
	apply.Header.Set("Content-Type", "application/json")
	apply.Header.Set("X-CSRF-Token", csrf)
	apply.Header.Set("X-Confirm-Destructive", "apply-verified-update")
	apply.AddCookie(cookie)
	applyResponse := httptest.NewRecorder()
	server.ServeHTTP(applyResponse, apply)
	if applyResponse.Code != http.StatusAccepted || runtime.blocks != 1 || trigger.calls != 1 || strings.Join(sequence, ",") != "firewall-block,privileged-trigger" {
		t.Fatalf("signed update apply = %d blocks=%d triggers=%d sequence=%v %s", applyResponse.Code, runtime.blocks, trigger.calls, sequence, applyResponse.Body.String())
	}

	stager.pending = true
	discard := httptest.NewRequest(http.MethodDelete, "/api/v1/system/update", strings.NewReader(`{"update_id":"`+operation.UpdateID+`"}`))
	discard.Header.Set("Content-Type", "application/json")
	discard.Header.Set("X-CSRF-Token", csrf)
	discard.Header.Set("X-Confirm-Destructive", "discard-staged-update")
	discard.AddCookie(cookie)
	discardResponse := httptest.NewRecorder()
	server.ServeHTTP(discardResponse, discard)
	if discardResponse.Code != http.StatusNoContent || stager.discards != 1 || stager.pending {
		t.Fatalf("signed update discard = %d discards=%d pending=%t", discardResponse.Code, stager.discards, stager.pending)
	}
}

func TestDiagnosticBundleAPIRedactsBuilderFailure(t *testing.T) {
	server, _ := testServer(t)
	server.dependencies.Diagnostics = &fakeDiagnosticBundler{err: errors.New("private path /root/secret and token=diagnostic-secret")}
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/system/diagnostics", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "/root/secret") || strings.Contains(response.Body.String(), "diagnostic-secret") {
		t.Fatalf("diagnostic builder failure = %d %s", response.Code, response.Body.String())
	}
}

func TestTargetCRUDPolicyConfirmationReorderAndProbeTriggerRequalification(t *testing.T) {
	server, ctx := testServer(t)
	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE modems SET state=? WHERE id='modem-a'", modem.StateReady); err != nil {
		t.Fatal(err)
	}
	pathProber := &fakeModemPathProber{}
	server.dependencies.ModemPathProbe = pathProber
	cookie, csrf := login(t, server)
	call := func(method, path, body, confirmation string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		if confirmation != "" {
			request.Header.Set("X-Confirm-Destructive", confirmation)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}
	create := `{"name":"Access marker","kind":"url","value":"https://example.com/check","required":true,"timeout_seconds":8,"success_mode":"expected_body","expected_status":"302,200-299","expected_body_substring":"access granted"}`
	response := call(http.MethodPost, "/api/v1/bypass-targets", create, "")
	if response.Code != http.StatusCreated || pathProber.calls != 1 || !strings.Contains(response.Body.String(), `"ExpectedStatus":"200-299/302"`) {
		t.Fatalf("create target = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	var targetID string
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT id FROM bypass_probe_targets").Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	disable := `{"name":"Access marker","kind":"url","value":"https://example.com/check","enabled":false,"required":true,"timeout_seconds":8,"success_mode":"expected_body","expected_status":"200-299/302","expected_body_substring":"access granted"}`
	response = call(http.MethodPatch, "/api/v1/bypass-targets/"+targetID, disable, "")
	if response.Code != http.StatusConflict || pathProber.calls != 1 || !strings.Contains(response.Body.String(), "CONFIRM_LAST_REQUIRED_TARGET") {
		t.Fatalf("disable last required without confirmation = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	response = call(http.MethodPatch, "/api/v1/bypass-targets/"+targetID, disable, "remove-last-required-target")
	if response.Code != http.StatusAccepted || pathProber.calls != 2 {
		t.Fatalf("disable last required with confirmation = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	enable := strings.Replace(disable, `"enabled":false`, `"enabled":true`, 1)
	response = call(http.MethodPatch, "/api/v1/bypass-targets/"+targetID, enable, "")
	if response.Code != http.StatusAccepted || pathProber.calls != 3 {
		t.Fatalf("enable target = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	response = call(http.MethodPut, "/api/v1/bypass-targets/priorities", `{"ids":["`+targetID+`"]}`, "")
	if response.Code != http.StatusAccepted || pathProber.calls != 4 {
		t.Fatalf("reorder target = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	response = call(http.MethodPost, "/api/v1/bypass-targets/"+targetID+"/probe", `{}`, "")
	if response.Code != http.StatusAccepted || pathProber.calls != 5 || !strings.Contains(response.Body.String(), `"scope":"ALL_ELIGIBLE_PATHS"`) {
		t.Fatalf("probe target = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	response = call(http.MethodDelete, "/api/v1/bypass-targets/"+targetID, `{}`, "")
	if response.Code != http.StatusConflict || pathProber.calls != 5 {
		t.Fatalf("delete last required without confirmation = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	response = call(http.MethodDelete, "/api/v1/bypass-targets/"+targetID, `{}`, "remove-last-required-target")
	if response.Code != http.StatusAccepted || pathProber.calls != 6 {
		t.Fatalf("delete last required with confirmation = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
}

func TestSessionRotationMatrixReadModelAndStaticSecurityHeaders(t *testing.T) {
	server, _ := testServer(t)
	cookie, _ := login(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "csrf_token") {
		t.Fatalf("session response = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/paths/matrix", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "reason_code") {
		t.Fatalf("matrix response = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/gateway/status", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "gateway_state") || strings.Contains(response.Body.String(), "GatewayState") {
		t.Fatalf("gateway status DTO = %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Security-Policy") == "" || !strings.Contains(response.Body.String(), "Gateway VPN") {
		t.Fatalf("static response = %d CSP=%q", response.Code, response.Header().Get("Content-Security-Policy"))
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/styles.css", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "[hidden]{display:none!important}") {
		t.Fatalf("static stylesheet does not preserve hidden layout semantics: %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	for _, required := range []string{"stagePortableRestore", "discard-staged-restore", "apply-verified-restore", "ВОССТАНОВИТЬ", "gateway-vpn-restore-reconnect"} {
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), required) {
			t.Fatalf("static restore UI missing %q: %d", required, response.Code)
		}
	}
	for _, required := range []string{"showMandatoryPasswordChange", "/api/v1/auth/password", "/api/v1/auth/users", "/api/v1/auth/sessions", "delete-disabled-user", "Пользователи и активные сессии"} {
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), required) {
			t.Fatalf("static auth management UI missing %q: %d", required, response.Code)
		}
	}
}

func TestSafeNetworkApplyReturnsTokenBeforeAsyncApplyAndUsesSocketDestination(t *testing.T) {
	server, ctx := testServer(t)
	backupManager := attachBackupManager(t, server)
	broker := &fakeNetworkBroker{applied: make(chan string, 1), prepared: networkapply.Prepared{
		ApplyID: "apply-0123456789abcdef", ConfirmToken: strings.Repeat("a", 64),
		OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.210.1:8443",
		RollbackDeadline: time.Now().Add(time.Minute),
	}}
	server.dependencies.NetworkBroker = broker
	server.dependencies.NetworkCandidate = func(_ context.Context, value string) (networkapply.Candidate, error) {
		if value != "192.168.210.1/24" {
			t.Fatalf("candidate LAN = %q", value)
		}
		return networkapply.Candidate{InterfaceName: "enp2s0", OldLANCIDR: "192.168.200.1/24", NewLANCIDR: value, OldURL: broker.prepared.OldURL, NewURL: broker.prepared.NewURL}, nil
	}
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/settings/network/apply", strings.NewReader(`{"lan_address":"192.168.210.1/24"}`))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), broker.prepared.ConfirmToken) {
		t.Fatalf("network stage response = %d %s", response.Code, response.Body.String())
	}
	items, err := backupManager.Inventory(ctx)
	if err != nil || len(items) != 1 || items[0].Kind != backup.KindPreNetworkApply || !items[0].Verified {
		t.Fatalf("pre-network-apply snapshot = %+v, %v", items, err)
	}
	var backupAudit int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='DATABASE_PRE_NETWORK_APPLY_SNAPSHOT_CREATED'").Scan(&backupAudit); err != nil || backupAudit != 1 {
		t.Fatalf("pre-network-apply audit = %d, %v", backupAudit, err)
	}
	select {
	case id := <-broker.applied:
		if id != broker.prepared.ApplyID {
			t.Fatalf("async apply id = %s", id)
		}
	case <-time.After(time.Second):
		t.Fatal("async apply did not start after response")
	}

	confirmBody := `{"confirm_token":"` + broker.prepared.ConfirmToken + `"}`
	request = httptest.NewRequest(http.MethodPost, "/api/v1/settings/network/apply/"+broker.prepared.ApplyID+"/confirm", strings.NewReader(confirmBody))
	request.Host = "192.168.210.1:8443" // Host is intentionally not trusted.
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("confirm without LocalAddr status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/settings/network/apply/"+broker.prepared.ApplyID+"/confirm", strings.NewReader(confirmBody))
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.168.210.1"), Port: 8443}))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || broker.confirmed.LocalDestinationIP != "192.168.210.1" || broker.confirmed.ViaWireGuard {
		t.Fatalf("new-destination confirm = %d %+v", response.Code, broker.confirmed)
	}
}

func TestManualSubscriptionRefreshRequiresCSRFAndUsesProductionContract(t *testing.T) {
	server, _ := testServer(t)
	refresher := &fakeSubscriptionRefresher{result: subscription.RefreshResult{SubscriptionID: "sub-a", VersionID: "version-2"}}
	server.dependencies.SubscriptionRefresh = refresher
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/subscriptions/sub-a/refresh", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("refresh without CSRF status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/subscriptions/sub-a/refresh", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "version-2") || len(refresher.ids) != 1 || refresher.ids[0] != "sub-a" {
		t.Fatalf("manual refresh response/calls = %d %s / %v", response.Code, response.Body.String(), refresher.ids)
	}
	refresher.err = subscription.ErrRefreshInProgress
	request = httptest.NewRequest(http.MethodPost, "/api/v1/subscriptions/sub-a/refresh", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "REFRESH_IN_PROGRESS") {
		t.Fatalf("duplicate refresh response = %d %s", response.Code, response.Body.String())
	}
}

func TestSubscriptionCRUDProtectsSecretsAndActivePath(t *testing.T) {
	server, ctx := testServer(t)
	root := t.TempDir()
	secretRoot := filepath.Join(root, "secrets")
	payloadRoot := filepath.Join(root, "payloads")
	if err := os.MkdirAll(secretRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(payloadRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	refresher := &fakeSubscriptionRefresher{result: subscription.RefreshResult{VersionID: "version-new"}}
	runtime := &fakeModemRuntime{}
	server.dependencies.SubscriptionSecretRoot = secretRoot
	server.dependencies.SubscriptionPayloadRoot = payloadRoot
	server.dependencies.SubscriptionRefresh = refresher
	server.dependencies.ModemRuntime = runtime
	cookie, csrf := login(t, server)
	call := func(method, path, body, confirmation string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		if confirmation != "" {
			request.Header.Set("X-Confirm-Destructive", confirmation)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}

	const sourceURL = "https://subscriptions.example.net/account/token"
	response := call(http.MethodPost, "/api/v1/subscriptions", `{"name":"Operator A","source_url":"`+sourceURL+`","auto_refresh":true,"refresh_interval_seconds":3600,"fallback_when_named_candidates_fail":false}`, "")
	if response.Code != http.StatusCreated || strings.Contains(response.Body.String(), sourceURL) {
		t.Fatalf("create subscription = %d %s", response.Code, response.Body.String())
	}
	var created struct {
		ID     string `json:"id"`
		Number int64  `json:"number"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ID == "" || created.Number != 2 {
		t.Fatalf("created subscription = %+v, %v", created, err)
	}
	if len(refresher.refreshIDs) != 1 || refresher.refreshIDs[0] != created.ID {
		t.Fatalf("create refresh calls = %v", refresher.refreshIDs)
	}
	item, err := server.dependencies.Subscriptions.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	secretContent, err := os.ReadFile(item.SourceSecretRef)
	if err != nil || strings.TrimSpace(string(secretContent)) != sourceURL {
		t.Fatalf("stored source secret = %q, %v", secretContent, err)
	}
	info, err := os.Stat(item.SourceSecretRef)
	if err != nil {
		t.Fatalf("stat source secret: %v", err)
	}
	if runtimepkg.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("source secret mode = %v, want 0600", info.Mode().Perm())
	}
	response = call(http.MethodGet, "/api/v1/subscriptions", "", "")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), sourceURL) || strings.Contains(response.Body.String(), item.SourceSecretRef) {
		t.Fatalf("subscription list leaked source = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodPatch, "/api/v1/subscriptions/"+created.ID, `{"name":"Invalid update","source_url":"https://subscriptions.example.net/replacement","auto_refresh":true,"refresh_interval_seconds":0,"fallback_when_named_candidates_fail":false}`, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid update = %d %s", response.Code, response.Body.String())
	}
	secretContent, err = os.ReadFile(item.SourceSecretRef)
	if err != nil || strings.TrimSpace(string(secretContent)) != sourceURL {
		t.Fatalf("invalid update changed source secret = %q, %v", secretContent, err)
	}

	response = call(http.MethodPatch, "/api/v1/subscriptions/"+created.ID, `{"name":"Operator A whitelist","source_url":"","auto_refresh":false,"refresh_interval_seconds":7200,"fallback_when_named_candidates_fail":true}`, "")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"refresh":"RECLASSIFIED"`) {
		t.Fatalf("update subscription = %d %s", response.Code, response.Body.String())
	}
	if len(refresher.reclassifyIDs) != 1 || refresher.reclassifyIDs[0] != created.ID {
		t.Fatalf("reclassification calls = %v", refresher.reclassifyIDs)
	}
	item, err = server.dependencies.Subscriptions.Get(ctx, created.ID)
	if err != nil || item.Name != "Operator A whitelist" || item.AutoRefresh || item.RefreshIntervalSeconds != 7200 || !item.FallbackWhenNamedCandidatesFail {
		t.Fatalf("updated subscription = %+v, %v", item, err)
	}

	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE runtime_state SET gateway_state='ACTIVE', path_state='PATH_ACTIVE', active_subscription_id=?, active_modem_id='modem-a' WHERE singleton_id=1", created.ID); err != nil {
		t.Fatal(err)
	}
	blockedBeforeMutation := false
	runtime.onBlock = func() {
		current, getErr := server.dependencies.Subscriptions.Get(ctx, created.ID)
		blockedBeforeMutation = getErr == nil && current.Enabled
	}
	response = call(http.MethodPost, "/api/v1/subscriptions/"+created.ID+"/disable", `{}`, "")
	if response.Code != http.StatusAccepted || runtime.blocks != 1 || !blockedBeforeMutation {
		t.Fatalf("disable active subscription = %d blocks=%d blocked-before-mutation=%t %s", response.Code, runtime.blocks, blockedBeforeMutation, response.Body.String())
	}
	snapshot, err := server.dependencies.State.Get(ctx)
	if err != nil || snapshot.ActiveSubscriptionID != "" || snapshot.ActiveModemID != "" || snapshot.ActivePathID != "" || snapshot.ActiveNodeID != "" || snapshot.PathState != state.PathBlocked {
		t.Fatalf("blocked active tuple = %+v, %v", snapshot, err)
	}

	payloadDirectory := filepath.Join(payloadRoot, created.ID)
	if err := os.MkdirAll(payloadDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloadDirectory, "candidate.yaml"), []byte("proxies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	response = call(http.MethodDelete, "/api/v1/subscriptions/"+created.ID, `{}`, "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "CONFIRM_DELETE_SUBSCRIPTION") {
		t.Fatalf("delete without confirmation = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodDelete, "/api/v1/subscriptions/"+created.ID, `{}`, "delete-disabled-subscription")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"cleanup":"COMPLETE"`) {
		t.Fatalf("confirmed delete = %d %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(item.SourceSecretRef); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source secret remains after delete: %v", err)
	}
	if _, err := os.Stat(payloadDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("payload directory remains after delete: %v", err)
	}
	if _, err := server.dependencies.Subscriptions.Get(ctx, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted subscription remains: %v", err)
	}
}

func TestMatcherPreviewAndNodeOverrideAPIUseActiveInventory(t *testing.T) {
	server, ctx := testServer(t)
	versions := subscription.NewVersionRepository(server.dependencies.Database)
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-nodes", SubscriptionID: "sub-a", Payload: []byte(
		"vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-route\n" +
			"vless://22222222-2222-2222-2222-222222222222@two.example:443#ordinary\n"), Matchers: subscription.DefaultMatchers()})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY' WHERE id='modem-a'"); err != nil {
		t.Fatal(err)
	}
	if err := server.dependencies.Paths.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	pathProber := &fakeModemPathProber{}
	server.dependencies.ModemPathProbe = pathProber
	cookie, csrf := login(t, server)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}

	response := call(http.MethodGet, "/api/v1/nodes?subscription_id=sub-a", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "LTE-route") || !strings.Contains(response.Body.String(), "NAME_FILTERED") || strings.Contains(response.Body.String(), "Fingerprint") || strings.Contains(response.Body.String(), "11111111-1111") {
		t.Fatalf("node inventory = %d %s", response.Code, response.Body.String())
	}
	var inventory struct {
		Items []struct {
			ID           string `json:"id"`
			ExternalName string `json:"external_name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &inventory); err != nil || len(inventory.Items) != 2 {
		t.Fatalf("decode node inventory = %+v, %v", inventory, err)
	}

	response = call(http.MethodPost, "/api/v1/node-matchers", `{"pattern":"^ordinary$","type":"regex"}`)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "MATCHER_PREVIEW_REQUIRED") {
		t.Fatalf("regex without preview = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodPost, "/api/v1/node-matchers/preview", `{"pattern":"^ordinary$","type":"regex"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"candidates"`) || !strings.Contains(response.Body.String(), `"filtered"`) {
		t.Fatalf("matcher preview = %d %s", response.Code, response.Body.String())
	}
	var preview struct {
		Token string `json:"preview_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &preview); err != nil || preview.Token == "" {
		t.Fatalf("decode matcher preview = %+v, %v", preview, err)
	}
	createBody, _ := json.Marshal(map[string]any{"pattern": "^ordinary$", "type": "regex", "preview_token": preview.Token})
	response = call(http.MethodPost, "/api/v1/node-matchers", string(createBody))
	if response.Code != http.StatusCreated || pathProber.calls != 1 {
		t.Fatalf("create previewed matcher = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}

	response = call(http.MethodPatch, "/api/v1/nodes/"+inventory.Items[0].ID, `{"selection_override":"exclude"}`)
	if response.Code != http.StatusAccepted || pathProber.calls != 2 {
		t.Fatalf("node override = %d probes=%d %s", response.Code, pathProber.calls, response.Body.String())
	}
	response = call(http.MethodGet, "/api/v1/nodes?subscription_id=sub-a", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"selection_override":"exclude"`) || !strings.Contains(response.Body.String(), `"candidate_source":"MANUAL_EXCLUDE"`) {
		t.Fatalf("node inventory after override = %d %s", response.Code, response.Body.String())
	}
}

func TestDiscoveredModemAdoptionIsCSRFProtectedAndRedactsIdentity(t *testing.T) {
	server, ctx := testServer(t)
	registry := hilink.NewDiscoveryRegistry(server.dependencies.Modems)
	identity := strings.Repeat("b", 64)
	registry.Replace([]hilink.Match{{State: hilink.DiscoveryUnadopted, Candidate: hilink.Candidate{DiscoveryID: "discovery-b", InterfaceName: "enx2", VendorID: "12d1", ProductID: "14db", IdentityKind: "usb_serial_hash", IdentityHash: identity, MaskedSerial: "****4321", Carrier: true}}})
	server.dependencies.Discoveries = registry
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/modems/discovered", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "discovery-b") || strings.Contains(response.Body.String(), identity) {
		t.Fatalf("discovered response = %d %s", response.Code, response.Body.String())
	}
	body := `{"name":"Backup LTE","operator_label":"Operator B"}`
	request = httptest.NewRequest(http.MethodPost, "/api/v1/modems/discovery-b/adopt", strings.NewReader(body))
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("adopt without CSRF status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/modems/discovery-b/adopt", strings.NewReader(body))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), "Backup LTE") {
		t.Fatalf("adopt response = %d %s", response.Code, response.Body.String())
	}
	var modemCount, pathCount int
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM modems").Scan(&modemCount); err != nil {
		t.Fatal(err)
	}
	if err := server.dependencies.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscription_modem_paths").Scan(&pathCount); err != nil {
		t.Fatal(err)
	}
	if modemCount != 2 || pathCount != 2 || len(registry.List()) != 0 {
		t.Fatalf("adoption counts/registry = %d/%d/%+v", modemCount, pathCount, registry.List())
	}
}

func TestWireGuardStatusReportsRuntimeWithoutSecrets(t *testing.T) {
	server, ctx := testServer(t)
	if err := server.dependencies.WireGuardRuntime.Put(ctx, wireguardpkg.RuntimeState{
		CurrentModemID: "modem-a", RouteModemID: "modem-a", EndpointIP: "203.0.113.10",
		LastHandshakeAt: "2026-08-24T12:00:00Z", ConfigSHA256: strings.Repeat("f", 64),
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cookie, _ := login(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/wireguard/status", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("WireGuard status = %d %s", response.Code, response.Body.String())
	}
	content := response.Body.String()
	for _, expected := range []string{`"status":"ACTIVE"`, `"current_modem_id":"modem-a"`, `"endpoint_ip":"203.0.113.10"`, `"management_reachability_state"`} {
		if !strings.Contains(content, expected) {
			t.Errorf("WireGuard status missing %s: %s", expected, content)
		}
	}
	if strings.Contains(content, "config_sha256") || strings.Contains(content, strings.Repeat("f", 64)) {
		t.Fatalf("WireGuard status exposed protected config fingerprint: %s", content)
	}
}

func TestExactPathOperationsAndLazyEvidenceAPI(t *testing.T) {
	server, ctx := testServer(t)
	now := time.Now().UTC()
	if _, err := server.dependencies.Database.ExecContext(ctx, `
UPDATE modems SET state='MODEM_READY' WHERE id='modem-a';
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at, activated_at)
VALUES ('version-a', 'sub-a', ?, 1, 'LKG', ?, ?);
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-a', 'version-a', 'LTE bypass', 'lte bypass', 'fingerprint-a', 'vless');
UPDATE subscriptions SET active_version_id='version-a' WHERE id='sub-a';
INSERT INTO bypass_probe_targets (
 id, name, target_kind, target_value, normalized_url, enabled, required,
 priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES ('target-a', 'Access', 'domain', 'example.com', 'https://example.com/', 1, 1, 10, 8, 'any_http_response', 'UNKNOWN', ?, ?)`, strings.Repeat("0", 64), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := server.dependencies.Paths.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, err := server.dependencies.Paths.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.dependencies.Paths.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 12,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 12, Targets: []pathmatrix.TargetEvidence{{TargetID: "target-a", State: "PASSED", HTTPStatus: 204}}}},
	}); err != nil {
		t.Fatal(err)
	}
	operation := &fakePathOperator{result: candidateruntime.PathOperationResult{
		PathID: cell.ID, NodeID: "node-a", CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Result: health.CellResult{PathID: cell.ID, ModemID: "modem-a", SubscriptionID: "sub-a", State: health.CellQualified, TransportState: health.ProbePassed, SelectedNodeID: "node-a", CandidateNodes: 1, QualifiedNodes: 1, RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, Nodes: []health.NodeResult{{NodeID: "node-a", State: health.NodeQualified, Transport: health.ProbeResult{State: health.ProbePassed}, RequiredPassed: 1, RequiredTotal: 1, Targets: []health.TargetResult{{TargetID: "target-a", Required: true, State: health.ProbePassed, HTTPStatus: 204}}}}},
	}}
	activator := &fakePathActivator{result: reconcile.Result{Action: "PATH_ACTIVATED", Candidate: reconcile.Candidate{PathID: cell.ID, ModemID: "modem-a", SubscriptionID: "sub-a", NodeID: "node-a"}}}
	server.dependencies.PathOperations = operation
	server.dependencies.PathActivator = activator
	cookie, csrf := login(t, server)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.AddCookie(cookie)
		if method != http.MethodGet {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}
	response := call(http.MethodGet, "/api/v1/paths/"+cell.ID+"/nodes?limit=1", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"can_activate":true`) || !strings.Contains(response.Body.String(), `"external_name":"LTE bypass"`) {
		t.Fatalf("path nodes = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodGet, "/api/v1/paths/"+cell.ID+"/nodes/node-a/targets?limit=1", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"target_id":"target-a"`) || !strings.Contains(response.Body.String(), `"state":"PASSED"`) {
		t.Fatalf("node targets = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodPost, "/api/v1/paths/"+cell.ID+"/nodes/node-a/probe", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"authoritative":false`) || !strings.Contains(response.Body.String(), `"targets"`) {
		t.Fatalf("exact diagnostic probe = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodPost, "/api/v1/paths/"+cell.ID+"/activate", `{"node_id":"node-a"}`)
	if response.Code != http.StatusOK || len(activator.calls) != 1 {
		t.Fatalf("exact activation = %d calls=%v %s", response.Code, activator.calls, response.Body.String())
	}
	activator.err = store.ErrNotFound
	response = call(http.MethodPost, "/api/v1/paths/"+cell.ID+"/activate", `{"node_id":"node-a"}`)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "NODE_NOT_FRESH") {
		t.Fatalf("stale exact activation = %d %s", response.Code, response.Body.String())
	}
}

type fakeWireGuardSync struct {
	calls int
	err   error
}

type fakeModemRuntime struct {
	blocks         int
	routingSyncs   int
	wireGuardSyncs int
	err            error
	onBlock        func()
}

type fakeModemPathProber struct {
	calls int
	err   error
}

type fakePathOperator struct {
	result candidateruntime.PathOperationResult
	err    error
	calls  []string
}

func (operator *fakePathOperator) ProbeNode(_ context.Context, pathID, nodeID string) (candidateruntime.PathOperationResult, error) {
	operator.calls = append(operator.calls, "probe:"+pathID+":"+nodeID)
	return operator.result, operator.err
}

func (operator *fakePathOperator) QualifyNode(_ context.Context, pathID, nodeID string) (candidateruntime.PathOperationResult, error) {
	operator.calls = append(operator.calls, "qualify-node:"+pathID+":"+nodeID)
	return operator.result, operator.err
}

func (operator *fakePathOperator) QualifyPath(_ context.Context, pathID string) (candidateruntime.PathOperationResult, error) {
	operator.calls = append(operator.calls, "qualify-path:"+pathID)
	return operator.result, operator.err
}

type fakePathActivator struct {
	result reconcile.Result
	err    error
	calls  []string
}

func (activator *fakePathActivator) ActivateExact(_ context.Context, pathID, nodeID string) (reconcile.Result, error) {
	activator.calls = append(activator.calls, pathID+":"+nodeID)
	return activator.result, activator.err
}

func (prober *fakeModemPathProber) RequalifyModem(_ context.Context, modemID string) (candidateruntime.RequalificationResult, error) {
	prober.calls++
	return candidateruntime.RequalificationResult{ModemID: modemID, SubscriptionsChecked: 1, Qualified: 1, CheckedAt: time.Now()}, prober.err
}

func (runtime *fakeModemRuntime) BlockPath(context.Context) error {
	runtime.blocks++
	if runtime.onBlock != nil {
		runtime.onBlock()
	}
	return runtime.err
}

func (runtime *fakeModemRuntime) SyncRouting(context.Context) error {
	runtime.routingSyncs++
	return runtime.err
}

func (runtime *fakeModemRuntime) SyncWireGuard(context.Context) error {
	runtime.wireGuardSyncs++
	return runtime.err
}

func (syncer *fakeWireGuardSync) SyncWireGuard(context.Context) error {
	syncer.calls++
	return syncer.err
}

func TestWireGuardSettingsAreCSRFProtectedPersistedAndSecretFree(t *testing.T) {
	server, _ := testServer(t)
	configPath := filepath.Join(t.TempDir(), "wireguard.yaml")
	syncer := &fakeWireGuardSync{}
	server.dependencies.WireGuardConfigPath = configPath
	server.dependencies.WireGuardSync = syncer
	cookie, csrf := login(t, server)
	privateKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	peerKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
	payload, _ := json.Marshal(map[string]any{
		"private_key": privateKey, "peer_public_key": peerKey,
		"endpoint": "203.0.113.10:51821", "persistent_keepalive": 25,
	})
	request := httptest.NewRequest(http.MethodPut, "/api/v1/settings/wireguard", bytes.NewReader(payload))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || syncer.calls != 1 {
		t.Fatalf("update WireGuard settings = %d/%d %s", response.Code, syncer.calls, response.Body.String())
	}
	stored, err := wireguardpkg.LoadConfig(configPath)
	if err != nil || stored.PrivateKey != privateKey || stored.Endpoint != "203.0.113.10:51821" {
		t.Fatalf("stored WireGuard config = %+v, %v", stored, err)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/api/v1/settings/wireguard", nil)
	getRequest.AddCookie(cookie)
	getResponse := httptest.NewRecorder()
	server.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), peerKey) {
		t.Fatalf("get WireGuard settings = %d %s", getResponse.Code, getResponse.Body.String())
	}
	if strings.Contains(getResponse.Body.String(), privateKey) || strings.Contains(response.Body.String(), privateKey) {
		t.Fatal("WireGuard private key was exposed by API")
	}
	updatePayload, _ := json.Marshal(map[string]any{
		"private_key": "", "peer_public_key": peerKey,
		"endpoint": "198.51.100.20:51821", "persistent_keepalive": 30,
	})
	updateRequest := httptest.NewRequest(http.MethodPut, "/api/v1/settings/wireguard", bytes.NewReader(updatePayload))
	updateRequest.AddCookie(cookie)
	updateRequest.Header.Set("X-CSRF-Token", csrf)
	updateResponse := httptest.NewRecorder()
	server.ServeHTTP(updateResponse, updateRequest)
	updated, err := wireguardpkg.LoadConfig(configPath)
	if updateResponse.Code != http.StatusAccepted || err != nil || updated.PrivateKey != privateKey || updated.Endpoint != "198.51.100.20:51821" {
		t.Fatalf("secret-preserving WireGuard update = %d, %+v, %v", updateResponse.Code, updated, err)
	}
}

func TestModemManagementOperationsConvergeAndNeverExposeIdentityHash(t *testing.T) {
	server, ctx := testServer(t)
	runtime := &fakeModemRuntime{}
	server.dependencies.ModemRuntime = runtime
	pathProber := &fakeModemPathProber{}
	server.dependencies.ModemPathProbe = pathProber
	server.dependencies.ModemReconcile = func(context.Context) (hilink.CycleResult, error) {
		return hilink.CycleResult{ReadyModems: []string{"modem-a"}}, nil
	}
	server.dependencies.Discoveries = hilink.NewDiscoveryRegistry(server.dependencies.Modems)
	cookie, csrf := login(t, server)
	call := func(method, path, body string, confirmation string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.AddCookie(cookie)
		request.Header.Set("X-CSRF-Token", csrf)
		if confirmation != "" {
			request.Header.Set("X-Confirm-Destructive", confirmation)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}

	if response := call(http.MethodPatch, "/api/v1/modems/modem-a", `{"name":"Primary LTE","operator_label":"Operator A"}`, ""); response.Code != http.StatusNoContent {
		t.Fatalf("update modem = %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPut, "/api/v1/modems/priorities", `{"ids":["modem-a"]}`, ""); response.Code != http.StatusAccepted {
		t.Fatalf("reorder modems = %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/api/v1/modems/modem-a/disable", `{}`, ""); response.Code != http.StatusAccepted {
		t.Fatalf("disable modem = %d %s", response.Code, response.Body.String())
	}
	disabled, _ := server.dependencies.Modems.Get(ctx, "modem-a")
	if disabled.Enabled || disabled.State != modem.StateDisabled {
		t.Fatalf("disabled modem = %+v", disabled)
	}
	if response := call(http.MethodPost, "/api/v1/modems/modem-a/enable", `{}`, ""); response.Code != http.StatusAccepted {
		t.Fatalf("enable modem = %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/api/v1/modems/modem-a/probe", `{}`, ""); response.Code != http.StatusAccepted {
		t.Fatalf("probe modem = %d %s", response.Code, response.Body.String())
	}
	if pathProber.calls != 1 {
		t.Fatalf("modem path probe calls = %d", pathProber.calls)
	}
	if response := call(http.MethodPost, "/api/v1/modems/modem-a/recover", `{}`, ""); response.Code != http.StatusAccepted {
		t.Fatalf("recover modem = %d %s", response.Code, response.Body.String())
	}
	if err := server.dependencies.Modems.MarkOffline(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	identity := strings.Repeat("b", 64)
	server.dependencies.Discoveries.Replace([]hilink.Match{{State: hilink.DiscoveryUnadopted, Candidate: hilink.Candidate{DiscoveryID: "replacement-a", InterfaceName: "enx2", IdentityKind: "usb_serial_hash", IdentityHash: identity, MaskedSerial: "****9999"}}})
	if response := call(http.MethodPost, "/api/v1/modems/modem-a/replace-identity", `{"discovery_id":"replacement-a"}`, "replace-modem-identity"); response.Code != http.StatusAccepted || strings.Contains(response.Body.String(), identity) {
		t.Fatalf("replace identity = %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodDelete, "/api/v1/modems/modem-a", `{}`, "forget-offline-modem"); response.Code != http.StatusAccepted {
		t.Fatalf("forget modem = %d %s", response.Code, response.Body.String())
	}
	if _, err := server.dependencies.Modems.Get(ctx, "modem-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forgotten modem error = %v", err)
	}
	if runtime.routingSyncs < 7 || runtime.wireGuardSyncs < 7 {
		t.Fatalf("modem runtime convergence calls = routing %d, WireGuard %d", runtime.routingSyncs, runtime.wireGuardSyncs)
	}
}

func TestDisablingActiveModemBlocksPathBeforeMutation(t *testing.T) {
	server, ctx := testServer(t)
	runtime := &fakeModemRuntime{}
	server.dependencies.ModemRuntime = runtime
	if _, err := server.dependencies.Database.ExecContext(ctx, "UPDATE runtime_state SET active_modem_id='modem-a' WHERE singleton_id=1"); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/modems/modem-a/disable", strings.NewReader(`{}`))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || runtime.blocks != 1 {
		t.Fatalf("active disable status/blocks = %d/%d %s", response.Code, runtime.blocks, response.Body.String())
	}
}

type fakeNetworkBroker struct {
	prepared  networkapply.Prepared
	applied   chan string
	confirmed networkapply.ConfirmEvidence
}

type fakeLoggingSynchronizer struct {
	calls int
	err   error
}

type fakeJournalReader struct {
	queries []loggingpkg.JournalQuery
	page    loggingpkg.JournalPage
	err     error
}

type fakeDiagnosticBundler struct {
	description diagnostics.Description
	bundle      diagnostics.Bundle
	err         error
	describes   int
	builds      int
}

type fakePortableBackups struct {
	artifact backup.PortableArtifact
	content  []byte
	err      error
	builds   int
	opens    int
	removes  int
}

type fakeRestoreStager struct {
	operation      backup.RestoreOperation
	content        []byte
	passphrase     string
	stageErr       error
	statusErr      error
	discardErr     error
	authorizeErr   error
	stages         int
	discards       int
	authorizations int
	pending        bool
	onAuthorize    func()
}

type fakeRestoreApplyTrigger struct {
	calls   int
	err     error
	onApply func() error
}

type fakeUpdateStager struct {
	operation  updatepkg.Operation
	content    []byte
	stageErr   error
	statusErr  error
	discardErr error
	stages     int
	discards   int
	pending    bool
}

type fakeUpdateApplyTrigger struct {
	calls     int
	err       error
	onApply   func() error
	status    networkapply.UpdateTransactionStatus
	statusErr error
}

type restoreMultipartPart struct {
	name     string
	filename string
	content  []byte
}

func restoreMultipart(t *testing.T, parts []restoreMultipartPart) ([]byte, string) {
	t.Helper()
	var content bytes.Buffer
	writer := multipart.NewWriter(&content)
	for _, part := range parts {
		var destination io.Writer
		var err error
		if part.filename == "" {
			destination, err = writer.CreateFormField(part.name)
		} else {
			destination, err = writer.CreateFormFile(part.name, part.filename)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := destination.Write(part.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return content.Bytes(), writer.FormDataContentType()
}

func (stager *fakeRestoreStager) Stage(_ context.Context, reader io.Reader, passphrase string) (backup.RestoreOperation, error) {
	stager.stages++
	stager.passphrase = passphrase
	content, err := io.ReadAll(reader)
	if err != nil {
		return backup.RestoreOperation{}, err
	}
	stager.content = content
	if stager.stageErr != nil {
		return backup.RestoreOperation{}, stager.stageErr
	}
	stager.pending = true
	return stager.operation, nil
}

func (stager *fakeRestoreStager) Status() (backup.RestoreOperation, bool, error) {
	return stager.operation, stager.pending, stager.statusErr
}

func (stager *fakeRestoreStager) AuthorizeApply(restoreID string) (backup.RestoreOperation, error) {
	stager.authorizations++
	if stager.authorizeErr != nil {
		return backup.RestoreOperation{}, stager.authorizeErr
	}
	if !stager.pending || restoreID != stager.operation.RestoreID || (stager.operation.State != backup.RestoreStateStaged && stager.operation.State != backup.RestoreStateApplyRequested) {
		return backup.RestoreOperation{}, backup.ErrRestoreNotPending
	}
	if stager.operation.State == backup.RestoreStateStaged {
		stager.operation.ApplyAuthorization = strings.Repeat("a", 64)
	}
	stager.operation.State = backup.RestoreStateApplyRequested
	stager.operation.ApplyErrorCode = ""
	if stager.onAuthorize != nil {
		stager.onAuthorize()
	}
	return stager.operation, nil
}

func (stager *fakeRestoreStager) Discard(_ context.Context, restoreID string) error {
	stager.discards++
	if stager.discardErr != nil {
		return stager.discardErr
	}
	if !stager.pending || restoreID != stager.operation.RestoreID || stager.operation.State != backup.RestoreStateStaged {
		return backup.ErrRestoreNotPending
	}
	stager.pending = false
	return nil
}

func (trigger *fakeRestoreApplyTrigger) ApplyPendingRestore(context.Context) error {
	trigger.calls++
	if trigger.onApply != nil {
		if err := trigger.onApply(); err != nil {
			return err
		}
	}
	return trigger.err
}

func (stager *fakeUpdateStager) Stage(_ context.Context, reader io.Reader) (updatepkg.Operation, error) {
	stager.stages++
	content, err := io.ReadAll(reader)
	if err != nil {
		return updatepkg.Operation{}, err
	}
	stager.content = content
	if stager.stageErr != nil {
		return updatepkg.Operation{}, stager.stageErr
	}
	stager.pending = true
	return stager.operation, nil
}

func (stager *fakeUpdateStager) Status() (updatepkg.Operation, bool, error) {
	return stager.operation, stager.pending, stager.statusErr
}

func (stager *fakeUpdateStager) Discard(_ context.Context, updateID string) error {
	stager.discards++
	if stager.discardErr != nil {
		return stager.discardErr
	}
	if !stager.pending || updateID != stager.operation.UpdateID {
		return errors.New("update is not pending")
	}
	stager.pending = false
	return nil
}

func (trigger *fakeUpdateApplyTrigger) ApplyPendingUpdate(context.Context) error {
	trigger.calls++
	if trigger.onApply != nil {
		if err := trigger.onApply(); err != nil {
			return err
		}
	}
	return trigger.err
}

func (trigger *fakeUpdateApplyTrigger) UpdateStatus(context.Context) (networkapply.UpdateTransactionStatus, error) {
	return trigger.status, trigger.statusErr
}

func (manager *fakePortableBackups) Build(_ context.Context, passphrase string) (backup.PortableArtifact, error) {
	manager.builds++
	if passphrase != "correct horse battery staple" {
		return backup.PortableArtifact{}, errors.New("unexpected passphrase")
	}
	return manager.artifact, manager.err
}

func (manager *fakePortableBackups) Open(backup.PortableArtifact) (io.ReadCloser, error) {
	manager.opens++
	if manager.err != nil {
		return nil, manager.err
	}
	return io.NopCloser(bytes.NewReader(manager.content)), nil
}

func (manager *fakePortableBackups) Remove(backup.PortableArtifact) error {
	manager.removes++
	return nil
}

func (bundler *fakeDiagnosticBundler) Describe(context.Context) (diagnostics.Description, error) {
	bundler.describes++
	return bundler.description, bundler.err
}

func (bundler *fakeDiagnosticBundler) Build(context.Context) (diagnostics.Bundle, error) {
	bundler.builds++
	return bundler.bundle, bundler.err
}

func (reader *fakeJournalReader) QueryLogs(_ context.Context, query loggingpkg.JournalQuery) (loggingpkg.JournalPage, error) {
	reader.queries = append(reader.queries, query)
	return reader.page, reader.err
}

func (synchronizer *fakeLoggingSynchronizer) SyncLogging(context.Context) error {
	synchronizer.calls++
	return synchronizer.err
}

type fakeSubscriptionRefresher struct {
	ids           []string
	refreshIDs    []string
	reclassifyIDs []string
	result        subscription.RefreshResult
	err           error
}

func (refresher *fakeSubscriptionRefresher) RefreshOne(_ context.Context, id string, force bool) (subscription.RefreshResult, error) {
	if !force {
		return subscription.RefreshResult{}, errors.New("manual refresh was not forced")
	}
	refresher.ids = append(refresher.ids, id)
	refresher.refreshIDs = append(refresher.refreshIDs, id)
	return refresher.result, refresher.err
}

func (refresher *fakeSubscriptionRefresher) ReclassifyOne(_ context.Context, id string) (subscription.RefreshResult, error) {
	refresher.ids = append(refresher.ids, id)
	refresher.reclassifyIDs = append(refresher.reclassifyIDs, id)
	return refresher.result, refresher.err
}

func (broker *fakeNetworkBroker) Stage(context.Context, networkapply.Candidate) (networkapply.Prepared, error) {
	return broker.prepared, nil
}

func (broker *fakeNetworkBroker) Apply(_ context.Context, id string) error {
	broker.applied <- id
	return nil
}

func (broker *fakeNetworkBroker) Confirm(_ context.Context, _ string, evidence networkapply.ConfirmEvidence) error {
	broker.confirmed = evidence
	return nil
}

func testServer(t *testing.T) (*Server, context.Context) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	authService := auth.Service{Database: database, Parameters: auth.Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}}
	if _, err := authService.CreateBootstrapAdmin(ctx, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	// Most API tests exercise post-bootstrap behavior. Mandatory temporary
	// password handling has dedicated tests below.
	if _, err := database.ExecContext(ctx, "UPDATE users SET must_change_password=0 WHERE id='admin'"); err != nil {
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("modem-a"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	paths := pathmatrix.NewRepository(database)
	if err := paths.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	matchers := subscription.NewMatcherRepository(database)
	if _, err := matchers.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	server, err := New(Dependencies{Database: database, Auth: authService, State: state.NewRepository(database), Modems: modems, Subscriptions: subscriptions, Nodes: subscription.NewNodeRepository(database), Paths: paths, Targets: bypass.NewRepository(database), Matchers: matchers, WireGuardRuntime: &wireguardpkg.RuntimeStore{Database: database}})
	if err != nil {
		t.Fatal(err)
	}
	return server, ctx
}

func attachBackupManager(t *testing.T, server *Server) *backup.Manager {
	t.Helper()
	var sequence int
	var databaseName, databasePath string
	if err := server.dependencies.Database.QueryRow("PRAGMA database_list").Scan(&sequence, &databaseName, &databasePath); err != nil {
		t.Fatal(err)
	}
	manager, err := backup.NewManager(server.dependencies.Database, filepath.Dir(databasePath), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	server.dependencies.Backups = manager
	return manager
}

func login(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	request.RemoteAddr = "192.168.200.2:12345"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login = %d %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookies = %+v", cookies)
	}
	var payload struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.CSRF == "" {
		t.Fatalf("login payload = %s, %v", response.Body.String(), err)
	}
	return cookies[0], payload.CSRF
}
