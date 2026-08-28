package webapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/modemrecovery"
)

type webRecoveryExecutor struct {
	commands []modemrecovery.Command
}

func (executor *webRecoveryExecutor) Execute(_ context.Context, command modemrecovery.Command) error {
	executor.commands = append(executor.commands, command)
	return nil
}

func TestModemRecoveryAPIExposesBoundedPolicyAndManualPhysicalAction(t *testing.T) {
	server, ctx := testServer(t)
	executor := &webRecoveryExecutor{}
	controller := &modemrecovery.Controller{
		Repository: modemrecovery.NewRepository(server.dependencies.Database),
		Executor:   executor,
	}
	server.dependencies.ModemRecovery = controller
	server.dependencies.ModemRuntime = &fakeModemRuntime{}
	server.dependencies.ModemReconcile = func(context.Context) (hilink.CycleResult, error) {
		return hilink.CycleResult{PhysicalFailures: map[string]string{"modem-a": modemrecovery.FailureDHCPLeaseMissing}}, nil
	}
	if err := server.dependencies.Modems.ObservePhysicalLink(ctx, "modem-a", "enx123", true); err != nil {
		t.Fatal(err)
	}
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

	response := call(http.MethodPost, "/api/v1/modems/modem-a/recover", `{}`)
	if response.Code != http.StatusAccepted || len(executor.commands) != 1 || executor.commands[0].Action != modemrecovery.ActionDHCPRenew {
		t.Fatalf("manual recovery = %d %s commands=%+v", response.Code, response.Body.String(), executor.commands)
	}
	response = call(http.MethodGet, "/api/v1/modems/modem-a/recovery?limit=10", "")
	var snapshot modemrecovery.Snapshot
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &snapshot) != nil || len(snapshot.Attempts) != 1 || snapshot.Attempts[0].FailureReason != modemrecovery.FailureDHCPLeaseMissing {
		t.Fatalf("recovery snapshot = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodPut, "/api/v1/modems/modem-a/recovery", `{
        "enabled":true,
        "dhcp_retry_after_seconds":20,
        "api_retry_after_seconds":40,
        "mobile_session_restart_after_seconds":100,
        "usb_rebind_after_seconds":240,
        "usb_reset_after_seconds":480,
        "usb_reset_cooldown_seconds":900,
        "max_usb_resets_per_window":2,
        "usb_reset_window_seconds":3600,
        "allow_hub_port_power_cycle":false
    }`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"policy_generation":2`) {
		t.Fatalf("policy update = %d %s", response.Code, response.Body.String())
	}

	response = call(http.MethodGet, "/api/v1/modems", "")
	for _, expected := range []string{`"recovery_state"`, `"recovery_reason":"POLICY_UPDATED"`, `"physical_failure"`} {
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("modem recovery projection missing %s: %d %s", expected, response.Code, response.Body.String())
		}
	}
}

func TestManualRecoveryDoesNothingForPhysicallyHealthyModem(t *testing.T) {
	server, _ := testServer(t)
	executor := &webRecoveryExecutor{}
	server.dependencies.ModemRecovery = &modemrecovery.Controller{Repository: modemrecovery.NewRepository(server.dependencies.Database), Executor: executor}
	server.dependencies.ModemRuntime = &fakeModemRuntime{}
	server.dependencies.ModemReconcile = func(context.Context) (hilink.CycleResult, error) {
		return hilink.CycleResult{ReadyModems: []string{"modem-a"}, PhysicallyHealthyModems: []string{"modem-a"}, PhysicalFailures: map[string]string{}}, nil
	}
	cookie, csrf := login(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/modems/modem-a/recover", strings.NewReader(`{}`))
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || len(executor.commands) != 0 || !strings.Contains(response.Body.String(), "NO_PHYSICAL_FAILURE") {
		t.Fatalf("healthy manual recovery = %d %s commands=%+v", response.Code, response.Body.String(), executor.commands)
	}
}
