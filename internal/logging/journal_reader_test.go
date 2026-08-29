package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
)

type journalExecutor struct {
	result   platformexec.Result
	err      error
	requests []platformexec.Request
}

func (executor *journalExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return executor.result, executor.err
}

func TestJournalReaderUsesFixedNamespaceBoundsAndFiltersParsedEntries(t *testing.T) {
	now := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	lines := []string{
		journalJSON(t, "s=newest", now, "6", "gateway-vpn.service", `{"time":"x","level":"INFO","msg":"path ok https://example.com/check?token=private","component":"path_health","path_id":"path-a","modem_id":"modem-a"}`),
		journalJSON(t, "s=middle", now.Add(-time.Second), "4", "gateway-vpn-mihomo.service", `proxy vless://private@example.net:443#node failed`),
		journalJSON(t, "s=oldest", now.Add(-2*time.Second), "3", "gateway-vpn.service", `{"level":"ERROR","msg":"path failed token=hidden","component":"path_health","path_id":"path-b","subscription_id":"sub-b","correlation_id":"corr-b"}`),
	}
	executor := &journalExecutor{result: platformexec.Result{Stdout: strings.Join(lines, "\n") + "\n"}}
	reader := JournalReader{Executor: executor, Journalctl: "/usr/bin/journalctl", Now: func() time.Time { return now }}
	page, err := reader.QueryLogs(context.Background(), JournalQuery{Limit: 1, Component: ComponentPathHealth, Levels: []string{LevelError}, Search: "failed"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Cursor != "s=oldest" || page.Items[0].PathID != "path-b" || page.Items[0].SubscriptionID != "sub-b" || page.Items[0].CorrelationID != "corr-b" || page.Items[0].Severity != LevelError {
		t.Fatalf("QueryLogs(filtered) = %+v, %v", page, err)
	}
	if strings.Contains(page.Items[0].Message, "hidden") || !strings.Contains(page.Items[0].Message, "[REDACTED]") {
		t.Fatalf("journal message redaction = %q", page.Items[0].Message)
	}
	if len(executor.requests) != 1 || executor.requests[0].Executable != "/usr/bin/journalctl" || executor.requests[0].MaxOutputBytes != journalOutputLimit {
		t.Fatalf("journal executor requests = %+v", executor.requests)
	}
	arguments := strings.Join(executor.requests[0].Arguments, " ")
	for _, required := range []string{"--namespace=gateway-vpn", "--output=json", "--reverse", "--lines=129", "--truncate-newline"} {
		if !strings.Contains(arguments, required) {
			t.Fatalf("journal arguments missing %q: %s", required, arguments)
		}
	}
	for _, forbidden := range []string{"path_health", "failed", "path-b", "sub-b"} {
		if strings.Contains(arguments, forbidden) {
			t.Fatalf("journal filters escaped typed in-process matching: %s", arguments)
		}
	}
}

func TestJournalReaderCursorPageIsExclusiveAndRedactsNonJSONMessage(t *testing.T) {
	now := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	executor := &journalExecutor{result: platformexec.Result{Stdout: strings.Join([]string{
		journalJSON(t, "s=cursor", now, "6", "gateway-vpn.service", "already returned"),
		journalJSON(t, "s=next", now.Add(-time.Second), "4", "gateway-vpn-mihomo.service", "proxy vless://private@example.net:443#node failed https://user:pass@example.org/x?q=secret"),
	}, "\n") + "\n"}}
	reader := JournalReader{Executor: executor, Journalctl: "/usr/bin/journalctl"}
	page, err := reader.QueryLogs(context.Background(), JournalQuery{Limit: 10, Cursor: "s=cursor"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Cursor != "s=next" || page.Items[0].Component != ComponentMihomo || page.Items[0].Severity != LevelWarning {
		t.Fatalf("QueryLogs(cursor) = %+v, %v", page, err)
	}
	if strings.Contains(page.Items[0].Message, "private") || strings.Contains(page.Items[0].Message, "secret") || strings.Contains(page.Items[0].Message, "pass") || !strings.Contains(page.Items[0].Message, "[REDACTED_PROXY_URI]") {
		t.Fatalf("non-JSON journal redaction = %q", page.Items[0].Message)
	}
	arguments := strings.Join(executor.requests[0].Arguments, " ")
	if !strings.Contains(arguments, "--cursor=s=cursor") {
		t.Fatalf("cursor arguments = %s", arguments)
	}
}

func TestJournalReaderPaginatesBeforeConsumingNextMatchingRecord(t *testing.T) {
	now := time.Now().UTC()
	executor := &journalExecutor{result: platformexec.Result{Stdout: strings.Join([]string{
		journalJSON(t, "s=one", now, "6", "gateway-vpn.service", `{"level":"INFO","msg":"one","component":"system"}`),
		journalJSON(t, "s=two", now.Add(-time.Second), "6", "gateway-vpn.service", `{"level":"INFO","msg":"two","component":"system"}`),
	}, "\n") + "\n"}}
	reader := JournalReader{Executor: executor, Journalctl: "/usr/bin/journalctl"}
	page, err := reader.QueryLogs(context.Background(), JournalQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 || !page.HasMore || page.NextCursor != "s=one" {
		t.Fatalf("QueryLogs(page) = %+v, %v", page, err)
	}
}

func TestJournalReaderRejectsUnsafeFiltersAndOutputFailure(t *testing.T) {
	reader := JournalReader{Executor: &journalExecutor{}, Journalctl: "/usr/bin/journalctl", Now: time.Now}
	tests := []JournalQuery{
		{Limit: 0},
		{Limit: 26},
		{Limit: 10, Cursor: "$(command)"},
		{Limit: 10, Component: "unknown"},
		{Limit: 10, Category: "arbitrary-unit"},
		{Limit: 10, ModemID: "id\nnext"},
		{Limit: 10, Levels: []string{"fatal"}},
		{Limit: 10, Search: strings.Repeat("x", 129)},
		{Limit: 10, Since: "invalid"},
		{Limit: 10, Since: time.Now().Add(-32 * 24 * time.Hour).Format(time.RFC3339Nano)},
	}
	for _, query := range tests {
		if _, err := reader.QueryLogs(context.Background(), query); err == nil {
			t.Fatalf("unsafe journal query accepted: %+v", query)
		}
	}
	executor := &journalExecutor{err: errors.New("private command detail")}
	reader.Executor = executor
	if _, err := reader.QueryLogs(context.Background(), JournalQuery{Limit: 10}); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("journal executor error = %v", err)
	}
}

func TestJournalCategoriesUseFixedComponentAndUnitMappings(t *testing.T) {
	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	entries := []JournalEntry{
		{Component: ComponentModem, Unit: "gateway-vpn.service"},
		{Component: ComponentSubscription, Unit: "gateway-vpn.service"},
		{Component: ComponentPathHealth, Unit: "gateway-vpn.service"},
		{Component: ComponentTraffic, Unit: "gateway-vpn.service"},
		{Component: ComponentMihomo, Unit: "gateway-vpn-mihomo.service"},
		{Component: ComponentRoutingFirewall, Unit: "gateway-vpn-network-broker.service"},
		{Component: ComponentSystem, Unit: "gateway-vpn-dnsmasq.service"},
		{Component: ComponentWireGuard, Unit: "gateway-vpn.service"},
		{Component: ComponentSystem, Unit: "gateway-vpn-watchdog.service"},
		{Component: ComponentSystem, Unit: "gateway-vpn-update.service"},
		{Component: ComponentSystem, Unit: "gateway-vpn-database-restore.service"},
		{Component: ComponentAuthAudit, Unit: "gateway-vpn.service"},
	}
	expected := map[string][]int{
		"modems": {0}, "subscriptions": {1}, "access": {2, 3}, "vpn-mihomo": {4},
		"network": {5, 6}, "wireguard-vps": {7}, "watchdog": {8},
		"updates": {9, 10}, "security-audit": {11},
	}
	for category, indexes := range expected {
		normalized, err := NormalizeJournalQuery(JournalQuery{Limit: 25, Category: category}, now)
		if err != nil {
			t.Fatalf("NormalizeJournalQuery(%s): %v", category, err)
		}
		for index, entry := range entries {
			want := false
			for _, expectedIndex := range indexes {
				want = want || index == expectedIndex
			}
			if got := journalEntryMatches(entry, normalized); got != want {
				t.Fatalf("category %s entry %d match=%t want=%t", category, index, got, want)
			}
		}
	}
}

func journalJSON(t *testing.T, cursor string, at time.Time, priority, unit, message string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"__CURSOR": cursor, "__REALTIME_TIMESTAMP": strconvMicroseconds(at),
		"PRIORITY": priority, "_SYSTEMD_UNIT": unit, "MESSAGE": message,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func strconvMicroseconds(at time.Time) string {
	return fmt.Sprintf("%d", at.UnixNano()/1000)
}
