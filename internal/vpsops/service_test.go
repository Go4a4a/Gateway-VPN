package vpsops_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsops"
)

func TestLogsAndDiagnosticBundleRemainUsefulWithoutRootSnapshot(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := vpsagent.Open(ctx, filepath.Join(root, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `INSERT INTO audit_events(occurred_at,severity,event_type,details_json) VALUES(?,?,?,?)`, "2026-08-30T20:00:00Z", "WARNING", "VPS_ADMIN_PEER_CREATED", `{"password":"never-export-this","admin_peer_id":"admin:1"}`); err != nil {
		t.Fatal(err)
	}
	fabric := filepath.Join(root, "fabric.json")
	if err := os.WriteFile(fabric, []byte(`{"state":"HEALTHY"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	service := &vpsops.Service{Database: database, SnapshotPath: filepath.Join(root, "operations", "snapshot.json"), FabricStatusPath: fabric, Config: vpsops.ConfigSummary{Listen: []string{"127.0.0.1:9443"}, AdminPrefixes: []string{"10.80.0.0/24"}, StateDirectory: "/var/lib/gateway-vpn-vps/agent"}, AgentVersion: "vps-agent test", Now: func() time.Time { return time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC) }}
	page, err := service.Logs(ctx, vpsops.LogQuery{Category: vpsops.CategoryAdmins, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.State != "DEGRADED" || page.Reason != "ROOT_SNAPSHOT_UNAVAILABLE" || len(page.Items) != 1 || strings.Contains(page.Items[0].Message, "never-export-this") || !strings.Contains(page.Items[0].Message, "[REDACTED]") {
		t.Fatalf("log page = %+v", page)
	}
	security, err := service.Logs(ctx, vpsops.LogQuery{Category: vpsops.CategorySecurity, Limit: 10})
	if err != nil || len(security.Items) != 1 || security.Items[0].Source != "security-audit" {
		t.Fatalf("security audit page = %+v, %v", security, err)
	}
	bundle, err := service.BuildBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vpsops.VerifyBundle(bundle.Content)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Complete || manifest.SecretsIncluded || !containsError(manifest.SectionErrors, "ROOT_SNAPSHOT_UNAVAILABLE") || strings.Contains(string(bundle.Content), "never-export-this") {
		t.Fatalf("bundle/manifest = %+v", manifest)
	}
}

func containsError(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
