package webapi

import (
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/pathmatrix"
)

func TestEffectiveAccessPathStateNeverTreatsMissingOrExpiredEvidenceAsFresh(t *testing.T) {
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	if state, reason := effectiveDirectPathState(accesspolicy.DirectPath{State: pathmatrix.StateQualified}, now); state != pathmatrix.StateStale || reason != "RESULT_EXPIRED" {
		t.Fatalf("direct missing expiry = %s/%s", state, reason)
	}
	if state, reason := effectivePathState(pathmatrix.Cell{State: pathmatrix.StateDegraded, ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano)}, now); state != pathmatrix.StateStale || reason != "RESULT_EXPIRED" {
		t.Fatalf("VPN expired limited evidence = %s/%s", state, reason)
	}
	if state, reason := effectiveDirectPathState(accesspolicy.DirectPath{State: pathmatrix.StateDegraded, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}, now); state != pathmatrix.StateDegraded || reason != "FRESH_LIMITED" {
		t.Fatalf("direct fresh limited evidence = %s/%s", state, reason)
	}
}
