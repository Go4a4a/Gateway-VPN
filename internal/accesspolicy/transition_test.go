package accesspolicy

import (
	"testing"
	"time"
)

func TestEvaluateTransitionUsesStableWindowCooldownAndHardFailure(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	policy := Policy{FailureHoldSeconds: 30, RecoveryStableSeconds: 120, SwitchCooldownSeconds: 60}
	decision, err := EvaluateTransition(TransitionInput{CurrentKey: "vpn", ProposedKey: "direct", CurrentHealthy: true, Policy: policy, Now: now})
	if err != nil || decision.Allow || !decision.TrackPending || decision.Reason != "RECOVERY_STABLE_STARTED" {
		t.Fatalf("initial recovery decision = %+v, %v", decision, err)
	}
	runtime := SelectionRuntime{PendingCandidateKey: "direct", PendingCandidateSince: now.Add(-119 * time.Second).Format(time.RFC3339Nano)}
	decision, err = EvaluateTransition(TransitionInput{CurrentKey: "vpn", ProposedKey: "direct", CurrentHealthy: true, Policy: policy, Runtime: runtime, Now: now})
	if err != nil || decision.Allow || decision.Reason != "RECOVERY_STABLE_PENDING" {
		t.Fatalf("pending recovery decision = %+v, %v", decision, err)
	}
	runtime.PendingCandidateSince = now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	runtime.LastSwitchAt = now.Add(-30 * time.Second).Format(time.RFC3339Nano)
	decision, err = EvaluateTransition(TransitionInput{CurrentKey: "vpn", ProposedKey: "direct", CurrentHealthy: true, Policy: policy, Runtime: runtime, Now: now})
	if err != nil || decision.Allow || decision.Reason != "SWITCH_COOLDOWN" {
		t.Fatalf("cooldown decision = %+v, %v", decision, err)
	}
	runtime.LastSwitchAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	decision, err = EvaluateTransition(TransitionInput{CurrentKey: "vpn", ProposedKey: "direct", CurrentHealthy: true, Policy: policy, Runtime: runtime, Now: now})
	if err != nil || !decision.Allow || decision.Reason != "RECOVERY_STABLE_SATISFIED" {
		t.Fatalf("stable recovery decision = %+v, %v", decision, err)
	}
	decision, err = EvaluateTransition(TransitionInput{CurrentKey: "vpn", ProposedKey: "direct", HardFailure: true, Policy: policy, Now: now})
	if err != nil || !decision.Allow || decision.Reason != "HARD_FAILURE_FAST_PATH" {
		t.Fatalf("hard failure decision = %+v, %v", decision, err)
	}
}

func TestTemporaryDirectOnlySurvivesProcessRestartButNotHostReboot(t *testing.T) {
	ctx, database := accessDatabase(t)
	repository := NewRepository(database)
	if err := repository.SetTemporaryDirectOnly(ctx, true, "boot-a"); err != nil {
		t.Fatal(err)
	}
	if reset, err := repository.ReconcileBoot(ctx, "boot-a"); err != nil || reset {
		t.Fatalf("same-boot reconciliation = %t, %v", reset, err)
	}
	current, err := repository.GetSelectionRuntime(ctx)
	if err != nil || !current.TemporaryDirectOnly || current.TemporaryDirectBootID != "boot-a" {
		t.Fatalf("same-boot runtime = %+v, %v", current, err)
	}
	if reset, err := repository.ReconcileBoot(ctx, "boot-b"); err != nil || !reset {
		t.Fatalf("new-boot reconciliation = %t, %v", reset, err)
	}
	current, err = repository.GetSelectionRuntime(ctx)
	if err != nil || current.TemporaryDirectOnly || current.TemporaryDirectBootID != "" {
		t.Fatalf("new-boot runtime = %+v, %v", current, err)
	}
}
