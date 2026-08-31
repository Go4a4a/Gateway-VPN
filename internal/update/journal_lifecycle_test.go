package update

import "testing"

func TestJournalInProgressMatchesOnlyDurableTerminalStates(t *testing.T) {
	terminal := map[TransactionState]bool{
		StateRolledBack: true,
		StateFinalized:  true,
	}
	states := []TransactionState{
		StatePrepared,
		StateQuiesced,
		StateRestorePointReady,
		StateCandidateReady,
		StateDatabaseSwitchPending,
		StateDatabaseSwitched,
		StateReleaseSwitchPending,
		StateSwitched,
		StateHealthChecking,
		StateStabilizing,
		StateRollingBack,
		StateRolledBack,
		StateRollbackFailed,
		StateFinalized,
	}
	for _, state := range states {
		if got := (Journal{State: state}).InProgress(); got == terminal[state] {
			t.Errorf("state %s InProgress() = %t", state, got)
		}
	}
}
