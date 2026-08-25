package mihomo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeCandidateValidator struct {
	err   error
	paths []string
}

func (validator *fakeCandidateValidator) Validate(_ context.Context, path string) error {
	validator.paths = append(validator.paths, path)
	return validator.err
}

type fakeGenerationRuntime struct {
	activations []string
	failVerify  map[string]bool
	blocked     int
}

func (runtime *fakeGenerationRuntime) Activate(_ context.Context, generation, _ string) error {
	runtime.activations = append(runtime.activations, generation)
	return nil
}

func (runtime *fakeGenerationRuntime) Verify(_ context.Context, generation string) error {
	if runtime.failVerify[generation] {
		return errors.New("verification failed")
	}
	return nil
}

func (runtime *fakeGenerationRuntime) FailClosed(context.Context) error {
	runtime.blocked++
	return nil
}

func TestTransactionAppliesVerifiedGenerationAndRollsBackFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	validator := &fakeCandidateValidator{}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Validator: validator, Runtime: runtime}
	bundle := Bundle{Main: []byte("proxies: []\n"), Providers: map[string][]byte{}}
	if result, err := controller.Apply(context.Background(), "generation-1", bundle); err != nil || result.RolledBack {
		t.Fatalf("Apply(first) = %+v, %v", result, err)
	}
	active, _ := readGenerationMarker(root, markerActive)
	lkg, _ := readGenerationMarker(root, markerLKG)
	if active != "generation-1" || lkg != "generation-1" {
		t.Fatalf("markers = %s/%s", active, lkg)
	}
	runtime.failVerify["generation-2"] = true
	result, err := controller.Apply(context.Background(), "generation-2", bundle)
	if err == nil || !result.RolledBack || result.PreviousGeneration != "generation-1" {
		t.Fatalf("Apply(failing second) = %+v, %v", result, err)
	}
	if !reflect.DeepEqual(runtime.activations, []string{"generation-1", "generation-2", "generation-1"}) {
		t.Fatalf("runtime activations = %v", runtime.activations)
	}
	active, _ = readGenerationMarker(root, markerActive)
	if active != "generation-1" {
		t.Fatalf("active marker after rollback = %s", active)
	}
}

func TestValidationFailureDoesNotActivateOrReplaceLKG(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	validator := &fakeCandidateValidator{err: errors.New("bad config")}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Validator: validator, Runtime: runtime}
	_, err := controller.Apply(context.Background(), "generation-1", Bundle{Main: []byte("bad")})
	if err == nil {
		t.Fatal("Apply(invalid) error = nil")
	}
	if len(runtime.activations) != 0 {
		t.Fatalf("invalid candidate activations = %v", runtime.activations)
	}
	if _, err := readGenerationMarker(root, markerLKG); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LKG marker error = %v", err)
	}
}

func TestFirstGenerationVerificationFailureForcesFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	validator := &fakeCandidateValidator{}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{"generation-1": true}}
	controller := &TransactionController{Root: root, Validator: validator, Runtime: runtime}
	result, err := controller.Apply(context.Background(), "generation-1", Bundle{Main: []byte("proxies: []\n")})
	if err == nil || !result.RolledBack {
		t.Fatalf("Apply(unverifiable first generation) = %+v, %v", result, err)
	}
	if runtime.blocked != 1 {
		t.Fatalf("FailClosed calls = %d", runtime.blocked)
	}
	if _, err := readGenerationMarker(root, markerPending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker remains after fail-closed: %v", err)
	}
}

func TestRecoverLKGRejectsPendingCandidate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	if err := writeGenerationMarker(root, markerLKG, "generation-1"); err != nil {
		t.Fatal(err)
	}
	if err := writeGenerationMarker(root, markerPending, "generation-2"); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Runtime: runtime}
	if err := controller.RecoverLKG(context.Background()); err != nil {
		t.Fatalf("RecoverLKG() error = %v", err)
	}
	if !reflect.DeepEqual(runtime.activations, []string{"generation-1"}) {
		t.Fatalf("recovery activations = %v", runtime.activations)
	}
	if _, err := readGenerationMarker(root, markerPending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker still exists: %v", err)
	}
}

func TestRecoverInterruptedFirstGenerationEnforcesFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	if err := writeGenerationMarker(root, markerPending, "generation-1"); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Runtime: runtime}
	if err := controller.RecoverLKG(context.Background()); err != nil {
		t.Fatalf("RecoverLKG(first interrupted) error = %v", err)
	}
	if runtime.blocked != 1 {
		t.Fatalf("FailClosed calls = %d", runtime.blocked)
	}
	if _, err := readGenerationMarker(root, markerPending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker remains: %v", err)
	}
}

func TestRestoreReactivatesEarlierSuccessfulGeneration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	validator := &fakeCandidateValidator{}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Validator: validator, Runtime: runtime}
	bundle := Bundle{Main: []byte("proxies: []\n"), Providers: map[string][]byte{}}
	if _, err := controller.Apply(context.Background(), "generation-1", bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Apply(context.Background(), "generation-2", bundle); err != nil {
		t.Fatal(err)
	}
	if err := controller.Restore(context.Background(), "generation-1"); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if !reflect.DeepEqual(runtime.activations, []string{"generation-1", "generation-2", "generation-1"}) {
		t.Fatalf("runtime activations = %v", runtime.activations)
	}
	active, _ := readGenerationMarker(root, markerActive)
	lkg, _ := readGenerationMarker(root, markerLKG)
	if active != "generation-1" || lkg != "generation-1" {
		t.Fatalf("restored markers = %s/%s", active, lkg)
	}
}

func TestRestoreWithoutPreviousGenerationBlocksRuntimeAndClearsMarkers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	validator := &fakeCandidateValidator{}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Validator: validator, Runtime: runtime}
	if _, err := controller.Apply(context.Background(), "candidate-only", Bundle{Main: []byte("proxies: []\n")}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Restore(context.Background(), ""); err != nil {
		t.Fatalf("Restore(empty) error = %v", err)
	}
	if runtime.blocked != 1 {
		t.Fatalf("FailClosed calls = %d", runtime.blocked)
	}
	for _, marker := range []string{markerActive, markerLKG, markerPending} {
		if _, err := readGenerationMarker(root, marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("marker %s still exists: %v", marker, err)
		}
	}
}

func TestRestoreVerificationFailureForcesFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mihomo")
	validator := &fakeCandidateValidator{}
	runtime := &fakeGenerationRuntime{failVerify: map[string]bool{}}
	controller := &TransactionController{Root: root, Validator: validator, Runtime: runtime}
	bundle := Bundle{Main: []byte("proxies: []\n")}
	if _, err := controller.Apply(context.Background(), "generation-1", bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Apply(context.Background(), "generation-2", bundle); err != nil {
		t.Fatal(err)
	}
	runtime.failVerify["generation-1"] = true
	if err := controller.Restore(context.Background(), "generation-1"); err == nil {
		t.Fatal("Restore(unverifiable) error = nil")
	}
	if runtime.blocked != 1 {
		t.Fatalf("FailClosed calls = %d", runtime.blocked)
	}
}
