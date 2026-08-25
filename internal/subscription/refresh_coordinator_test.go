package subscription

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	runtimepkg "runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type queuedFetcher struct {
	results []FetchResult
	errors  []error
	options []FetchOptions
}

func (fetcher *queuedFetcher) Fetch(_ context.Context, _ string, options FetchOptions) (FetchResult, error) {
	fetcher.options = append(fetcher.options, options)
	index := len(fetcher.options) - 1
	if index >= len(fetcher.results) {
		return FetchResult{}, errors.New("unexpected fetch")
	}
	var err error
	if index < len(fetcher.errors) {
		err = fetcher.errors[index]
	}
	return fetcher.results[index], err
}

type staticSourceURLReader struct {
	value string
	err   error
}

func (reader staticSourceURLReader) ReadURL(context.Context, string) (string, error) {
	return reader.value, reader.err
}

type recordingRuntime struct {
	candidates []Candidate
	err        error
	onPromote  func()
	rollback   *recordingRollback
}

func (runtime *recordingRuntime) Promote(_ context.Context, candidate Candidate) (CandidatePromotion, error) {
	runtime.candidates = append(runtime.candidates, candidate)
	if runtime.onPromote != nil {
		runtime.onPromote()
	}
	if runtime.err != nil {
		return nil, runtime.err
	}
	if runtime.rollback == nil {
		runtime.rollback = &recordingRollback{}
	}
	return runtime.rollback, nil
}

type recordingRollback struct {
	commits     int
	calls       int
	commitErr   error
	rollbackErr error
}

func (rollback *recordingRollback) Commit(context.Context) error {
	rollback.commits++
	return rollback.commitErr
}

func (rollback *recordingRollback) Rollback(context.Context) error {
	rollback.calls++
	return rollback.rollbackErr
}

func TestRefreshCoordinatorPromotesQualifiedCandidateAndUsesConditionalCache(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{
		{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one"), ETag: `"v1"`, LastModified: "today"},
		{NotModified: true, ETag: `"v1"`, LastModified: "today"},
		{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one"), ETag: `"v2"`, LastModified: "tomorrow"},
	}}
	runtime := &recordingRuntime{}
	coordinator := testRefreshCoordinator(t, database, fetcher, runtime)

	result, err := coordinator.RefreshOne(ctx, "sub-a", true)
	if err != nil {
		t.Fatalf("RefreshOne() error = %v", err)
	}
	if result.VersionID != "version-1" || result.NotModified || len(runtime.candidates) != 1 {
		t.Fatalf("RefreshOne() = %+v, candidates=%d", result, len(runtime.candidates))
	}
	if runtime.rollback.commits != 1 || runtime.rollback.calls != 0 {
		t.Fatalf("promotion commit/rollback = %d/%d", runtime.rollback.commits, runtime.rollback.calls)
	}
	candidate := runtime.candidates[0]
	if candidate.Version.Version.State != VersionCandidate || len(candidate.Version.Nodes) != 1 || !candidate.Version.Nodes[0].Enabled {
		t.Fatalf("runtime candidate = %+v", candidate.Version)
	}
	if info, err := os.Stat(candidate.PayloadPath); err != nil || (runtimepkg.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("candidate payload = %v, %v", info, err)
	}
	current, err := NewRepository(database).Get(ctx, "sub-a")
	if err != nil || current.ActiveVersionID != "version-1" {
		t.Fatalf("active subscription = %+v, %v", current, err)
	}
	state, err := NewRefreshRepository(database).Get(ctx, "sub-a")
	if err != nil || state.ETag != `"v1"` || state.ConsecutiveFailures != 0 || state.LeaseOwner != "" {
		t.Fatalf("refresh state = %+v, %v", state, err)
	}

	result, err = coordinator.RefreshOne(ctx, "sub-a", true)
	if err != nil || !result.NotModified || result.VersionID != "" || len(runtime.candidates) != 1 {
		t.Fatalf("unchanged RefreshOne() = %+v, %v, candidates=%d", result, err, len(runtime.candidates))
	}
	if len(fetcher.options) != 2 || fetcher.options[1].ETag != `"v1"` || fetcher.options[1].LastModified != "today" {
		t.Fatalf("conditional options = %+v", fetcher.options)
	}
	result, err = coordinator.RefreshOne(ctx, "sub-a", true)
	if err != nil || !result.NotModified || result.VersionID != "version-1" || len(runtime.candidates) != 1 {
		t.Fatalf("identical-body RefreshOne() = %+v, %v, candidates=%d", result, err, len(runtime.candidates))
	}
	state, err = NewRefreshRepository(database).Get(ctx, "sub-a")
	if err != nil || state.ETag != `"v2"` || state.LastModified != "tomorrow" {
		t.Fatalf("identical-body cache state = %+v, %v", state, err)
	}
	result, err = coordinator.ReclassifyOne(ctx, "sub-a")
	if err != nil || result.NotModified || result.VersionID != "version-2" || len(runtime.candidates) != 2 {
		t.Fatalf("ReclassifyOne() = %+v, %v, candidates=%d", result, err, len(runtime.candidates))
	}
	if len(fetcher.options) != 3 {
		t.Fatalf("reclassification unexpectedly used mobile fetch: %+v", fetcher.options)
	}
	state, err = NewRefreshRepository(database).Get(ctx, "sub-a")
	if err != nil || state.ETag != `"v2"` || state.LastModified != "tomorrow" {
		t.Fatalf("local reclassification changed HTTP cache state: %+v, %v", state, err)
	}
}

func TestRefreshCoordinatorRuntimeFailurePreservesPreviousLKG(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{
		{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one"), ETag: `"v1"`},
		{Payload: []byte("vless://22222222-2222-2222-2222-222222222222@two.example:443#LTE-two"), ETag: `"v2"`},
	}}
	runtime := &recordingRuntime{}
	coordinator := testRefreshCoordinator(t, database, fetcher, runtime)
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err != nil {
		t.Fatalf("initial RefreshOne() error = %v", err)
	}
	runtime.err = errors.New("runtime detail that must not be persisted")
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err == nil || strings.Contains(err.Error(), "runtime detail") {
		t.Fatalf("failed RefreshOne() error = %v", err)
	}
	current, err := NewRepository(database).Get(ctx, "sub-a")
	if err != nil || current.ActiveVersionID != "version-1" {
		t.Fatalf("active subscription after failure = %+v, %v", current, err)
	}
	failed, err := NewVersionRepository(database).Get(ctx, "version-2")
	if err != nil || failed.State != VersionFailed || failed.Error != RefreshRuntimeRejected {
		t.Fatalf("failed version = %+v, %v", failed, err)
	}
	state, err := NewRefreshRepository(database).Get(ctx, "sub-a")
	if err != nil || state.ConsecutiveFailures != 1 || state.LastErrorCode != RefreshRuntimeRejected || state.ETag != `"v1"` {
		t.Fatalf("refresh failure state = %+v, %v", state, err)
	}
}

func TestRefreshCoordinatorRollsRuntimeBackWhenDatabaseActivationIsCanceled(t *testing.T) {
	baseContext, database := migratedDatabase(t)
	createRefreshableSubscription(t, baseContext, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one")}}}
	ctx, cancel := context.WithCancel(baseContext)
	rollback := &recordingRollback{}
	runtime := &recordingRuntime{onPromote: cancel, rollback: rollback}
	coordinator := testRefreshCoordinator(t, database, fetcher, runtime)
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err == nil {
		t.Fatal("RefreshOne(canceled activation) error = nil")
	}
	if rollback.calls != 1 {
		t.Fatalf("rollback calls = %d, want 1", rollback.calls)
	}
	failed, err := NewVersionRepository(database).Get(baseContext, "version-1")
	if err != nil || failed.State != VersionFailed || failed.Error != RefreshActivateFailed {
		t.Fatalf("failed canceled version = %+v, %v", failed, err)
	}
	state, err := NewRefreshRepository(database).Get(baseContext, "sub-a")
	if err != nil || state.LeaseOwner != "" || state.LastErrorCode != RefreshActivateFailed {
		t.Fatalf("state after cancellation = %+v, %v", state, err)
	}
}

func TestRefreshCoordinatorCompensatesLKGWhenPromotionCommitFails(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{
		{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one")},
		{Payload: []byte("vless://22222222-2222-2222-2222-222222222222@two.example:443#LTE-two")},
	}}
	runtime := &recordingRuntime{}
	coordinator := testRefreshCoordinator(t, database, fetcher, runtime)
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err != nil {
		t.Fatal(err)
	}
	secondPromotion := &recordingRollback{commitErr: errors.New("evidence write failed")}
	runtime.rollback = secondPromotion
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err == nil || !strings.Contains(err.Error(), RefreshRuntimeCommit) {
		t.Fatalf("RefreshOne(commit failure) error = %v", err)
	}
	current, err := NewRepository(database).Get(ctx, "sub-a")
	if err != nil || current.ActiveVersionID != "version-1" {
		t.Fatalf("active subscription after commit failure = %+v, %v", current, err)
	}
	failed, err := NewVersionRepository(database).Get(ctx, "version-2")
	if err != nil || failed.State != VersionFailed || failed.Error != RefreshRuntimeCommit || secondPromotion.commits != 1 || secondPromotion.calls != 1 {
		t.Fatalf("commit-failed version=%+v error=%v promotion=%+v", failed, err, secondPromotion)
	}
}

func TestRefreshCoordinatorCompensatesSQLiteEvenWhenRuntimeRollbackReportsFailure(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{
		{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one")},
		{Payload: []byte("vless://22222222-2222-2222-2222-222222222222@two.example:443#LTE-two")},
	}}
	runtime := &recordingRuntime{}
	coordinator := testRefreshCoordinator(t, database, fetcher, runtime)
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err != nil {
		t.Fatal(err)
	}
	secondPromotion := &recordingRollback{commitErr: errors.New("evidence write failed"), rollbackErr: errors.New("runtime stayed fail-closed")}
	runtime.rollback = secondPromotion
	if _, err := coordinator.RefreshOne(ctx, "sub-a", true); err == nil || !strings.Contains(err.Error(), RefreshRollbackFailed) {
		t.Fatalf("RefreshOne(rollback report) error = %v", err)
	}
	current, err := NewRepository(database).Get(ctx, "sub-a")
	if err != nil || current.ActiveVersionID != "version-1" {
		t.Fatalf("active subscription after reported rollback failure = %+v, %v", current, err)
	}
	failed, err := NewVersionRepository(database).Get(ctx, "version-2")
	if err != nil || failed.State != VersionFailed || failed.Error != RefreshRuntimeCommit {
		t.Fatalf("compensated version after rollback report = %+v, %v", failed, err)
	}
}

func testRefreshCoordinator(t *testing.T, database *sql.DB, fetcher SubscriptionFetcher, runtime CandidateRuntime) *RefreshCoordinator {
	t.Helper()
	coordinator := NewRefreshCoordinator(
		NewRepository(database),
		NewVersionRepository(database),
		NewMatcherRepository(database),
		NewRefreshRepository(database),
		fetcher,
		staticSourceURLReader{value: "https://provider.example/sub?token=secret"},
		runtime,
		filepath.Join(t.TempDir(), "subscriptions"),
	)
	fixed := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	coordinator.now = func() time.Time { return fixed }
	coordinator.Refresh.now = coordinator.now
	coordinator.random = func() float64 { return 0.5 }
	counts := map[string]int{}
	coordinator.newID = func(prefix string) (string, error) {
		counts[prefix]++
		return prefix + "-" + strconv.Itoa(counts[prefix]), nil
	}
	return coordinator
}
