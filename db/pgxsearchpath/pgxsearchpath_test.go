package pgxsearchpath

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
)

// recordingTx implements pgx.Tx just enough to capture the SET LOCAL
// search_path query without spinning up postgres. Every other method
// panics on purpose — the helper must only call Exec.
type recordingTx struct {
	queries []string
	execErr error
}

func (r *recordingTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	r.queries = append(r.queries, sql)
	return pgconn.CommandTag{}, r.execErr
}

func (r *recordingTx) Begin(_ context.Context) (pgx.Tx, error) {
	panic("recordingTx.Begin must not be called")
}
func (r *recordingTx) Commit(_ context.Context) error {
	panic("recordingTx.Commit must not be called")
}
func (r *recordingTx) Rollback(_ context.Context) error {
	panic("recordingTx.Rollback must not be called")
}
func (r *recordingTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, _ pgx.CopyFromSource) (int64, error) {
	panic("recordingTx.CopyFrom must not be called")
}
func (r *recordingTx) SendBatch(_ context.Context, _ *pgx.Batch) pgx.BatchResults {
	panic("recordingTx.SendBatch must not be called")
}
func (r *recordingTx) LargeObjects() pgx.LargeObjects {
	panic("recordingTx.LargeObjects must not be called")
}
func (r *recordingTx) Prepare(_ context.Context, _, _ string) (*pgconn.StatementDescription, error) {
	panic("recordingTx.Prepare must not be called")
}
func (r *recordingTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	panic("recordingTx.Query must not be called")
}
func (r *recordingTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	panic("recordingTx.QueryRow must not be called")
}
func (r *recordingTx) Conn() *pgx.Conn {
	panic("recordingTx.Conn must not be called")
}

func TestApply_IssuesSetLocalWhenLanguageInContext(t *testing.T) {
	tx := &recordingTx{}
	ctx := sharedDB.WithLanguage(context.Background(), "sv")

	err := Apply(ctx, tx)
	require.NoError(t, err)
	require.Len(t, tx.queries, 1)
	assert.Equal(t,
		"SET LOCAL search_path TO klearn_sv,cms_sv,klearn,cms,users,localization,communications,convo,media,public",
		tx.queries[0],
	)
}

func TestApply_NoOpWithoutLanguageInContext(t *testing.T) {
	tx := &recordingTx{}
	err := Apply(context.Background(), tx)
	assert.NoError(t, err)
	assert.Empty(t, tx.queries, "no SET LOCAL should be issued without an active language")
}

func TestApply_PropagatesExecError(t *testing.T) {
	wantErr := errors.New("boom")
	tx := &recordingTx{execErr: wantErr}
	ctx := sharedDB.WithLanguage(context.Background(), "vi")

	err := Apply(ctx, tx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// stubBeginner is the test double for TxBeginner. It returns the
// pre-baked tx and tracks how many times Begin was called.
type stubBeginner struct {
	tx       pgx.Tx
	beginErr error
	calls    int
}

func (s *stubBeginner) Begin(_ context.Context) (pgx.Tx, error) {
	s.calls++
	return s.tx, s.beginErr
}

// trackingTx records lifecycle calls (Commit / Rollback) so tests can
// assert the helper's commit/rollback decisions are correct.
type trackingTx struct {
	recordingTx
	committed  bool
	rolledBack bool
	commitErr  error
}

func (t *trackingTx) Commit(_ context.Context) error {
	t.committed = true
	return t.commitErr
}
func (t *trackingTx) Rollback(_ context.Context) error {
	t.rolledBack = true
	return nil
}

func TestWithReadTx_RollsBackEvenOnSuccess(t *testing.T) {
	tx := &trackingTx{}
	beginner := &stubBeginner{tx: tx}
	ctx := sharedDB.WithLanguage(context.Background(), "sv")

	calls := 0
	err := WithReadTx(ctx, beginner, func(_ pgx.Tx) error {
		calls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "fn should run exactly once")
	assert.True(t, tx.rolledBack, "read tx must always rollback")
	assert.False(t, tx.committed, "read tx must never commit")
	// Apply was issued so search_path is set inside the tx scope.
	require.Len(t, tx.queries, 1)
}

func TestWithReadTx_PropagatesFnError(t *testing.T) {
	tx := &trackingTx{}
	beginner := &stubBeginner{tx: tx}
	ctx := sharedDB.WithLanguage(context.Background(), "fi")
	wantErr := errors.New("query failed")

	err := WithReadTx(ctx, beginner, func(_ pgx.Tx) error {
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr, "fn error should propagate verbatim")
	assert.True(t, tx.rolledBack)
}

func TestWithReadTx_PropagatesBeginError(t *testing.T) {
	wantErr := errors.New("connection lost")
	beginner := &stubBeginner{beginErr: wantErr}

	err := WithReadTx(context.Background(), beginner, func(_ pgx.Tx) error {
		t.Fatalf("fn must not run when begin fails")
		return nil
	})
	assert.ErrorIs(t, err, wantErr)
}

func TestWithTx_CommitsOnSuccess(t *testing.T) {
	tx := &trackingTx{}
	beginner := &stubBeginner{tx: tx}
	ctx := sharedDB.WithLanguage(context.Background(), "sv")

	err := WithTx(ctx, beginner, func(_ pgx.Tx) error {
		return nil
	})
	require.NoError(t, err)
	assert.True(t, tx.committed, "successful fn should commit")
	assert.False(t, tx.rolledBack, "successful commit should not also rollback")
}

func TestWithTx_RollsBackOnFnError(t *testing.T) {
	tx := &trackingTx{}
	beginner := &stubBeginner{tx: tx}
	ctx := sharedDB.WithLanguage(context.Background(), "fi")
	wantErr := errors.New("write conflict")

	err := WithTx(ctx, beginner, func(_ pgx.Tx) error {
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr)
	assert.True(t, tx.rolledBack, "fn error must trigger rollback")
	assert.False(t, tx.committed)
}

func TestWithTx_WrapsCommitError(t *testing.T) {
	commitErr := errors.New("commit failed")
	tx := &trackingTx{commitErr: commitErr}
	beginner := &stubBeginner{tx: tx}
	ctx := sharedDB.WithLanguage(context.Background(), "vi")

	err := WithTx(ctx, beginner, func(_ pgx.Tx) error {
		return nil
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, commitErr)
	// trackingTx records Commit was attempted; the deferred rollback
	// fires because committed=false at that point.
	assert.True(t, tx.committed)
	assert.True(t, tx.rolledBack)
}

func TestWithTx_AppliesSearchPathBeforeFn(t *testing.T) {
	// Ordering guarantee: Apply must run before fn so all queries
	// inside fn see the per-language search_path. Verified by checking
	// the recorded query order and that fn observes the tx with the
	// SET LOCAL already issued.
	tx := &trackingTx{}
	beginner := &stubBeginner{tx: tx}
	ctx := sharedDB.WithLanguage(context.Background(), "sv")

	var queryCountWhenFnRan int
	err := WithTx(ctx, beginner, func(_ pgx.Tx) error {
		queryCountWhenFnRan = len(tx.queries)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, queryCountWhenFnRan, "Apply (SET LOCAL) must precede fn")
}

func TestWithReadTx_NoLanguage_NoApplyIssued(t *testing.T) {
	// Without an active language, Apply is a no-op so no SET LOCAL is
	// issued. fn still runs and the tx still rolls back — useful for
	// background workers that haven't opted into per-language scoping.
	tx := &trackingTx{}
	beginner := &stubBeginner{tx: tx}

	called := false
	err := WithReadTx(context.Background(), beginner, func(_ pgx.Tx) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
	assert.Empty(t, tx.queries, "no SET LOCAL when ctx has no language")
	assert.True(t, tx.rolledBack)
}
