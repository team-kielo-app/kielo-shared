package pgxsearchpath

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRows is a minimal pgx.Rows implementation that yields a fixed
// slice of (code, is_active) tuples. Languages helper only reads code
// — the activity filter is applied in SQL — but we still seed both
// fields so the test data mirrors what the real query returns.
type stubRows struct {
	codes   []string
	idx     int
	closed  bool
	scanErr error
	iterErr error
}

func (r *stubRows) Close()                                       { r.closed = true }
func (r *stubRows) Err() error                                   { return r.iterErr }
func (r *stubRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *stubRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *stubRows) Values() ([]any, error)                       { return nil, nil }
func (r *stubRows) RawValues() [][]byte                          { return nil }
func (r *stubRows) Conn() *pgx.Conn                              { return nil }

func (r *stubRows) Next() bool {
	if r.idx >= len(r.codes) {
		return false
	}
	r.idx++
	return true
}

func (r *stubRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if len(dest) != 1 {
		return errors.New("stubRows.Scan: expected exactly one dest")
	}
	ptr, ok := dest[0].(*string)
	if !ok {
		return errors.New("stubRows.Scan: dest[0] is not *string")
	}
	*ptr = r.codes[r.idx-1]
	return nil
}

// queryingTx is a pgx.Tx test double that returns a pre-baked Rows from
// Query and records the SQL it received. Its Exec returns no-op so the
// outer WithReadTx -> Apply path never fails.
type queryingTx struct {
	rows       *stubRows
	queryErr   error
	queries    []string
	rolledBack bool
}

func (t *queryingTx) Begin(_ context.Context) (pgx.Tx, error) { panic("not used") }
func (t *queryingTx) Commit(_ context.Context) error          { return nil }
func (t *queryingTx) Rollback(_ context.Context) error {
	t.rolledBack = true
	return nil
}
func (t *queryingTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, _ pgx.CopyFromSource) (int64, error) {
	panic("not used")
}
func (t *queryingTx) SendBatch(_ context.Context, _ *pgx.Batch) pgx.BatchResults {
	panic("not used")
}
func (t *queryingTx) LargeObjects() pgx.LargeObjects { panic("not used") }
func (t *queryingTx) Prepare(_ context.Context, _, _ string) (*pgconn.StatementDescription, error) {
	panic("not used")
}
func (t *queryingTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.queries = append(t.queries, sql)
	return pgconn.CommandTag{}, nil
}
func (t *queryingTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	t.queries = append(t.queries, sql)
	if t.queryErr != nil {
		return nil, t.queryErr
	}
	return t.rows, nil
}
func (t *queryingTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row { panic("not used") }
func (t *queryingTx) Conn() *pgx.Conn                                        { return nil }

// listLanguagesBeginner returns the same queryingTx for every Begin call
// so tests can inspect what happened on the tx after the helper ran.
type listLanguagesBeginner struct {
	tx       *queryingTx
	beginErr error
	calls    int
}

func (b *listLanguagesBeginner) Begin(_ context.Context) (pgx.Tx, error) {
	b.calls++
	if b.beginErr != nil {
		return nil, b.beginErr
	}
	return b.tx, nil
}

func TestListActiveLanguageCodes_ReturnsCodesInQueryOrder(t *testing.T) {
	// SQL ORDERs by code, so the helper itself doesn't sort — pin that
	// the slice it returns matches what the rows yielded, in order.
	rows := &stubRows{codes: []string{"fi", "sv", "vi"}}
	tx := &queryingTx{rows: rows}
	beginner := &listLanguagesBeginner{tx: tx}

	codes, err := ListActiveLanguageCodes(context.Background(), beginner)
	require.NoError(t, err)
	assert.Equal(t, []string{"fi", "sv", "vi"}, codes)
	assert.True(t, rows.closed, "rows must be closed after iteration")
}

func TestListActiveLanguageCodes_EmptyResultReturnsNilSlice(t *testing.T) {
	// is_active = FALSE filtering happens in SQL; the helper itself just
	// iterates whatever rows it receives. Empty rows -> nil/empty slice
	// without error.
	rows := &stubRows{codes: nil}
	tx := &queryingTx{rows: rows}
	beginner := &listLanguagesBeginner{tx: tx}

	codes, err := ListActiveLanguageCodes(context.Background(), beginner)
	require.NoError(t, err)
	assert.Empty(t, codes)
}

func TestListActiveLanguageCodes_QueryHasIsActiveFilterAndOrderBy(t *testing.T) {
	// Pin the SQL so changes to the WHERE/ORDER BY are caught: the
	// downstream contract (active-only, alphabetical) lives in the SQL
	// not in the Go code.
	rows := &stubRows{}
	tx := &queryingTx{rows: rows}
	beginner := &listLanguagesBeginner{tx: tx}

	_, err := ListActiveLanguageCodes(context.Background(), beginner)
	require.NoError(t, err)

	// queries[0] is the SET LOCAL search_path Apply issues IF a language
	// is on ctx; here ctx is bare so Apply is a no-op and the SELECT is
	// the only recorded query.
	require.Len(t, tx.queries, 1)
	assert.Contains(t, tx.queries[0], "FROM localization.languages")
	assert.Contains(t, tx.queries[0], "is_active = TRUE")
	assert.Contains(t, tx.queries[0], "ORDER BY code")
}

func TestListActiveLanguageCodes_RunsInsideReadTxRolledBack(t *testing.T) {
	// The helper opens a read tx via WithReadTx, which always rolls back.
	rows := &stubRows{codes: []string{"fi"}}
	tx := &queryingTx{rows: rows}
	beginner := &listLanguagesBeginner{tx: tx}

	_, err := ListActiveLanguageCodes(context.Background(), beginner)
	require.NoError(t, err)
	assert.Equal(t, 1, beginner.calls, "Begin should be called once")
	assert.True(t, tx.rolledBack, "read tx must always rollback")
}

func TestListActiveLanguageCodes_PropagatesQueryError(t *testing.T) {
	wantErr := errors.New("connection lost")
	tx := &queryingTx{queryErr: wantErr}
	beginner := &listLanguagesBeginner{tx: tx}

	codes, err := ListActiveLanguageCodes(context.Background(), beginner)
	assert.Nil(t, codes)
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestListActiveLanguageCodes_PropagatesBeginError(t *testing.T) {
	wantErr := errors.New("pool exhausted")
	beginner := &listLanguagesBeginner{beginErr: wantErr}

	codes, err := ListActiveLanguageCodes(context.Background(), beginner)
	assert.Nil(t, codes)
	assert.ErrorIs(t, err, wantErr)
}

func TestListActiveLanguageCodes_PropagatesScanError(t *testing.T) {
	scanErr := errors.New("bad scan")
	rows := &stubRows{codes: []string{"fi"}, scanErr: scanErr}
	tx := &queryingTx{rows: rows}
	beginner := &listLanguagesBeginner{tx: tx}

	codes, err := ListActiveLanguageCodes(context.Background(), beginner)
	assert.Nil(t, codes)
	assert.ErrorIs(t, err, scanErr)
}
