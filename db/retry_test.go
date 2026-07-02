package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsTransientLockError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"deadlock 40P01", &pgconn.PgError{Code: "40P01"}, true},
		{"serialization 40001", &pgconn.PgError{Code: "40001"}, true},
		{"unique violation 23505", &pgconn.PgError{Code: "23505"}, false},
		{"wrapped deadlock", fmt.Errorf("cascade: %w", &pgconn.PgError{Code: "40P01"}), true},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTransientLockError(tc.err); got != tc.want {
				t.Fatalf("IsTransientLockError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryOnDeadlock_RetriesThenSucceeds(t *testing.T) {
	calls := 0
	err := RetryOnDeadlock(context.Background(), func() error {
		calls++
		if calls < 3 {
			return &pgconn.PgError{Code: "40P01"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls (2 retries + success), got %d", calls)
	}
}

func TestRetryOnDeadlock_GivesUpAfterMaxRetries(t *testing.T) {
	calls := 0
	err := RetryOnDeadlock(context.Background(), func() error {
		calls++
		return &pgconn.PgError{Code: "40001"}
	})
	if !IsTransientLockError(err) {
		t.Fatalf("expected transient lock error returned, got %v", err)
	}
	// total attempts should be one more than the retry count
	if calls != deadlockRetries+1 {
		t.Fatalf("expected %d calls, got %d", deadlockRetries+1, calls)
	}
}

func TestRetryOnDeadlock_NonTransientReturnsImmediately(t *testing.T) {
	calls := 0
	sentinel := errors.New("fk violation")
	err := RetryOnDeadlock(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel returned, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retry on non-transient), got %d", calls)
	}
}

func TestRetryOnDeadlock_HonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := RetryOnDeadlock(ctx, func() error {
		calls++
		return &pgconn.PgError{Code: "40P01"}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// First fn() runs, then the backoff select observes the canceled ctx.
	if calls != 1 {
		t.Fatalf("expected 1 call before cancellation observed, got %d", calls)
	}
}

// fakeExecer drives ExecWithRetry without a real DB.
type fakeExecer struct {
	failsBeforeSuccess int
	calls              int
}

func (f *fakeExecer) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	f.calls++
	if f.calls <= f.failsBeforeSuccess {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "40P01"}
	}
	return pgconn.NewCommandTag("DELETE 1"), nil
}

func TestExecWithRetry_RetriesAndReturnsTag(t *testing.T) {
	fe := &fakeExecer{failsBeforeSuccess: 2}
	tag, err := ExecWithRetry(context.Background(), fe, "DELETE FROM t WHERE id = $1", 7)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if fe.calls != 3 {
		t.Fatalf("expected 3 Exec calls, got %d", fe.calls)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected RowsAffected 1, got %d", tag.RowsAffected())
	}
}
