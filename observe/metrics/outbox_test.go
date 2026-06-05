package metrics

import (
	"errors"
	"testing"
)

// Sweep FH.4 Phase 3 (2026-06-05): regression tests for the
// admin-action outbox error classifier. Pins the classifier
// invariants so the metric cardinality budget stays bounded
// (drainer can't produce unbounded error_class label values).

func TestClassifyAdminActionOutboxError_NilReturnsEmpty(t *testing.T) {
	if got := ClassifyAdminActionOutboxError(nil); got != "" {
		t.Errorf("expected empty string for nil error, got %q", got)
	}
}

func TestClassifyAdminActionOutboxError_TimeoutClass(t *testing.T) {
	cases := []string{
		"context deadline exceeded",
		"rpc error: code = DeadlineExceeded desc = ...",
		"dial tcp 10.0.0.1:8085: i/o timeout",
	}
	for _, msg := range cases {
		t.Run(msg, func(t *testing.T) {
			err := errors.New(msg)
			if got := ClassifyAdminActionOutboxError(err); got != AdminActionOutboxErrorClassPublishTimeout {
				t.Errorf("expected %q, got %q", AdminActionOutboxErrorClassPublishTimeout, got)
			}
		})
	}
}

func TestClassifyAdminActionOutboxError_UnavailableClass(t *testing.T) {
	cases := []string{
		"rpc error: code = Unavailable desc = ...",
		"dial tcp 10.0.0.1:8085: connect: connection refused",
		"lookup pubsub.googleapis.com: no such host",
	}
	for _, msg := range cases {
		t.Run(msg, func(t *testing.T) {
			err := errors.New(msg)
			if got := ClassifyAdminActionOutboxError(err); got != AdminActionOutboxErrorClassPublishUnavailable {
				t.Errorf("expected %q, got %q", AdminActionOutboxErrorClassPublishUnavailable, got)
			}
		})
	}
}

func TestClassifyAdminActionOutboxError_MarshalClass(t *testing.T) {
	cases := []string{
		"failed to marshal event payload",
		"json: cannot unmarshal string into Go struct field",
		"encode admin subscription grant",
	}
	for _, msg := range cases {
		t.Run(msg, func(t *testing.T) {
			err := errors.New(msg)
			if got := ClassifyAdminActionOutboxError(err); got != AdminActionOutboxErrorClassMarshalError {
				t.Errorf("expected %q, got %q", AdminActionOutboxErrorClassMarshalError, got)
			}
		})
	}
}

func TestClassifyAdminActionOutboxError_PermissionDeniedClass(t *testing.T) {
	cases := []string{
		"rpc error: code = PermissionDenied desc = ...",
		"rpc error: code = Unauthenticated desc = ...",
		"failed: permission denied for topic admin-actions",
	}
	for _, msg := range cases {
		t.Run(msg, func(t *testing.T) {
			err := errors.New(msg)
			if got := ClassifyAdminActionOutboxError(err); got != AdminActionOutboxErrorClassPermissionDenied {
				t.Errorf("expected %q, got %q", AdminActionOutboxErrorClassPermissionDenied, got)
			}
		})
	}
}

func TestClassifyAdminActionOutboxError_UnknownClass(t *testing.T) {
	// Errors that don't match any known prefix surface as "unknown".
	// This is the canonical signal that the classifier needs extension.
	err := errors.New("some unexpected error pattern that the classifier hasn't seen")
	if got := ClassifyAdminActionOutboxError(err); got != AdminActionOutboxErrorClassUnknown {
		t.Errorf("expected %q, got %q", AdminActionOutboxErrorClassUnknown, got)
	}
}

func TestAdminActionOutboxMetricsRegistered(t *testing.T) {
	// Smoke test: verify the 3 metrics are constructible + their
	// label sets are stable. Catches the case where a future PR
	// changes the metric name / label list silently.
	t.Run("UnprocessedTotal_HasTableLabel", func(t *testing.T) {
		gauge := AdminActionOutboxUnprocessedTotal.WithLabelValues(AdminActionOutboxTableUserService)
		if gauge == nil {
			t.Fatal("AdminActionOutboxUnprocessedTotal.WithLabelValues returned nil")
		}
		gauge.Set(42)
	})

	t.Run("PublishFailedTotal_Has3Labels", func(t *testing.T) {
		counter := AdminActionOutboxPublishFailedTotal.WithLabelValues(
			AdminActionOutboxTableUserService,
			"admin.broadcast.v1",
			AdminActionOutboxErrorClassPublishTimeout,
		)
		if counter == nil {
			t.Fatal("AdminActionOutboxPublishFailedTotal.WithLabelValues returned nil")
		}
		counter.Inc()
	})

	t.Run("RowAgeSeconds_HasTableAndOutcomeLabel", func(t *testing.T) {
		hist := AdminActionOutboxRowAgeSeconds.WithLabelValues(
			AdminActionOutboxTableCommunications,
			"processed",
		)
		if hist == nil {
			t.Fatal("AdminActionOutboxRowAgeSeconds.WithLabelValues returned nil")
		}
		hist.Observe(5.0)
	})
}

func TestAdminActionOutboxTableConstants_MatchSchemaNames(t *testing.T) {
	// Per FH.4 Phase 3 spec: the "table" label uses the canonical
	// schema-qualified name. Future schema renames must update both
	// the constant value AND the corresponding migration to keep
	// the metric label matching the actual table the gauge samples.
	cases := []struct {
		name     string
		got      string
		expected string
	}{
		{"UserService", AdminActionOutboxTableUserService, "users.admin_action_outbox"},
		{"Communications", AdminActionOutboxTableCommunications, "communications.admin_action_publish_outbox"},
	}
	for _, tc := range cases {
		if tc.got != tc.expected {
			t.Errorf("%s: expected table label %q, got %q", tc.name, tc.expected, tc.got)
		}
	}
}
