package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLanguageDefaultFallbackTotal_Increments(t *testing.T) {
	LanguageDefaultFallbackTotal.Reset()

	LanguageDefaultFallbackTotal.WithLabelValues("cms", "test_callsite").Inc()
	LanguageDefaultFallbackTotal.WithLabelValues("cms", "test_callsite").Inc()
	LanguageDefaultFallbackTotal.WithLabelValues("cms", "other").Inc()

	if got := testutil.ToFloat64(LanguageDefaultFallbackTotal.WithLabelValues("cms", "test_callsite")); got != 2 {
		t.Errorf("test_callsite count = %v, want 2", got)
	}
	if got := testutil.ToFloat64(LanguageDefaultFallbackTotal.WithLabelValues("cms", "other")); got != 1 {
		t.Errorf("other count = %v, want 1", got)
	}
}
