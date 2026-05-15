package metricsprom

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func TestNew_RegistersCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := New(reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m == nil {
		t.Fatal("New returned nil")
	}

	// CounterVec is registered eagerly but the family only shows up in
	// Gather() once at least one labelset has been observed (prometheus
	// hides empty CounterVecs to keep /metrics output lean). Touch any
	// labelset, then verify the family is collected.
	m.Record(context.Background(), "test", "test", "test")

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var found *io_prometheus_client.MetricFamily
	for _, family := range families {
		if family.GetName() == CounterName {
			found = family
			break
		}
	}
	if found == nil {
		t.Fatalf("counter %q not registered", CounterName)
	}
}

func TestRecord_IncrementsLabelledCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := MustNew(reg)
	ctx := context.Background()

	m.Record(ctx, "article.title", "vi", "cache_hit")
	m.Record(ctx, "article.title", "vi", "cache_hit")
	m.Record(ctx, "article.title", "vi", "provider_call")
	m.Record(ctx, "article.title", "de", "cache_hit")
	// A different namespace so counterValue is exercised across the
	// full label space — not just the article.title row.
	m.Record(ctx, "scenario.title", "vi", "cache_hit")

	got := counterValue(t, reg, "article.title", "vi", "cache_hit")
	if got != 2 {
		t.Errorf("vi cache_hit count: got %v, want 2", got)
	}
	got = counterValue(t, reg, "article.title", "vi", "provider_call")
	if got != 1 {
		t.Errorf("vi provider_call count: got %v, want 1", got)
	}
	got = counterValue(t, reg, "article.title", "de", "cache_hit")
	if got != 1 {
		t.Errorf("de cache_hit count: got %v, want 1", got)
	}
	got = counterValue(t, reg, "scenario.title", "vi", "cache_hit")
	if got != 1 {
		t.Errorf("scenario.title vi cache_hit count: got %v, want 1", got)
	}
}

func TestRecord_NilReceiverDoesNotPanic(t *testing.T) {
	var m *Metrics
	// Calling Record on a nil receiver must be safe; some call sites
	// hold a *Metrics that hasn't been initialized yet.
	m.Record(context.Background(), "article.title", "vi", "cache_hit")
}

func TestNew_DuplicateRegistrationReusesExisting(t *testing.T) {
	reg := prometheus.NewRegistry()
	m1, err := New(reg)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	m2, err := New(reg)
	if err != nil {
		t.Fatalf("second New (same shape): %v", err)
	}

	// Both Metrics instances must write to the same counter family.
	// Different counters with the same name would have caused
	// registration to fail or split into two families.
	m1.Record(context.Background(), "article.title", "vi", "cache_hit")
	m2.Record(context.Background(), "article.title", "vi", "cache_hit")

	got := counterValue(t, reg, "article.title", "vi", "cache_hit")
	if got != 2 {
		t.Errorf("shared counter should accumulate to 2; got %v", got)
	}
}

func TestNew_NilRegistererStillWorks(t *testing.T) {
	// Some test environments pass a nil registerer (e.g. when running
	// the seam without prometheus wiring). Counter increments are
	// silently dropped — never panic.
	m, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	m.Record(context.Background(), "article.title", "vi", "cache_hit")
}

func TestLabelNames_HasExpectedShape(t *testing.T) {
	// Labels are positional in prometheus.WithLabelValues, so their
	// order is part of the public contract. Pin it.
	want := []string{"namespace", "target_locale", "source"}
	if len(LabelNames) != len(want) {
		t.Fatalf("LabelNames length: got %d want %d", len(LabelNames), len(want))
	}
	for i, w := range want {
		if LabelNames[i] != w {
			t.Errorf("LabelNames[%d]: got %q want %q", i, LabelNames[i], w)
		}
	}
}

// counterValue extracts the value of a specific (namespace, target_locale,
// source) counter from a registry. Returns 0 if the labelset doesn't
// exist. Tests pass labels positionally to match prometheus's own
// WithLabelValues convention.
func counterValue(t *testing.T, reg *prometheus.Registry, ns, target, source string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != CounterName {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := metric.GetLabel()
			if labelValue(labels, "namespace") == ns &&
				labelValue(labels, "target_locale") == target &&
				labelValue(labels, "source") == source {
				if c := metric.GetCounter(); c != nil {
					return c.GetValue()
				}
			}
		}
	}
	return 0
}

func labelValue(labels []*io_prometheus_client.LabelPair, name string) string {
	for _, lp := range labels {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func TestHelp_DocumentsAllSourceValues(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := MustNew(reg)
	m.Record(context.Background(), "x", "vi", "cache_hit") // touch so it gathers

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != CounterName {
			continue
		}
		help := family.GetHelp()
		// Each documented source value must appear in the help text
		// so dashboards / SRE docs don't drift from the code.
		required := []string{
			"english_passthrough",
			"override",
			"cache_hit",
			"cache_swr",
			"cache_miss_share",
			"provider_call",
			"provider_error",
		}
		for _, r := range required {
			if !strings.Contains(help, r) {
				t.Errorf("help text missing source value %q: %q", r, help)
			}
		}
	}
}
