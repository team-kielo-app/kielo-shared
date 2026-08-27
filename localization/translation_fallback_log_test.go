package localization

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// captureLog collects everything the standard logger writes during fn.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()

	var buf bytes.Buffer
	origW := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origW)
		log.SetFlags(origFlags)
	})

	fn()
	return buf.String()
}

// The leading fields are a parsing contract, not cosmetics: log-based metrics
// and alerts match on them, and the Prometheus counter this line replaced went
// to nobody after the sidecar retirement. A cause must therefore be APPENDED,
// never inserted — reordering silently breaks every consumer.
func TestLogTranslationFallback_CauseIsAppendedAfterTheStableFields(t *testing.T) {
	out := captureLog(t, func() {
		logTranslationFallback("provider_error", "scenario.description", "batch", "fi", 24,
			"provider_call: 503 upstream unavailable")
	})

	line := strings.TrimSpace(out)
	prefix := "[translation-fallback] source=provider_error namespace=scenario.description source_id=batch target=fi count=24"
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("stable field prefix changed — log-based metrics parse this.\n got: %q\nwant prefix: %q", line, prefix)
	}
	if !strings.Contains(line, `cause="provider_call: 503 upstream unavailable"`) {
		t.Errorf("cause missing or unquoted: %q", line)
	}
	if strings.Count(line, "\n") != 0 {
		t.Errorf("entry must stay one line: %q", line)
	}
}

// An absent cause must leave the line byte-identical to the old format, so
// existing dashboards keep working for the paths that have no error to report.
func TestLogTranslationFallback_NoCauseKeepsTheOriginalFormat(t *testing.T) {
	out := captureLog(t, func() {
		logTranslationFallback("guard_rejected", "scenario.title", "abc123", "vi", 1, "")
	})

	line := strings.TrimSpace(out)
	want := "[translation-fallback] source=guard_rejected namespace=scenario.title source_id=abc123 target=vi count=1"
	if line != want {
		t.Fatalf("no-cause format drifted.\n got: %q\nwant: %q", line, want)
	}
	if strings.Contains(line, "cause=") {
		t.Error("empty cause must be omitted entirely, not logged as cause=\"\"")
	}
}

// A provider error can echo its prompt back in the message. Logging %v
// unbounded would spill source content into logs, so the cause is capped.
func TestLogTranslationFallback_CauseIsBounded(t *testing.T) {
	huge := strings.Repeat("s", 5000)
	out := captureLog(t, func() {
		logTranslationFallback("provider_error", "ns", "id", "fi", 1, huge)
	})

	line := strings.TrimSpace(out)
	if len(line) > 600 {
		t.Fatalf("line is %d chars — the cause is not being truncated", len(line))
	}
	if !strings.Contains(line, "...(truncated)") {
		t.Error("truncation must be visible so nobody reads a clipped cause as complete")
	}
}

// Multi-byte causes must not be cut mid-rune into invalid UTF-8.
func TestLogTranslationFallback_TruncationIsRuneSafe(t *testing.T) {
	out := captureLog(t, func() {
		logTranslationFallback("provider_error", "ns", "id", "ja", 1, strings.Repeat("日本語", 500))
	})

	line := strings.TrimSpace(out)
	if !strings.Contains(line, "...(truncated)") {
		t.Fatal("expected truncation")
	}
	if strings.ContainsRune(line, '�') {
		t.Error("truncation split a multi-byte rune, producing invalid UTF-8")
	}
}
