package metrics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
)

func TestClassifyExternalAPIFailure(t *testing.T) {
	cases := []struct {
		name   string
		status int
		msg    string
		class  string
		want   string
	}{
		{"402 is quota", 402, "", "", ExternalAPIKindQuota},
		{"429 quota body", 429, `{"error":{"message":"You exceeded your current quota"}}`, "", ExternalAPIKindQuota},
		{"gemini resource exhausted", 429, "429 RESOURCE_EXHAUSTED", "", ExternalAPIKindQuota},
		{"deepgram insufficient credits", 402, "PROJECT_BALANCE_INSUFFICIENT", "", ExternalAPIKindQuota},
		{"bare 429", 429, "too many requests", "", ExternalAPIKindRateLimit},
		{"401", 401, "", "", ExternalAPIKindAuth},
		{"403 forbidden text", 0, "revenuecat API error: status 403, body: forbidden", "", ExternalAPIKindAuth},
		{"seam timeout class", 0, "", "timeout", ExternalAPIKindTimeout},
		{"transport timeout text", 0, "Post \"https://x\": context deadline exceeded", "", ExternalAPIKindTimeout},
		{"dial error", 0, "dial tcp: lookup api.deepgram.com: no such host", "", ExternalAPIKindConnection},
		{"5xx", 503, "", "", ExternalAPIKindServer},
		{"seam 5xx class", 0, "", "http_5xx", ExternalAPIKindServer},
		{"4xx", 422, "", "", ExternalAPIKindClient},
		{"unknown", 0, "", "", ExternalAPIKindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyExternalAPIFailure(tc.status, tc.msg, tc.class); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestExternalAPIFailureEmitWritesCanonicalLine(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	SetServiceName("kielo-user-service")

	ExternalAPIFailureEmit(context.Background(), ExternalAPIFailure{
		Provider:  "revenuecat",
		Operation: "get_subscriber",
		Status:    401,
		Detail:    "invalid\nkey",
	})

	line := buf.String()
	for _, want := range []string{
		ExternalAPIFailureLogToken,
		"provider=revenuecat",
		"operation=get_subscriber",
		"kind=auth",
		"status=401",
		"service=kielo-user-service",
		"level=WARN",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line missing %q: %s", want, line)
		}
	}
	if strings.Contains(line, "invalid\nkey") {
		t.Fatalf("newline should be flattened: %q", line)
	}
}

func TestExternalAPIFailureEmitClassifiesDeadlineExceeded(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ExternalAPIFailureEmit(context.Background(), ExternalAPIFailure{
		Provider:  "expo_push",
		Operation: "send",
		Err:       errors.Join(context.DeadlineExceeded),
	})
	if !strings.Contains(buf.String(), "kind=timeout") {
		t.Fatalf("expected kind=timeout: %s", buf.String())
	}
}

func TestExternalAPIFailureEmitSkipsCallerCancellation(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ExternalAPIFailureEmit(context.Background(), ExternalAPIFailure{
		Provider:   "deepgram",
		Operation:  "stt.prerecorded",
		ErrorClass: "connection",
		Err:        &url.Error{Op: "Post", URL: "https://api.deepgram.com/v1/listen", Err: context.Canceled},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ExternalAPIFailureEmit(ctx, ExternalAPIFailure{
		Provider:  "deepgram",
		Operation: "stt.prerecorded",
		Err:       errors.New("read: connection reset by peer"),
	})
	if strings.Contains(buf.String(), ExternalAPIFailureLogToken) {
		t.Fatalf("a call the caller canceled must not be recorded: %s", buf.String())
	}

	ExternalAPIFailureEmit(ctx, ExternalAPIFailure{Provider: "deepgram", Operation: "stt.prerecorded", Status: 503})
	if !strings.Contains(buf.String(), "kind=server") {
		t.Fatalf("a provider response is recorded even after cancellation: %s", buf.String())
	}
}
