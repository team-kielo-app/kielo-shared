package llm

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type forbiddenTransport struct {
	t     *testing.T
	calls int
}

func (f *forbiddenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls++
	return nil, errors.New("network must not be reached")
}

func prodDefaultProvider(tr *forbiddenTransport) *GeminiJSONProvider {
	return NewGeminiJSONProvider("fake-key", &http.Client{Transport: tr})
}

func TestGeminiRefusesPaidCallOutsideProductionByDefault(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("LLM_ALLOW_PAID_CALLS", "")
	tr := &forbiddenTransport{t: t}
	_, err := prodDefaultProvider(tr).Generate(context.Background(), Request{Prompt: "hi", Task: "t"})
	if !errors.Is(err, ErrPaidCallRefused) {
		t.Fatalf("want ErrPaidCallRefused, got %v", err)
	}
	if tr.calls != 0 {
		t.Fatalf("network was reached %d times", tr.calls)
	}
}

func TestGeminiHourlyCapRefusesBeyondLimit(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("LLM_ALLOW_PAID_CALLS", "true")
	t.Setenv("LLM_HOURLY_CALL_CAP", "2")
	guardMu.Lock()
	guardWindow, guardCalls = time.Time{}, 0
	guardNow = func() time.Time { return time.Date(2026, 10, 3, 10, 5, 0, 0, time.UTC) }
	guardMu.Unlock()
	defer func() { guardMu.Lock(); guardNow = time.Now; guardMu.Unlock() }()

	tr := &forbiddenTransport{t: t}
	p := prodDefaultProvider(tr)
	for i := 0; i < 2; i++ {
		if _, err := p.Generate(context.Background(), Request{Prompt: "hi"}); errors.Is(err, ErrPaidCallRefused) {
			t.Fatalf("call %d refused too early: %v", i, err)
		}
	}
	if _, err := p.Generate(context.Background(), Request{Prompt: "hi"}); !errors.Is(err, ErrPaidCallRefused) {
		t.Fatalf("third call should be refused, got %v", err)
	}
}

func TestGeminiProductionIsUnrestrictedByDefault(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("LLM_ALLOW_PAID_CALLS", "")
	t.Setenv("LLM_HOURLY_CALL_CAP", "")
	if err := admitPaidCall("t", "p"); err != nil {
		t.Fatalf("production must not be refused: %v", err)
	}
}
