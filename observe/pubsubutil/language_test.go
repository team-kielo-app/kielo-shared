package pubsubutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestEventAttributes_NoLanguageNoEventType(t *testing.T) {
	got := EventAttributes(context.Background(), "")
	assert.Nil(t, got, "expected nil when no event_type and no ctx language")
}

func TestEventAttributes_OnlyEventType(t *testing.T) {
	got := EventAttributes(context.Background(), "user.profile.updated.v1")
	assert.Equal(t, map[string]string{
		"event_type": "user.profile.updated.v1",
	}, got)
}

func TestEventAttributes_OnlyLanguage(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	got := EventAttributes(ctx, "")
	assert.Equal(t, map[string]string{
		"learning_language_code": "sv",
	}, got)
}

func TestEventAttributes_BothEventTypeAndLanguage(t *testing.T) {
	ctx := sharedDB.WithLanguage(context.Background(), "fi")
	got := EventAttributes(ctx, "purchase.confirmation.v1")
	assert.Equal(t, map[string]string{
		"event_type":             "purchase.confirmation.v1",
		"learning_language_code": "fi",
	}, got)
}

func TestEventAttributes_StampsTraceFromContext(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)
	got := EventAttributes(ctx, "user.profile.updated.v1")
	assert.Equal(t, "user.profile.updated.v1", got["event_type"])
	assert.Equal(t, tc.TraceID, got["trace_id"])
	assert.Equal(t, tc.SpanID, got["span_id"])
	if tc.RequestID != "" {
		assert.Equal(t, tc.RequestID, got["request_id"])
	}
}

func TestEventAttributes_StampsTraceWithLanguage(t *testing.T) {
	tc := observe.New()
	ctx := observe.WithContext(context.Background(), tc)
	ctx = sharedDB.WithLanguage(ctx, "fi")
	got := EventAttributes(ctx, "purchase.confirmation.v1")
	assert.Equal(t, "purchase.confirmation.v1", got["event_type"])
	assert.Equal(t, "fi", got["learning_language_code"])
	assert.Equal(t, tc.TraceID, got["trace_id"])
}

func TestEventAttributes_NoTraceWithoutContext(t *testing.T) {
	got := EventAttributes(context.Background(), "user.profile.updated.v1")
	_, hasTrace := got["trace_id"]
	assert.False(t, hasTrace)
}

func TestEventAttributes_DropsInvalidLanguage(t *testing.T) {
	// WithLanguage rejects malformed idents — they don't poison the
	// returned ctx, so EventAttributes sees no language.
	ctx := sharedDB.WithLanguage(context.Background(), "../etc/passwd")
	got := EventAttributes(ctx, "user.profile.updated.v1")
	assert.Equal(t, map[string]string{
		"event_type": "user.profile.updated.v1",
	}, got)
	_, hasLang := got["learning_language_code"]
	assert.False(t, hasLang)
}

func TestInjectLanguageAttribute_StampsFromContext(t *testing.T) {
	attrs := map[string]string{"event_type": "x"}
	ctx := sharedDB.WithLanguage(context.Background(), "fi")
	InjectLanguageAttribute(attrs, ctx)
	assert.Equal(t, "fi", attrs["learning_language_code"])
	assert.Equal(t, "x", attrs["event_type"])
}

func TestInjectLanguageAttribute_NoOpWithoutContext(t *testing.T) {
	attrs := map[string]string{"event_type": "x"}
	InjectLanguageAttribute(attrs, context.Background())
	_, exists := attrs["learning_language_code"]
	assert.False(t, exists)
}

func TestInjectLanguageAttribute_PreservesExistingValue(t *testing.T) {
	// Per-call override (admin tooling) must survive — Inject doesn't
	// clobber an explicit value already in the map.
	attrs := map[string]string{
		"event_type":             "x",
		"learning_language_code": "fi",
	}
	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	InjectLanguageAttribute(attrs, ctx)
	assert.Equal(t, "fi", attrs["learning_language_code"])
}

func TestInjectLanguageAttribute_NilMapIsNoOp(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	ctx := sharedDB.WithLanguage(context.Background(), "sv")
	InjectLanguageAttribute(nil, ctx)
}

func TestLanguageFromAttributes(t *testing.T) {
	assert.Equal(t, "sv", LanguageFromAttributes(map[string]string{"learning_language_code": "sv"}))
	assert.Empty(t, LanguageFromAttributes(map[string]string{"learning_language_code": "vi"}))
	assert.Empty(t, LanguageFromAttributes(map[string]string{"event_type": "x"}))
	assert.Empty(t, LanguageFromAttributes(nil))
}

func TestWithLanguageFromAttributes_AppliesValidLang(t *testing.T) {
	ctx := WithLanguageFromAttributes(context.Background(), map[string]string{"learning_language_code": "sv"})
	got, ok := sharedDB.LanguageFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "sv", got)
}

func TestWithLanguageFromAttributes_PassthroughOnEmpty(t *testing.T) {
	parent := context.Background()

	ctx := WithLanguageFromAttributes(parent, nil)
	_, ok := sharedDB.LanguageFromContext(ctx)
	assert.False(t, ok, "nil attrs must not apply a language")

	ctx = WithLanguageFromAttributes(parent, map[string]string{"event_type": "x"})
	_, ok = sharedDB.LanguageFromContext(ctx)
	assert.False(t, ok, "missing language attr must not apply a language")
}

func TestWithLanguageFromAttributes_PassthroughOnInvalidLang(t *testing.T) {
	// sharedDB.WithLanguage rejects malformed idents — the helper must
	// not poison ctx in that case.
	ctx := WithLanguageFromAttributes(context.Background(), map[string]string{"learning_language_code": "../etc/passwd"})
	_, ok := sharedDB.LanguageFromContext(ctx)
	assert.False(t, ok, "invalid lang must not be applied")
}

func TestWithLanguageFromAttributes_PassthroughOnUnsupportedLearningLanguage(t *testing.T) {
	ctx := WithLanguageFromAttributes(context.Background(), map[string]string{"learning_language_code": "vi"})
	_, ok := sharedDB.LanguageFromContext(ctx)
	assert.False(t, ok, "localization-only language must not be applied as active learning language")
}
