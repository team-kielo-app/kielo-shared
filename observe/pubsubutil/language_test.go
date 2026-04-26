package pubsubutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
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
	ctx := sharedDB.WithLanguage(context.Background(), "vi")
	got := EventAttributes(ctx, "purchase.confirmation.v1")
	assert.Equal(t, map[string]string{
		"event_type":             "purchase.confirmation.v1",
		"learning_language_code": "vi",
	}, got)
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
	assert.Empty(t, LanguageFromAttributes(map[string]string{"event_type": "x"}))
	assert.Empty(t, LanguageFromAttributes(nil))
}
