package pubsubutil

import (
	"context"

	sharedDB "github.com/team-kielo-app/kielo-shared/db"
	"github.com/team-kielo-app/kielo-shared/locale"
)

// LanguageAttribute is the canonical Pub/Sub message attribute name used
// to propagate the active learning language from publishers to consumers.
// Keep in sync with the Python kielo_shared equivalent and the
// X-Kielo-Learning-Language HTTP header.
const LanguageAttribute = "learning_language_code"

// EventTypeAttribute is the canonical attribute name carrying the event
// type discriminator (e.g. "user.profile.updated.v1") used by every
// Kielo subscriber to route inbound messages.
const EventTypeAttribute = "event_type"

// InjectLanguageAttribute stamps the active learning language from ctx
// onto the attributes map. No-op when ctx has no language. Existing
// values for the language attribute are preserved so per-call overrides
// (admin tooling) survive.
//
// Usage:
//
//	attrs := map[string]string{pubsubutil.EventTypeAttribute: "user.profile.updated.v1"}
//	pubsubutil.InjectLanguageAttribute(attrs, ctx)
//	topic.Publish(ctx, &pubsub.Message{Data: data, Attributes: attrs})
func InjectLanguageAttribute(attrs map[string]string, ctx context.Context) {
	if attrs == nil {
		return
	}
	if _, exists := attrs[LanguageAttribute]; exists {
		return
	}
	if lang, ok := sharedDB.LanguageFromContext(ctx); ok {
		attrs[LanguageAttribute] = lang
	}
}

// EventAttributes builds a fresh attributes map carrying event_type and,
// when ctx has an active learning language, the language attribute.
// Pass an empty eventType to skip the event_type stamp (e.g. when the
// caller's contract doesn't require it, like the content-service
// jobqueue Enqueue path).
//
// This is the standard recipe every Kielo publisher should call:
//
//	msg := &pubsub.Message{
//	    Data:       payloadBytes,
//	    Attributes: pubsubutil.EventAttributes(ctx, "user.profile.updated.v1"),
//	}
//
// Returns nil when both event_type and the ctx language are absent so
// publishers that produce attribute-free messages (legacy job queues)
// don't have to special-case the empty-map result.
func EventAttributes(ctx context.Context, eventType string) map[string]string {
	lang, hasLang := sharedDB.LanguageFromContext(ctx)
	attrs := make(map[string]string, 4)
	if eventType != "" {
		attrs[EventTypeAttribute] = eventType
	}
	if hasLang {
		attrs[LanguageAttribute] = lang
	}
	InjectTraceAttributes(attrs, ctx)
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// LanguageFromAttributes returns the publisher-attached
// learning_language_code, or "" if the attribute is missing or empty.
// Subscribers use this to re-establish per-language search_path on
// their own DB transactions via sharedDB.WithLanguage.
func LanguageFromAttributes(attrs map[string]string) string {
	if attrs == nil {
		return ""
	}
	return locale.NormalizeSupportedLearningLanguageCode(attrs[LanguageAttribute])
}

// WithLanguageFromAttributes is the canonical subscriber recipe: extract
// learning_language_code from a Pub/Sub message's attributes and apply
// it to ctx via sharedDB.WithLanguage so downstream DB transactions
// scope to the correct per-language schema. No-op when the attribute
// is missing or invalid (resolver's legacy fallback applies).
//
// Replaces verbatim activeLanguageFromAttributes /
// scopeActiveLanguageFromAttributes helpers that lived in every
// subscriber's pubsub_handler.go.
func WithLanguageFromAttributes(ctx context.Context, attrs map[string]string) context.Context {
	lang := LanguageFromAttributes(attrs)
	if lang == "" {
		return ctx
	}
	return sharedDB.WithLanguage(ctx, lang)
}
