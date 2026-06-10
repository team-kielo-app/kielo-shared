// Package localization mirrors the Python kielo_shared.localization
// abstraction in Go. Phase C6 ships the contract types + registry surface
// only — concrete providers (OpenAI, Gemini, OpusMT) are added per-service
// when a Go translation surface lands.
//
// Mirroring the Python side keeps cross-service caching coherent: both
// sides hash cache keys with the same recipe (provider_id|src|tgt|role|sha256).
package localization

import "context"

// TranslationRole gates per-role behavior in providers (prompt selection,
// validators, cache scoping).
type TranslationRole string

const (
	// RolePlain is natural prose. Preserve learner-language tokens (e.g.
	// Finnish words inside an English context).
	RolePlain TranslationRole = "plain"

	// RoleGloss is short glossary. Output target language only; preserve
	// list separators (slashes, semicolons, commas).
	RoleGloss TranslationRole = "gloss"

	// RoleHTML is HTML content. Preserve all tags and attributes; only
	// translate visible text.
	RoleHTML TranslationRole = "html"
)

// LocalizationFieldStatus enumerates the readiness states a lazily-localized
// field can report to API clients.
type LocalizationFieldStatus string

const (
	// LocalizationPending means the accompanying text is a temporary
	// source-locale fallback and a background translation has been dispatched.
	// The client should render a loading/skeleton state and re-request the
	// resource; a subsequent fetch returns the localized text with the status
	// object absent (= ready).
	LocalizationPending LocalizationFieldStatus = "pending"

	// LocalizationReady means the text is final. Normally signaled implicitly
	// by the ABSENCE of the status object; producers may set it explicitly
	// when an unambiguous positive signal is preferred.
	LocalizationReady LocalizationFieldStatus = "ready"
)

// LocalizationStatus is the shared API-contract type signaling per-field
// localization readiness for lazily-translated content (scenario
// descriptions, roadmap-lesson copy, ...). It rides alongside the localized
// field and is OMITTED (json omitempty on a pointer) when the field is final
// — cache hit, no translation needed, or no fill dispatched — so a missing
// object means "ready" and pre-existing clients that ignore the field keep
// rendering the source text (no breaking change).
//
// Defined once here so the generated SDK emits a single reused
// `#/components/schemas/LocalizationStatus` component across every service
// and surface — type safety + consistent coverage rather than a per-endpoint
// inline shape. New lazy-localized responses embed *LocalizationStatus on the
// item that carries the translatable field.
type LocalizationStatus struct {
	Status LocalizationFieldStatus `json:"status"`
	Locale string                  `json:"locale,omitempty"`
}

// TranslationItem is one input to translate.
type TranslationItem struct {
	Text     string          `json:"text"`
	Role     TranslationRole `json:"role,omitempty"`
	CacheKey string          `json:"cache_key,omitempty"`
	Context  map[string]any  `json:"context,omitempty"`
}

// TranslationResult is one translated output. Mirrors the Python dataclass.
type TranslationResult struct {
	Text          string         `json:"text"`
	Provider      string         `json:"provider"`
	Cached        bool           `json:"cached"`
	LatencyMs     int            `json:"latency_ms"`
	Confidence    *float64       `json:"confidence,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// Provider is the single contract for a localization backend. Decorators
// also implement this interface so the stack composes the same way as in
// the Python package.
type Provider interface {
	// ProviderID returns a stable id including a version stamp; used in
	// logs, telemetry, and as part of the cache key namespace.
	ProviderID() string

	// TranslateBatch translates the items in order. Result length must
	// match input length. Per-item failure is allowed (provider returns a
	// passthrough); whole-batch failure must return an error.
	TranslateBatch(
		ctx context.Context,
		items []TranslationItem,
		opts TranslateOptions,
	) ([]TranslationResult, error)
}

// TranslateOptions carries per-call routing context.
type TranslateOptions struct {
	SourceLocale   string
	TargetLocale   string
	IdempotencyKey string
}
