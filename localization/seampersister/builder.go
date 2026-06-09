package seampersister

import (
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/team-kielo-app/kielo-shared/localization"
	"github.com/team-kielo-app/kielo-shared/localization/cacheredis"
	"github.com/team-kielo-app/kielo-shared/localization/dynclient"
	"github.com/team-kielo-app/kielo-shared/localization/overridepgx"
	"github.com/team-kielo-app/kielo-shared/localization/translateprovider"
	sharedtranslation "github.com/team-kielo-app/kielo-shared/translation"
)

// SeamBuilderInputs collects the dependencies every Round 10D
// production seam needs. Pass to NewProductionSeam to get back a
// fully-wired *localization.Seam with persister + guard + cache +
// override-store + provider already configured.
//
// Round 10D foundation — collapses 8 lines of identical boilerplate
// per service main.go into one factory call. All four production
// services (kielo-user-service, kielo-content-service,
// kielo-communications-service, kielo-convo) wire the same Seam shape;
// the only per-service difference is which translation Client + which
// pgxpool + which Redis client they pass in.
type SeamBuilderInputs struct {
	// ModelsURL: the kielo-models internal URL (e.g.
	// "http://kielo-models:8080"). Pass through to the translation
	// Client constructor. Required.
	ModelsURL string

	// EngineURL: the kielolearn-engine internal URL (e.g.
	// "http://kielolearn-engine:8000"). Pass through to the
	// translation Client constructor. Required.
	EngineURL string

	// InternalAPIKey: the shared internal API key used by the
	// translation Client + dynclient.Client. Required.
	InternalAPIKey string

	// LocalizationServiceURL: the kielo-localization internal URL
	// (e.g. "http://kielo-localization:8080"). Required for the
	// dynclient.Client used by the persister.
	LocalizationServiceURL string

	// Redis: the redis client used for the seam's translation cache.
	// 7-day total cache TTL applied (24h fresh + 6d SWR). Required —
	// the seam will function without a cache (NoopCache) but
	// production traffic without cache hammers the LLM.
	Redis *redis.Client

	// DBPool: the pgxpool.Pool used for the seam's override store
	// (reads from localization.translations).
	DBPool *pgxpool.Pool

	// ProviderID: the canonical provider identifier under which the
	// translation provider registers (e.g. "kielo-models:ui-string-v1").
	// Used as the Redis cache key prefix; pick a stable string per
	// service so cross-service cache reuse stays predictable.
	// Required.
	ProviderID string

	// TranslatorSource: the translator_source value persisted to
	// localization.dynamic_translations rows the seam writes (e.g.
	// "seam_autotranslate_user"). Default "seam_autotranslate" when
	// empty.
	TranslatorSource string

	// Logger: structured logger for persister warnings. Defaults to
	// slog.Default() when nil.
	Logger *slog.Logger
}

// NewProductionSeam wires a fully-configured *localization.Seam for
// Round 10D production use. Returns nil when any required input is
// missing — callers should defensively fall back to disabling the
// dynamicregistry autotranslate path in that case:
//
//	seam := seampersister.NewProductionSeam(inputs)
//	var translator dynamicregistry.Translator = dynamicregistry.NoopTranslator{}
//	if seam != nil {
//	    translator = dynamicregistry.NewSeamTranslator(seam)
//	}
//	dyn := dynamicregistry.New(seed, pgxPool, dynregCache,
//	    dynamicregistry.WithTranslator(translator))
//
// Components wired:
//
//   - translation.Client (Round 10D LLM provider)
//   - translateprovider.New (registers the LLM under ProviderID)
//   - localization.Registry (Tier-A en → target locale routing)
//   - cacheredis.New (Redis-backed translation cache, 7-day TTL)
//   - overridepgx.New (pgx-backed override-store read path)
//   - seampersister.NewDynClient (write-through persister)
//   - localization.NewCanonicalGuard (Sweep PP/QQ/KKK guard)
//   - localization.NewSeamWith (the actual Seam construction)
//
// Returns nil + logs a WARN when ModelsURL / Redis / DBPool /
// LocalizationServiceURL / InternalAPIKey / ProviderID are missing
// (logs include which inputs are missing so the operator can fix
// config). Round 10D consumers MUST handle nil; the dynamicregistry
// fall-through to seed English is the canonical degraded mode.
func NewProductionSeam(inputs SeamBuilderInputs) *localization.Seam {
	logger := inputs.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// Required-input audit. We log + return nil rather than panic
	// because the canonical operator failure mode is a misconfigured
	// env var; the service still starts and degrades to seed English.
	//
	// Redis is OPTIONAL: when nil the seam uses NoopCache (every miss
	// re-runs the LLM). For low-volume services like
	// kielo-communications-service this is acceptable until traffic
	// justifies Redis wiring.
	missing := []any{}
	if inputs.ModelsURL == "" {
		missing = append(missing, slog.String("missing", "ModelsURL"))
	}
	if inputs.EngineURL == "" {
		missing = append(missing, slog.String("missing", "EngineURL"))
	}
	if inputs.InternalAPIKey == "" {
		missing = append(missing, slog.String("missing", "InternalAPIKey"))
	}
	if inputs.LocalizationServiceURL == "" {
		missing = append(missing, slog.String("missing", "LocalizationServiceURL"))
	}
	if inputs.DBPool == nil {
		missing = append(missing, slog.String("missing", "DBPool"))
	}
	if inputs.ProviderID == "" {
		missing = append(missing, slog.String("missing", "ProviderID"))
	}
	if len(missing) > 0 {
		logger.Warn("Round 10D seam not wired (missing inputs)", missing...)
		return nil
	}

	// Translation provider chain.
	translationClient := sharedtranslation.NewClient(
		inputs.ModelsURL,
		inputs.EngineURL,
		inputs.InternalAPIKey,
		nil, // default httputil.Client
	)
	provider := translateprovider.New(translationClient, inputs.ProviderID)

	registry := localization.NewRegistry()
	if err := registry.Register(provider.ProviderID(), provider); err != nil {
		logger.Warn("Round 10D seam: failed to register provider",
			slog.String("provider_id", inputs.ProviderID),
			slog.String("err", err.Error()))
		return nil
	}
	registry.SetDefault(provider.ProviderID())

	// Cache + override-store + persister + guard.
	// Redis-optional: when nil substitute NoopCache so the seam still
	// functions (every miss re-runs the LLM; acceptable for low-volume
	// services like kielo-communications-service).
	var cache localization.Cache
	if inputs.Redis != nil {
		cache = cacheredis.New(inputs.Redis, 7*24*time.Hour)
	} else {
		cache = localization.NoopCache{}
		logger.Info("Round 10D seam: Redis not wired — using NoopCache (every miss re-runs LLM)",
			slog.String("provider_id", inputs.ProviderID))
	}
	overrides := overridepgx.New(inputs.DBPool)

	dynClient := dynclient.New(inputs.LocalizationServiceURL, inputs.InternalAPIKey, nil)
	persister := NewDynClient(dynClient, inputs.TranslatorSource, logger)

	guard := localization.NewCanonicalGuard()

	seam := localization.NewSeamWith(
		registry,
		cache,
		overrides,
		localization.NoopMetrics{}, // services that want Prometheus wire their own at top-level
		persister,
		guard,
		localization.SeamConfig{},
	)
	logger.Info("Round 10D seam wired",
		slog.String("provider_id", inputs.ProviderID),
		slog.String("translator_source", persister.translatorSource),
		slog.String("models_url", inputs.ModelsURL),
		slog.String("localization_url", inputs.LocalizationServiceURL))
	return seam
}
