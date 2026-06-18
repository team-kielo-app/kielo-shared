package errors

// Sweep DDDDD A3: FEATURE_LIMIT_REACHED — the highest-fanout
// cross-service code in the monorepo. Pre-DDDDD it was:
//
//   - typed as kielo-convo/go_orchestrator/internal/api/errors.go
//     ErrFeatureLimitReached = "FEATURE_LIMIT_REACHED" (1 producer
//     site, typed)
//   - emitted as raw string literal by kielo-user-service in
//     feature_handler.go (2 sites) + feedback_handler.go (1 site)
//   - emitted as raw string literal by kielo-content-service in
//     articles/handler.go (1 site) + kielotv/handler.go (1 site) +
//     klearn/klearn.go (2 sites)
//   - mirrored as unexported const in kielo-content-service/internal/
//     platform/user/client.go (featureLimitReachedCode) for response-
//     parsing (CONSUMER side)
//   - mirrored as inline fallback in kielo-mobile-bff/internal/
//     features/conversations/errors.go:28 (fallbackConversationErrorCode)
//   - typed as kielo-app/src/features/convo/convoErrors.ts:12 union
//     member (CLIENT side)
//
// 5 distinct producer services + 2 client mirrors + 1 BFF passthrough
// fallback, all of which copy-pasted the wire string. The 6th typing
// (this file) is the canonical SoT all the others reference post-DDDDD.
//
// Semantics: emitted when a free-tier user hits a per-feature daily
// quota (e.g. 3 conversations per day) or per-feature lifetime cap
// (e.g. 20 generated concept-hubs). The user-service computes the
// cap state and returns 402 Payment Required + this code; producers
// at other services pass it through verbatim (per the Sweep ZZZZ
// vocabulary-stability discipline). Mobile renders a localized
// "you've reached your daily limit" message + a paywall CTA.
//
// Status: 402 Payment Required (Sweep ADR-004 §5 status mapping —
// this is the canonical paywall trigger).
const CodeFeatureLimitReached Code = "FEATURE_LIMIT_REACHED"
