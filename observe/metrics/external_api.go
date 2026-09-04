package metrics

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ExternalAPIFailureLogToken is the stable text the Cloud Logging log-based
// metric in terraform/external-api-monitoring.tf matches on. The Python twin
// (kielo_shared/observability/external_api.py) emits the same line shape:
//
//	external_api_failure provider=revenuecat operation=get_subscriber kind=auth status=401 service=kielo-user-service detail=...
//
// Keep the token and the `kind=` vocabulary in sync with the Python module.
const ExternalAPIFailureLogToken = "external_api_failure"

// Bounded failure kinds. quota and auth mean "credits or credentials", and
// page on the first occurrence; the rest page on a sustained rate.
const (
	ExternalAPIKindQuota      = "quota"
	ExternalAPIKindAuth       = "auth"
	ExternalAPIKindRateLimit  = "rate_limit"
	ExternalAPIKindTimeout    = "timeout"
	ExternalAPIKindConnection = "connection"
	ExternalAPIKindServer     = "server"
	ExternalAPIKindClient     = "client"
	ExternalAPIKindUnknown    = "unknown"
)

var quotaMarkers = []string{
	"quota", "billing", "insufficient", "credit", "balance", "payment",
	"exceeded your current", "resource_exhausted", "resourceexhausted", "resource has been exhausted",
	"plan limit", "out of funds",
}

var authMarkers = []string{
	"unauthorized", "invalid api key", "invalid_api_key", "api key not valid",
	"authentication", "permission denied", "forbidden", "invalid credentials", "token expired",
}

var rateLimitMarkers = []string{"rate limit", "ratelimit", "too many requests"}

var timeoutMarkers = []string{"timeout", "timed out", "deadline"}

var connectionMarkers = []string{"connect", "dns", "resolve", "reset by peer", "unreachable", "no such host"}

// ExternalAPIFailureTotal mirrors kielo_external_api_failure_total on the
// Python side. No production scraper reads it today; the log line is the
// alert signal.
var ExternalAPIFailureTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kielo_external_api_failure_total",
		Help: "External (paid) API failures by provider and bounded kind. " +
			"kind=quota|auth means credits or credentials, not a transient error.",
	},
	[]string{"service", "provider", "kind"},
)

// ClassifyExternalAPIFailure maps an HTTP status and/or error text to the
// bounded kind vocabulary. A 429 whose body mentions quota or billing is
// quota (OpenAI and Gemini use 429 for both), a bare 429 is rate_limit, 402
// is always quota, 401/403 are auth. errorClass is a seam ErrorClass string
// ("timeout", "connection", "http_5xx", ...) used when no status is known.
func ClassifyExternalAPIFailure(status int, message, errorClass string) string {
	msg := strings.ToLower(message)
	cls := strings.ToLower(errorClass)
	if kind := classifyCreditFailure(status, msg); kind != "" {
		return kind
	}
	if kind := classifyTransportFailure(cls, msg); kind != "" {
		return kind
	}
	return classifyStatusFailure(status, cls)
}

func classifyCreditFailure(status int, msg string) string {
	switch {
	case status == 402 || containsAny(msg, quotaMarkers):
		return ExternalAPIKindQuota
	case status == 401 || status == 403 || containsAny(msg, authMarkers):
		return ExternalAPIKindAuth
	case status == 429 || containsAny(msg, rateLimitMarkers):
		return ExternalAPIKindRateLimit
	}
	return ""
}

func classifyTransportFailure(cls, msg string) string {
	switch {
	case cls == "timeout" || containsAny(msg, timeoutMarkers):
		return ExternalAPIKindTimeout
	case cls == "connection" || containsAny(msg, connectionMarkers):
		return ExternalAPIKindConnection
	}
	return ""
}

func classifyStatusFailure(status int, cls string) string {
	switch {
	case status >= 500 || cls == "http_5xx":
		return ExternalAPIKindServer
	case (status >= 400 && status < 500) || cls == "http_4xx":
		return ExternalAPIKindClient
	}
	return ExternalAPIKindUnknown
}

// ExternalAPIFailure describes one failed call to a paid third-party API.
// Status is 0 when the failure happened before a response arrived. Kind may
// be left empty to have it classified from Status and Err.
type ExternalAPIFailure struct {
	Provider   string
	Operation  string
	Status     int
	Kind       string
	ErrorClass string
	Err        error
	Detail     string
}

// ExternalAPIFailureEmit writes the canonical WARN line and bumps the
// counter. Safe on a nil error and never panics; the service label comes
// from SetServiceName, matching the search_path emitter.
func ExternalAPIFailureEmit(ctx context.Context, f ExternalAPIFailure) {
	detail := f.Detail
	if detail == "" && f.Err != nil {
		detail = f.Err.Error()
	}
	if f.Err != nil && f.ErrorClass == "" {
		if errors.Is(f.Err, context.DeadlineExceeded) {
			f.ErrorClass = "timeout"
		}
	}
	kind := f.Kind
	if kind == "" {
		kind = ClassifyExternalAPIFailure(f.Status, detail, f.ErrorClass)
	}
	provider := f.Provider
	if provider == "" {
		provider = "unknown"
	}
	operation := f.Operation
	if operation == "" {
		operation = "unknown"
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	detail = strings.ReplaceAll(detail, "\n", " ")
	svc := ServiceName()
	if ctx == nil {
		ctx = context.Background()
	}
	slog.WarnContext(ctx,
		ExternalAPIFailureLogToken+" provider="+provider+" operation="+operation+" kind="+kind+
			" status="+statusLabel(f.Status)+" service="+svc+" detail="+detail,
		"provider", provider,
		"operation", operation,
		"kind", kind,
		"status", f.Status,
	)
	ExternalAPIFailureTotal.WithLabelValues(svc, provider, kind).Inc()
}

func statusLabel(status int) string {
	if status <= 0 {
		return "-"
	}
	return strconv.Itoa(status)
}

func containsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}
