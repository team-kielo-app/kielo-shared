// Package middleware: shared CORS helper.
//
// CORSAllowedOrigins centralizes the allow-list logic each Echo-based
// service used to copy verbatim. Reads CORS_ALLOWED_ORIGINS
// (comma-separated) with a service-supplied fallback. Returns a
// non-empty list so Echo's CORS middleware never silently degrades to
// "allow any origin" — the footgun this helper exists to close.
//
// Production must override the fallback via env. Local dev usually
// inherits the fallback; CI/staging set CORS_ALLOWED_ORIGINS via env.
package middleware

import (
	"log"
	"os"
	"strings"
)

// CORSAllowedOrigins parses CORS_ALLOWED_ORIGINS env or, when unset,
// the supplied fallback. Both are comma-separated origin lists.
// Whitespace is trimmed; empty entries are dropped.
//
// If the resulting list is empty (caller passed empty fallback AND env
// is unset), the function logs a warning and returns []string{"null"}
// so Echo's CORS middleware rejects all cross-origin requests rather
// than treating an empty allow-list as "allow any" via Echo's
// (legitimate but surprising) default.
func CORSAllowedOrigins(fallback string) []string {
	raw := os.Getenv("CORS_ALLOWED_ORIGINS")
	if strings.TrimSpace(raw) == "" {
		raw = fallback
	}
	var out []string
	for p := range strings.SplitSeq(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		log.Printf("WARN: CORS allow-list is empty; all cross-origin browser requests will be rejected")
		out = []string{"null"}
	}
	return out
}
