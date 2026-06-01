package httputil

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

// TimezoneOffsetHeader is the canonical service-to-service header
// carrying the request's timezone offset in minutes east of UTC.
// Pinned by `kielo-shared/timeutil.TimezoneOffsetHeader`. Mobile +
// admin clients stamp it on every outbound request via the BFF
// baseQuery so day-boundary calculations (streaks, daily progress,
// daily challenge resets) honor the user's actual wall-clock day
// rather than UTC.
//
// Sweep RRRR canonical lift: pre-RRRR only kielo-content-service's
// internal/platform/user/client.go (3 of 3 methods) explicitly
// stamped this header on outbound user-service calls. Every other
// Go HTTP client that depended on the receiving Go service's
// day-boundary logic (streak calc, daily-challenge reset window,
// etc.) silently dropped the offset; the receiving service then
// defaulted to UTC (offset 0) and computed boundaries off the wrong
// timezone. Pattern is the sibling of Sweep QQQQ (support_language)
// applied to a different cross-cutting signal.
const TimezoneOffsetHeader = timeutil.TimezoneOffsetHeader

// ApplyTimezoneOffsetHeader copies the active timezone-offset-minutes
// signal from the request context onto the outbound HTTP request as
// the canonical X-Timezone-Offset-Minutes header. No-op when ctx has
// no offset (background workers without a request scope) or when the
// header is already present (explicit caller overrides survive).
//
// Read by the receiving Go service via `timeutil.TimezoneOffsetMinutes
// FromHeader(req)` + stash on ctx via `timeutil.WithTimezoneOffset
// Minutes`. Sweep RRRR canonical: every internal HTTP client should
// consume this via the shared `PrepareInternalJSONRequest` helper
// (which calls it automatically). Pre-RRRR the user/client.go in
// kielo-content-service implemented the same behavior per-client;
// RRRR lifts the pattern.
func ApplyTimezoneOffsetHeader(req *http.Request) {
	if req == nil {
		return
	}
	if strings.TrimSpace(req.Header.Get(TimezoneOffsetHeader)) != "" {
		return
	}
	offset := timeutil.TimezoneOffsetMinutesFromContext(req.Context())
	if offset == 0 {
		// Treat zero as "not set" rather than "explicitly UTC". The
		// per-RRRR contract is that handlers/middleware on the
		// receiving side already default to 0 (UTC) when the header
		// is absent; stamping "0" verbatim has no behavioral effect
		// but adds noise to traces. If a caller genuinely wants to
		// force UTC despite ctx carrying a non-zero value (rare),
		// they can set the header explicitly before calling
		// PrepareInternalJSONRequest.
		return
	}
	req.Header.Set(TimezoneOffsetHeader, strconv.Itoa(offset))
}
