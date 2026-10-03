package opswitch

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/middleware"
)

// CodeFeatureDisabled is the wire code for a refusal by a kill switch. The
// app shows details.message to the learner and may retry later; status is 503.
const CodeFeatureDisabled = "FEATURE_DISABLED"

func details(key string, d Decision) map[string]any {
	return map[string]any{"switch_key": key, "custom_message": d.Custom}
}

// ScopeFromEcho reads the learning language and platform for the request.
func ScopeFromEcho(c echo.Context, language string) Scope {
	return Scope{Language: language, Platform: c.Request().Header.Get(HeaderPlatform)}
}

// Refuse writes the 503 FEATURE_DISABLED envelope for an Echo handler:
// `if d := cl.Check(...); d.Off { return opswitch.Refuse(c, key, d) }`.
func Refuse(c echo.Context, key string, d Decision) error {
	c.Response().Header().Set("Retry-After", "60")
	return middleware.APIError(c, http.StatusServiceUnavailable, CodeFeatureDisabled, d.Message, details(key, d))
}

// RefuseStdlib is Refuse for net/http handlers.
func RefuseStdlib(ctx context.Context, w http.ResponseWriter, key string, d Decision) {
	w.Header().Set("Retry-After", "60")
	middleware.APIErrorStdlib(w, ctx, http.StatusServiceUnavailable, CodeFeatureDisabled, d.Message, details(key, d))
}
