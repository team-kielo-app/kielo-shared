// cache_control.go: default Cache-Control header for user-scoped APIs.
//
// Mounted on a service's authenticated v3 group, this middleware sets
//   Cache-Control: private, no-store
// before the handler runs. The header instructs:
//   - private:   intermediate proxies / CDNs MUST NOT cache. Critical
//                because the response is keyed to the JWT subject, not
//                the URL — caching at the proxy layer leaks one user's
//                data to another.
//   - no-store:  the user agent (mobile app's HTTP layer, the desktop
//                browser) also doesn't persist. Browsers will still
//                keep it in the back-button history cache, which is
//                fine; "no-store" stops disk persistence + bfcache.
//
// Handlers that genuinely benefit from short client-side caching (a
// rarely-changing profile that the client polls every 30s) can override
// AFTER calling this middleware:
//
//   c.Response().Header().Set("Cache-Control", "private, max-age=30")
//
// Echo's response writer preserves the last header set, so the
// handler's value wins. The middleware just ensures we never SHIP an
// authenticated GET with no Cache-Control header at all — which would
// let CloudFront / nginx / the browser apply their own (often public)
// caching policy and silently leak.

package middleware

import "github.com/labstack/echo/v4"

// PrivateNoStore is the default Cache-Control middleware for
// authenticated v3 surfaces. Sets `private, no-store` on every
// response; handlers may override before writing their body.
func PrivateNoStore() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			h := c.Response().Header()
			if h.Get("Cache-Control") == "" {
				h.Set("Cache-Control", "private, no-store")
			}
			return next(c)
		}
	}
}
