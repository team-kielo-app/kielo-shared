package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

func TestTimezoneOffset_CarriesZoneAndDerivesMissingOffset(t *testing.T) {
	e := echo.New()
	run := func(headers map[string]string) (string, int, bool) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		c := e.NewContext(req, httptest.NewRecorder())
		var zone string
		var offset int
		var hasOffset bool
		_ = TimezoneOffset()(func(c echo.Context) error {
			zone, _ = timeutil.TimezoneNameFromContext(c.Request().Context())
			offset, hasOffset = timeutil.LookupTimezoneOffsetMinutesFromContext(c.Request().Context())
			return nil
		})(c)
		return zone, offset, hasOffset
	}

	zone, offset, ok := run(map[string]string{timeutil.TimezoneHeader: "Asia/Kolkata"})
	if zone != "Asia/Kolkata" || !ok || offset != 330 {
		t.Fatalf("zone only: got %q %d %v", zone, offset, ok)
	}
	zone, offset, ok = run(map[string]string{timeutil.TimezoneHeader: "Europe/Helsinki", timeutil.TimezoneOffsetHeader: "60"})
	if zone != "Europe/Helsinki" || !ok || offset != 60 {
		t.Fatalf("the device's own offset wins for the request: got %q %d %v", zone, offset, ok)
	}
	zone, _, ok = run(map[string]string{timeutil.TimezoneHeader: "Mars/Olympus"})
	if zone != "" || ok {
		t.Fatalf("invalid zone must be ignored: got %q %v", zone, ok)
	}
}
