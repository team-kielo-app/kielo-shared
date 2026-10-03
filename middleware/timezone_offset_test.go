package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/team-kielo-app/kielo-shared/timeutil"
)

func TestTimezoneOffset(t *testing.T) {
	cases := []struct {
		name, header, value string
		want                int
		found               bool
	}{
		{"canonical", timeutil.TimezoneOffsetHeader, "420", 420, true},
		{"legacy alias", "X-Timezone-Offset", "-300", -300, true},
		{"explicit utc", timeutil.TimezoneOffsetHeader, "0", 0, true},
		{"invalid", timeutil.TimezoneOffsetHeader, "abc", 0, false},
		{"out of range", timeutil.TimezoneOffsetHeader, "9999", 0, false},
		{"absent", "", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			c := e.NewContext(req, httptest.NewRecorder())
			var got int
			var found bool
			err := TimezoneOffset()(func(c echo.Context) error {
				got, found = timeutil.LookupTimezoneOffsetMinutesFromContext(c.Request().Context())
				return nil
			})(c)
			assert.NoError(t, err)
			assert.Equal(t, tc.found, found)
			assert.Equal(t, tc.want, got)
		})
	}
}
