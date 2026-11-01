package httputil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func TestTheAccessLineCarriesTheTraceOfTheRequest(t *testing.T) {
	var out bytes.Buffer
	cfg := middleware.DefaultLoggerConfig
	cfg.Output = &out
	e := echo.New()
	e.Use(RequestTracing(), AccessLogWithConfig(cfg))
	e.GET("/x", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })

	tc := observe.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(observe.HeaderTraceparent, tc.Traceparent())
	e.ServeHTTP(httptest.NewRecorder(), req)

	var line map[string]any
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatalf("not one JSON line: %q (%v)", out.String(), err)
	}
	if line["trace_id"] != tc.TraceID || line["status"] != float64(http.StatusNoContent) || line["uri"] != "/x" {
		t.Fatalf("got %v, want trace_id %s beside Echo's fields", line, tc.TraceID)
	}
}
