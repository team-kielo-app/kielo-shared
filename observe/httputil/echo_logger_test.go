package httputil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"

	"github.com/team-kielo-app/kielo-shared/observe"
)

func newBufferLogger(buf *bytes.Buffer) *log.Logger {
	l := log.New("echo")
	l.SetOutput(buf)
	l.SetLevel(log.DEBUG)
	return l
}

func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestRequestTracingMakesEchoLoggerLinesCarryTheTraceID(t *testing.T) {
	var buf bytes.Buffer
	e := echo.New()
	serverLogger := newBufferLogger(&buf)
	e.Logger = serverLogger
	e.Use(RequestTracing())
	e.GET("/x", func(c echo.Context) error {
		c.Logger().Infof("user %s loaded", "u1")
		c.Logger().Warnj(log.JSON{"msg": "slow"})
		return c.NoContent(http.StatusOK)
	})

	incoming := observe.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(observe.HeaderTraceparent, incoming.Traceparent())
	e.ServeHTTP(httptest.NewRecorder(), req)

	lines := decodeLines(t, &buf)
	if len(lines) != 2 {
		t.Fatalf("lines = %v", lines)
	}
	for _, m := range lines {
		if m["prefix"] != "trace_id="+incoming.TraceID {
			t.Errorf("prefix = %v, want trace_id=%s", m["prefix"], incoming.TraceID)
		}
		if m["file"] != "echo_logger_test.go" {
			t.Errorf("file = %v, want the caller (echo_logger_test.go)", m["file"])
		}
	}
	if lines[0]["message"] != "user u1 loaded" || lines[0]["level"] != "INFO" {
		t.Errorf("Infof line = %v", lines[0])
	}
	if lines[1]["msg"] != "slow" {
		t.Errorf("Warnj line = %v", lines[1])
	}

	if e.Logger != echo.Logger(serverLogger) || serverLogger.Prefix() != "echo" {
		t.Fatal("the server-wide logger must not change")
	}
	buf.Reset()
	e.Logger.Infof("outside a request")
	if strings.Contains(buf.String(), "trace_id") {
		t.Fatalf("server logger carries a trace: %q", buf.String())
	}
}

func TestEachRequestGetsItsOwnTrace(t *testing.T) {
	var buf bytes.Buffer
	e := echo.New()
	e.Logger = newBufferLogger(&buf)
	e.Use(RequestTracing())
	e.GET("/x", func(c echo.Context) error {
		c.Logger().Info("hit")
		return c.NoContent(http.StatusOK)
	})
	for i := 0; i < 2; i++ {
		e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	}
	lines := decodeLines(t, &buf)
	if len(lines) != 2 || lines[0]["prefix"] == lines[1]["prefix"] {
		t.Fatalf("lines = %v", lines)
	}
}

func TestNoTraceIDLeavesTheLoggerAlone(t *testing.T) {
	var buf bytes.Buffer
	c, _ := newTestContext("/x", nil)
	base := newBufferLogger(&buf)
	c.Echo().Logger = base

	withTracedLogger(c, "")
	if c.Logger() != echo.Logger(base) {
		t.Fatal("logger replaced without a trace id")
	}
	c.Logger().Infof("plain %d", 1)
	if strings.Contains(buf.String(), "trace_id") || !strings.Contains(buf.String(), "plain 1") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestTracedLoggerKeepsTheLevelAndOutputAndLeavesCustomLoggersAlone(t *testing.T) {
	var buf bytes.Buffer
	c, _ := newTestContext("/x", nil)
	base := newBufferLogger(&buf)
	base.SetLevel(log.ERROR)
	c.Echo().Logger = base

	withTracedLogger(c, "abc")
	c.Logger().Infof("hidden")
	c.Logger().Errorf("shown")
	if got := decodeLines(t, &buf); len(got) != 1 || got[0]["message"] != "shown" || got[0]["prefix"] != "trace_id=abc" {
		t.Fatalf("lines = %v", got)
	}
	first := c.Logger()
	withTracedLogger(c, "abc")
	if c.Logger() != first {
		t.Fatal("wrapped twice")
	}

	c2, _ := newTestContext("/x", nil)
	custom := customLogger{Logger: base}
	c2.Echo().Logger = custom
	withTracedLogger(c2, "abc")
	if c2.Logger() != echo.Logger(custom) {
		t.Fatal("a non-gommon logger must be left untouched")
	}
}

type customLogger struct{ echo.Logger }

func BenchmarkWithTracedLogger(b *testing.B) {
	c, _ := newTestContext("/x", nil)
	c.Echo().Logger = newBufferLogger(&bytes.Buffer{})
	id := observe.New().TraceID
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.SetLogger(nil)
		withTracedLogger(c, id)
	}
}
