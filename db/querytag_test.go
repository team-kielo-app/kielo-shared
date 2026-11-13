package db

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testTag = "/*app='svc',role='primary'*/"

func TestTagSQL(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "SELECT 1", "SELECT 1 " + testTag},
		{"semicolon", "SELECT 1;", "SELECT 1 " + testTag + ";"},
		{"semicolon and space", "SELECT 1 ;\n", "SELECT 1 " + testTag + ";"},
		{"block comment kept", "SELECT 1 /* x */", "SELECT 1 /* x */ " + testTag},
		{"line comment on own line", "SELECT 1 -- why", "SELECT 1 -- why\n" + testTag},
		{"line comment then semicolon", "SELECT 1 -- why\n;", "SELECT 1 -- why\n" + testTag + ";"},
		{"comment marks inside a literal only cost a newline", "SELECT 'a;--b*/'", "SELECT 'a;--b*/'\n" + testTag},
		{"literal ending in semicolon", "SELECT 'a;';", "SELECT 'a;' " + testTag + ";"},
		{"empty", "", ""},
		{"only semicolon", ";", ";"},
		{"already tagged", "SELECT 1 " + testTag, "SELECT 1 " + testTag},
	}
	for _, c := range cases {
		if got := TagSQL(c.in, testTag); got != c.want {
			t.Errorf("%s: TagSQL(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	if got := TagSQL("SELECT 1", ""); got != "SELECT 1" {
		t.Errorf("empty tag changed the statement: %q", got)
	}
}

func TestQueryTagEscapes(t *testing.T) {
	if got, want := QueryTag("a'b", `c\d*/`), `/*app='a\'b',role='c\\d'*/`; got != want {
		t.Errorf("QueryTag = %q, want %q", got, want)
	}
}

func frontendBytes(t *testing.T, msgs ...pgproto3.FrontendMessage) []byte {
	t.Helper()
	var buf []byte
	for _, m := range msgs {
		var err error
		if buf, err = m.Encode(buf); err != nil {
			t.Fatal(err)
		}
	}
	return buf
}

func TestTagWriterRewritesQueryAndParse(t *testing.T) {
	in := frontendBytes(t,
		&pgproto3.Query{String: "SELECT 1;"},
		&pgproto3.Parse{Name: "s1", Query: "SELECT $1", ParameterOIDs: []uint32{23, 25}},
		&pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{[]byte("1")}},
		&pgproto3.Execute{},
		&pgproto3.CopyData{Data: []byte("Q\x00\x00\x00\x08abc\x00")},
		&pgproto3.Sync{},
	)
	var sink bytes.Buffer
	w := &tagWriter{w: &sink, tag: testTag}
	n, err := w.Write(in)
	if err != nil || n != len(in) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(in))
	}

	be := pgproto3.NewBackend(&sink, nil)
	q, err := be.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if got := q.(*pgproto3.Query).String; got != "SELECT 1 "+testTag+";" {
		t.Errorf("query = %q", got)
	}
	p, err := be.Receive()
	if err != nil {
		t.Fatal(err)
	}
	parse := p.(*pgproto3.Parse)
	if parse.Name != "s1" || parse.Query != "SELECT $1 "+testTag || len(parse.ParameterOIDs) != 2 || parse.ParameterOIDs[1] != 25 {
		t.Errorf("parse = %+v", parse)
	}
	b, err := be.Receive()
	if err != nil || string(b.(*pgproto3.Bind).Parameters[0]) != "1" {
		t.Errorf("bind = %+v, %v", b, err)
	}
	if _, err := be.Receive(); err != nil {
		t.Fatal(err)
	}
	cd, err := be.Receive()
	if err != nil || !bytes.Equal(cd.(*pgproto3.CopyData).Data, []byte("Q\x00\x00\x00\x08abc\x00")) {
		t.Errorf("copy data changed: %+v, %v", cd, err)
	}
}

func TestTagWriterPassesThroughWhatItDoesNotKnow(t *testing.T) {
	startup := frontendBytes(t, &pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "u"}})
	for name, in := range map[string][]byte{
		"startup":   startup,
		"truncated": append(frontendBytes(t, &pgproto3.Sync{}), 'Q', 0, 0, 0, 40, 'S'),
		"empty":     {},
	} {
		var sink bytes.Buffer
		if _, err := (&tagWriter{w: &sink, tag: testTag}).Write(in); err != nil || !bytes.Equal(sink.Bytes(), in) {
			t.Errorf("%s: bytes changed or errored: %v", name, err)
		}
	}
}

func TestPoolConfigTagsUnlessOff(t *testing.T) {
	t.Setenv(queryAppEnv, "svc")
	cfg, err := PoolConfig("postgres://u:p@127.0.0.1:1/d", PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var sink bytes.Buffer
	fe := cfg.ConnConfig.BuildFrontend(strings.NewReader(""), &sink)
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sink.String(), "SELECT 1 "+testTag) {
		t.Errorf("statement not tagged: %q", sink.String())
	}

	t.Setenv(queryTagsEnv, "0")
	sink.Reset()
	fe = cfg.ConnConfig.BuildFrontend(strings.NewReader(""), &sink)
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sink.String(), "/*") {
		t.Errorf("DB_QUERY_TAGS=0 still tagged: %q", sink.String())
	}
}

// TestTaggedStatementsExecute runs every call path against a real database
// and reads the tag back from pg_stat_activity. Set TEST_QUERYTAG_DATABASE_URL.
func TestTaggedStatementsExecute(t *testing.T) {
	dsn := os.Getenv("TEST_QUERYTAG_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_QUERYTAG_DATABASE_URL not set")
	}
	t.Setenv(queryAppEnv, "svc")
	ctx := context.Background()
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeSimpleProtocol, pgx.QueryExecModeCacheStatement} {
		cfg, err := TestPoolConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.DefaultQueryExecMode = mode
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := pool.QueryRow(ctx, "SELECT $1::int", 7).Scan(&n); err != nil || n != 7 {
			t.Fatalf("mode %v QueryRow = %d, %v", mode, n, err)
		}
		if _, err := pool.Exec(ctx, "CREATE TEMP TABLE IF NOT EXISTS qt (a int);"); err != nil {
			t.Fatal(err)
		}
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, "CREATE TEMP TABLE IF NOT EXISTS qt (a int)"); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.CopyFrom(ctx, pgx.Identifier{"qt"}, []string{"a"}, pgx.CopyFromRows([][]any{{1}, {2}})); err != nil {
			t.Fatalf("mode %v CopyFrom: %v", mode, err)
		}
		batch := &pgx.Batch{}
		batch.Queue("SELECT count(*) FROM qt")
		batch.Queue("SELECT 'a;--b'")
		res := conn.SendBatch(ctx, batch)
		if err := res.QueryRow().Scan(&n); err != nil || n != 2 {
			t.Fatalf("mode %v batch count = %d, %v", mode, n, err)
		}
		var lit string
		if err := res.QueryRow().Scan(&lit); err != nil || lit != "a;--b" {
			t.Fatalf("mode %v batch literal = %q, %v", mode, lit, err)
		}
		if err := res.Close(); err != nil {
			t.Fatal(err)
		}
		var seen string
		if err := conn.QueryRow(ctx, "SELECT query FROM pg_stat_activity WHERE pid = pg_backend_pid()").Scan(&seen); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(seen, testTag) {
			t.Errorf("mode %v: backend saw %q, want the tag", mode, seen)
		}
		conn.Release()
		pool.Close()
	}
}
