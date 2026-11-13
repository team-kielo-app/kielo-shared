package db

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

type recordingWriter struct {
	writes [][]byte
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

// A frontend flushes its whole buffer in one Write, however large the
// statement, so the tag is never lost to a split buffer.
func TestFrontendFlushesLargeQueryInOneWriteAndTagsIt(t *testing.T) {
	var rec recordingWriter
	tw := &tagWriter{w: &rec, tag: testTag}
	fe := pgproto3.NewFrontend(bytes.NewReader(nil), tw)
	big := "SELECT 1 FROM unnest('{" + strings.Repeat("0b6a5f3e-1111-2222-3333-444455556666,", 8000) + "}'::text[])"
	fe.Send(&pgproto3.Query{String: big})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(rec.writes))
	}
	m, err := pgproto3.NewBackend(bytes.NewReader(rec.writes[0]), nil).Receive()
	if err != nil {
		t.Fatal(err)
	}
	if got := m.(*pgproto3.Query).String; !strings.HasSuffix(got, testTag) || len(got) < 290000 {
		t.Errorf("tag missing on %d byte query", len(got))
	}
}

func TestTagQueriesTagsEveryStatementOfASimpleProtocolBatch(t *testing.T) {
	// pgx joins a simple-protocol Batch into one Query with ";" between the
	// queries (conn.go sendBatchQueryExecModeSimpleProtocol).
	cases := map[string]string{
		"SELECT 1;SELECT 2;SELECT 3":               "SELECT 1 " + testTag + ";SELECT 2 " + testTag + ";SELECT 3 " + testTag,
		"SELECT 1;":                                "SELECT 1 " + testTag + ";",
		"BEGIN; SET LOCAL search_path = 'a;b'":     "BEGIN " + testTag + "; SET LOCAL search_path = 'a;b' " + testTag,
		"SELECT ';' , \";\" , $q$ ; $q$ ;SELECT 2": "SELECT ';' , \";\" , $q$ ; $q$ " + testTag + ";SELECT 2 " + testTag,
		"SELECT 1 -- a;b\n;SELECT 2 /* ; */":       "SELECT 1 -- a;b\n" + testTag + ";SELECT 2 /* ; */ " + testTag,
		"SELECT E'\\';' ;SELECT 2":                 "SELECT E'\\';' " + testTag + ";SELECT 2 " + testTag,
		"SELECT 1;  ;-- done\n":                    "SELECT 1 " + testTag + ";  ;-- done\n",
		"SELECT 1 /*x*/ ; SELECT 2":                "SELECT 1 /*x*/ " + testTag + "; SELECT 2 " + testTag,
	}
	for in, want := range cases {
		if got := tagQueries(in, testTag); got != want {
			t.Errorf("tagQueries(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	if got := tagQueries("SELECT 1 "+testTag+";SELECT 2", testTag); got != "SELECT 1 "+testTag+";SELECT 2 "+testTag {
		t.Errorf("already tagged statement: %q", got)
	}
}

func TestTagWriterTagsEachStatementOfABatchQuery(t *testing.T) {
	var sink bytes.Buffer
	in := frontendBytes(t, &pgproto3.Query{String: "SELECT 1;SELECT 2"})
	if _, err := (&tagWriter{w: &sink, tag: testTag}).Write(in); err != nil {
		t.Fatal(err)
	}
	m, err := pgproto3.NewBackend(&sink, nil).Receive()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m.(*pgproto3.Query).String, "SELECT 1 "+testTag+";SELECT 2 "+testTag; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

var _ io.Writer = (*recordingWriter)(nil)
