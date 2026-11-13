package db

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/team-kielo-app/kielo-shared/observe/metrics"
)

// pgx has no hook that rewrites SQL text (QueryRewriter only runs when a
// caller passes one as the first argument), and every service holds a concrete
// *pgxpool.Pool, so a pool wrapper would touch every call site. The one place
// all statements pass is the connection's writer: pgconn.Config.BuildFrontend
// receives the io.Writer the wire protocol is flushed to. tagWriter walks the
// protocol messages in each flush and appends the tag to Query ('Q', simple
// protocol: Query/QueryRow/Exec/SendBatch/CopyFrom/Begin) and Parse ('P',
// extended protocol) statements. Bind, Execute, CopyData and the rest are
// copied untouched.

const (
	queryTagsEnv = "DB_QUERY_TAGS"
	queryAppEnv  = "DB_QUERY_APP"
	queryRoleEnv = "DB_QUERY_ROLE"

	defaultQueryRole = "primary"
)

func queryTagsOn() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(queryTagsEnv))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// QueryTag is the SQLCommenter-style comment that marks a service's statements
// for PlanetScale Insights: /*app='<service>',role='<role>'*/.
func QueryTag(app, role string) string {
	return "/*app='" + tagValue(app) + "',role='" + tagValue(role) + "'*/"
}

func tagValue(v string) string {
	v = strings.NewReplacer("*/", "", "\n", " ", "\r", " ", "\x00", "").Replace(v)
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v)
}

// TagSQL appends tag to sql without touching anything inside it: before a
// closing ";", after any trailing comment (on its own line when that comment
// is a "--" one, which would otherwise swallow the tag). A statement that is
// empty, only a ";", or already carries the tag is returned as it is.
func TagSQL(sql, tag string) string {
	if tag == "" || strings.Contains(sql, tag) {
		return sql
	}
	body := strings.TrimRight(sql, " \t\r\n")
	semi := strings.HasSuffix(body, ";")
	if semi {
		body = strings.TrimRight(body[:len(body)-1], " \t\r\n")
	}
	if body == "" {
		return sql
	}
	sep := " "
	if last := body[strings.LastIndexByte(body, '\n')+1:]; strings.Contains(last, "--") {
		sep = "\n"
	}
	out := body + sep + tag
	if semi {
		out += ";"
	}
	return out
}

func resolveQueryApp(explicit string) string {
	for _, name := range []string{explicit, os.Getenv(queryAppEnv), metrics.ServiceName(), os.Getenv("K_SERVICE")} {
		name = strings.TrimSpace(name)
		if name != "" && name != "unknown" {
			return name
		}
	}
	return filepath.Base(os.Args[0])
}

// installQueryTags makes every connection the config opens tag its statements.
// The service name is resolved when a connection is built (PoolOptions.Service,
// DB_QUERY_APP, metrics.SetServiceName, K_SERVICE, then the binary name), so it
// is constant for a process once main has named the service.
func installQueryTags(cfg *pgconn.Config, service, role string) {
	build := cfg.BuildFrontend
	if build == nil {
		return
	}
	if role = strings.TrimSpace(role); role == "" {
		role = strings.TrimSpace(os.Getenv(queryRoleEnv))
	}
	if role == "" {
		role = defaultQueryRole
	}
	cfg.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		if queryTagsOn() {
			w = &tagWriter{w: w, tag: QueryTag(resolveQueryApp(service), role)}
		}
		return build(r, w)
	}
}

type tagWriter struct {
	w   io.Writer
	tag string
	buf []byte
}

// Write rewrites the Query and Parse messages in p. It reports len(p) once the
// rewritten bytes are written, as the caller counts the bytes it handed over.
func (t *tagWriter) Write(p []byte) (int, error) {
	out, changed := t.rewrite(p)
	if !changed {
		return t.w.Write(p)
	}
	n, err := t.w.Write(out)
	if err != nil {
		return min(n, len(p)-1), err
	}
	return len(p), nil
}

func (t *tagWriter) rewrite(p []byte) ([]byte, bool) {
	out := t.buf[:0]
	changed := false
	pos := 0
	for pos+5 <= len(p) {
		kind := p[pos]
		size := int(binary.BigEndian.Uint32(p[pos+1 : pos+5]))
		end := pos + 1 + size
		if kind < 'A' || kind > 'z' || size < 4 || end > len(p) {
			break
		}
		body := p[pos+5 : end]
		var msg []byte
		switch kind {
		case 'Q':
			msg = t.tagQuery(body)
		case 'P':
			msg = t.tagParse(body)
		}
		if msg == nil {
			out = append(out, p[pos:end]...)
		} else {
			out = appendMessage(out, kind, msg)
			changed = true
		}
		pos = end
	}
	if !changed {
		return nil, false
	}
	out = append(out, p[pos:]...)
	t.buf = out
	return out, true
}

func appendMessage(dst []byte, kind byte, body []byte) []byte {
	dst = append(dst, kind)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)+4))
	return append(dst, body...)
}

func (t *tagWriter) tagQuery(body []byte) []byte {
	if len(body) == 0 || body[len(body)-1] != 0 {
		return nil
	}
	sql := string(body[:len(body)-1])
	tagged := tagQueries(sql, t.tag)
	if tagged == sql {
		return nil
	}
	return append([]byte(tagged), 0)
}

// tagParse handles Parse: name\0 sql\0 int16 count, then the parameter OIDs.
func (t *tagWriter) tagParse(body []byte) []byte {
	nameEnd := indexNUL(body)
	if nameEnd < 0 {
		return nil
	}
	rest := body[nameEnd+1:]
	sqlEnd := indexNUL(rest)
	if sqlEnd < 0 {
		return nil
	}
	sql := string(rest[:sqlEnd])
	tagged := TagSQL(sql, t.tag)
	if tagged == sql {
		return nil
	}
	msg := make([]byte, 0, len(body)+len(tagged)-len(sql))
	msg = append(msg, body[:nameEnd+1]...)
	msg = append(msg, tagged...)
	return append(msg, rest[sqlEnd:]...)
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
