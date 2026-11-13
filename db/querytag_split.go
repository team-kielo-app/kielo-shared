package db

import "strings"

// tagQueries tags every statement of a simple-protocol Query. pgx joins the
// queries of a Batch into one Query with ";" between them, and PlanetScale
// reads a tag only from the statement whose text it ends, so a tag on the last
// statement alone leaves the others untagged. A statement with nothing but
// whitespace or comments is left as it is.
func tagQueries(sql, tag string) string {
	spans := splitStatements(sql)
	if len(spans) == 1 {
		return TagSQL(sql, tag)
	}
	var b strings.Builder
	b.Grow(len(sql) + len(spans)*(len(tag)+1))
	pos := 0
	for i, s := range spans {
		if i > 0 {
			b.WriteByte(';')
		}
		seg := sql[pos:s.end]
		if s.code {
			seg = TagSQL(seg, tag)
		}
		b.WriteString(seg)
		pos = s.end + 1
	}
	return b.String()
}

type stmtSpan struct {
	end  int
	code bool
}

// splitStatements returns one span per statement: end is the index of its
// terminating ";" (len(sql) for the last), code whether it holds anything
// besides whitespace and comments. ";" inside quotes, dollar quotes and
// comments does not end a statement.
func splitStatements(sql string) []stmtSpan {
	var spans []stmtSpan
	code := false
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == ';':
			spans = append(spans, stmtSpan{i, code})
			code = false
			i++
		case strings.HasPrefix(sql[i:], "--"):
			i = skipTo(sql, i, "\n")
		case strings.HasPrefix(sql[i:], "/*"):
			i = skipBlockComment(sql, i)
		case c == '\'':
			code = true
			i = skipQuoted(sql, i, '\'', i > 0 && (sql[i-1] == 'E' || sql[i-1] == 'e'))
		case c == '"':
			code = true
			i = skipQuoted(sql, i, '"', false)
		case c == '$':
			code = true
			i = skipDollar(sql, i)
		default:
			code = code || !strings.ContainsRune(" \t\n\r", rune(c))
			i++
		}
	}
	return append(spans, stmtSpan{len(sql), code})
}

func skipTo(sql string, i int, end string) int {
	if j := strings.Index(sql[i:], end); j >= 0 {
		return i + j + len(end)
	}
	return len(sql)
}

func skipBlockComment(sql string, i int) int {
	depth := 0
	for i < len(sql) {
		switch {
		case strings.HasPrefix(sql[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(sql[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(sql)
}

func skipQuoted(sql string, i int, q byte, backslash bool) int {
	for i++; i < len(sql); i++ {
		switch {
		case backslash && sql[i] == '\\':
			i++
		case sql[i] == q:
			if i+1 < len(sql) && sql[i+1] == q {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(sql)
}

// skipDollar steps over a $tag$ ... $tag$ string, or a lone "$" / "$1"
// parameter marker.
func skipDollar(sql string, i int) int {
	j := i + 1
	for j < len(sql) && (sql[j] == '_' || sql[j] >= 'a' && sql[j] <= 'z' || sql[j] >= 'A' && sql[j] <= 'Z' ||
		sql[j] >= '0' && sql[j] <= '9' && j > i+1) {
		j++
	}
	if j >= len(sql) || sql[j] != '$' {
		return i + 1
	}
	delim := sql[i : j+1]
	return skipTo(sql, j+1, delim)
}
