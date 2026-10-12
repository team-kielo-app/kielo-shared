// Package testbaseline reads the monorepo's core database baseline
// (database/baseline/) for tests.
//
// The core migrations V001..V376 were retired into that baseline, so a test
// that used to replay one old migration file reads the equivalent from the
// baseline instead: seed rows from 20_seed.sql, and a table's final DDL from
// 10_schema_pre.sql plus 30_schema_post.sql. Test-only: nothing in a service
// binary imports it.
package testbaseline

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Null marks a SQL NULL in a seed row.
const Null = "\x00NULL"

const versionFile = "BASELINE_VERSION"

// Dir returns the baseline directory by walking up from the working directory
// to the monorepo root; ok is false when the service is checked out alone.
func Dir() (dir string, ok bool) {
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(wd, "database", "baseline")
		if _, err := os.Stat(filepath.Join(candidate, versionFile)); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", false
		}
		wd = parent
	}
}

// RequireDir is Dir that fails the test when the baseline is not there.
func RequireDir(t testing.TB) string {
	t.Helper()
	dir, ok := Dir()
	if !ok {
		t.Fatalf("core baseline database/baseline not found above %s", mustGetwd())
	}
	return dir
}

// SkipUnlessAvailable skips the test when the monorepo is not checked out around the service.
func SkipUnlessAvailable(t testing.TB) {
	t.Helper()
	if _, ok := Dir(); !ok {
		t.Skip("monorepo database/baseline not checked out around this submodule")
	}
}

func mustGetwd() string {
	wd, _ := os.Getwd()
	return wd
}

// Text returns one baseline file (for example "10_schema_pre.sql").
func Text(t testing.TB, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(RequireDir(t), name)) //nolint:gosec // fixed baseline file names
	if err != nil {
		t.Fatalf("read core baseline %s: %v", name, err)
	}
	return string(raw)
}

var copyEscapes = strings.NewReplacer(`\\`, `\`, `\t`, "\t", `\n`, "\n", `\r`, "\r")

func unescapeCopy(field string) string {
	if field == `\N` {
		return Null
	}
	if !strings.Contains(field, `\`) {
		return field
	}
	return copyEscapes.Replace(field)
}

// SeedRows returns the rows the baseline loads into schema.table, keyed by
// column name in seed order. NULLs are the Null sentinel.
func SeedRows(t testing.TB, table string) []map[string]string {
	t.Helper()
	lines := strings.Split(Text(t, "20_seed.sql"), "\n")
	prefix := "COPY " + table + " ("
	for i, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		end := strings.Index(line, ") FROM stdin")
		if end < 0 {
			t.Fatalf("malformed COPY header for %s: %s", table, line)
		}
		cols := strings.Split(line[len(prefix):end], ", ")
		var rows []map[string]string
		for _, raw := range lines[i+1:] {
			if raw == `\.` {
				return rows
			}
			fields := strings.Split(raw, "\t")
			if len(fields) != len(cols) {
				t.Fatalf("%s seed row has %d fields, want %d: %q", table, len(fields), len(cols), raw)
			}
			row := make(map[string]string, len(cols))
			for j, col := range cols {
				row[col] = unescapeCopy(fields[j])
			}
			rows = append(rows, row)
		}
		t.Fatalf("COPY block for %s in the core baseline is not terminated", table)
	}
	t.Fatalf("core baseline has no seed rows for %s", table)
	return nil
}

// SeedColumn returns one column of a baseline seed table, in seed order.
func SeedColumn(t testing.TB, table, column string) []string {
	t.Helper()
	rows := SeedRows(t, table)
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		v, ok := row[column]
		if !ok {
			t.Fatalf("baseline seed table %s has no column %s", table, column)
		}
		out = append(out, v)
	}
	return out
}

func quoteLiteral(v string) string {
	if v == Null {
		return "NULL"
	}
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

// InsertSQL renders the baseline seed rows of schema.table that keep accepts
// (all of them when keep is nil) as one INSERT, followed by onConflict, leaving
// out the omit columns (for example a surrogate id). It is how a test restores
// seed rows that other suites in a shared database delete.
func InsertSQL(t testing.TB, table string, keep func(row map[string]string) bool, onConflict string, omit ...string) string {
	t.Helper()
	rows := SeedRows(t, table)
	var cols []string
	for _, line := range strings.Split(Text(t, "20_seed.sql"), "\n") {
		if strings.HasPrefix(line, "COPY "+table+" (") {
			for _, col := range strings.Split(line[len("COPY "+table+" ("):strings.Index(line, ") FROM stdin")], ", ") {
				if !slices.Contains(omit, col) {
					cols = append(cols, col)
				}
			}
			break
		}
	}
	var values []string
	for _, row := range rows {
		if keep != nil && !keep(row) {
			continue
		}
		lits := make([]string, len(cols))
		for i, col := range cols {
			lits[i] = quoteLiteral(row[col])
		}
		values = append(values, "("+strings.Join(lits, ", ")+")")
	}
	if len(values) == 0 {
		t.Fatalf("no baseline seed rows of %s selected", table)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES %s %s", table, strings.Join(cols, ", "), strings.Join(values, ", "), onConflict)
}

var (
	blockSplit  = regexp.MustCompile(`(?m)^--\n-- Name: `)
	blockHeader = regexp.MustCompile(`^(.+?); Type: (.+?); Schema: (.+?); Owner:`)
	nextvalRE   = regexp.MustCompile(`nextval\('([^']+)'::regclass\)`)
	referencesR = regexp.MustCompile(`REFERENCES ([a-z_0-9]+\.[a-z_0-9]+)\(`)
)

type ddlBlock struct{ name, kind, schema, body string }

func parseBlocks(text string) []ddlBlock {
	var out []ddlBlock
	for _, raw := range blockSplit.Split(text, -1)[1:] {
		first, rest, _ := strings.Cut(raw, "\n")
		m := blockHeader.FindStringSubmatch(first)
		if m == nil {
			continue
		}
		out = append(out, ddlBlock{name: m[1], kind: m[2], schema: m[3], body: strings.Trim(rest, "\n- ")})
	}
	return out
}

// TableDDL returns the statements that create schema.table as the baseline
// defines it: the table, its column defaults and sequences, primary key and
// unique constraints, and indexes. A foreign key is included only when it
// references one of fkTargets (qualified names of tables the test creates).
// Triggers, comments and ACLs are left out. The schema must already exist.
func TableDDL(t testing.TB, table string, fkTargets ...string) []string {
	t.Helper()
	schema, name, ok := strings.Cut(table, ".")
	if !ok {
		t.Fatalf("TableDDL wants schema.table, got %q", table)
	}
	onTable := regexp.MustCompile(`\bON (?:ONLY )?` + regexp.QuoteMeta(table) + `[ (;]`)
	pre := parseBlocks(Text(t, "10_schema_pre.sql"))
	post := parseBlocks(Text(t, "30_schema_post.sql"))

	var stmts []string
	found := false
	var seqs []string
	for _, b := range pre {
		if b.schema != schema {
			continue
		}
		switch {
		case b.kind == "TABLE" && b.name == name:
			found = true
			stmts = append(stmts, b.body)
		case b.kind == "DEFAULT" && strings.HasPrefix(b.name, name+" "):
			stmts = append(stmts, b.body)
			for _, m := range nextvalRE.FindAllStringSubmatch(b.body, -1) {
				seqs = append(seqs, m[1])
			}
		}
	}
	if !found {
		t.Fatalf("core baseline has no table %s", table)
	}
	var seqStmts []string
	for _, seq := range seqs {
		sname := seq[strings.Index(seq, ".")+1:]
		for _, b := range pre {
			if b.kind == "SEQUENCE" && b.schema == schema && b.name == sname {
				seqStmts = append(seqStmts, b.body)
			}
		}
	}
	stmts = append(seqStmts, stmts...)
	for _, b := range post {
		if b.schema != schema {
			continue
		}
		switch b.kind {
		case "CONSTRAINT":
			if strings.HasPrefix(b.name, name+" ") {
				stmts = append(stmts, b.body)
			}
		case "INDEX":
			if onTable.MatchString(b.body) {
				stmts = append(stmts, b.body)
			}
		case "FK CONSTRAINT":
			if !strings.HasPrefix(b.name, name+" ") {
				continue
			}
			if m := referencesR.FindStringSubmatch(b.body); m != nil {
				for _, target := range fkTargets {
					if target == m[1] {
						stmts = append(stmts, b.body)
					}
				}
			}
		}
	}
	return splitStatements(stmts)
}

// TablesDDL returns the statements for several tables, with every foreign key
// between them last so the order of tables does not matter.
func TablesDDL(t testing.TB, tables ...string) []string {
	t.Helper()
	return TablesDDLAgainst(t, nil, tables...)
}

// TablesDDLAgainst is TablesDDL for tables whose foreign keys may also point at
// tables the test created itself (existing, as schema.table).
func TablesDDLAgainst(t testing.TB, existing []string, tables ...string) []string {
	t.Helper()
	targets := append(append([]string{}, existing...), tables...)
	var plain, foreign []string
	for _, table := range tables {
		for _, stmt := range TableDDL(t, table, targets...) {
			if strings.Contains(stmt, "FOREIGN KEY") {
				foreign = append(foreign, stmt)
			} else {
				plain = append(plain, stmt)
			}
		}
	}
	return append(plain, foreign...)
}

// FunctionDDL returns the CREATE FUNCTION statement of schema.name as the
// baseline defines it (one statement; the body is not split).
func FunctionDDL(t testing.TB, qualified string) string {
	t.Helper()
	schema, name, ok := strings.Cut(qualified, ".")
	if !ok {
		t.Fatalf("FunctionDDL wants schema.function, got %q", qualified)
	}
	for _, b := range parseBlocks(Text(t, "10_schema_pre.sql")) {
		if b.kind == "FUNCTION" && b.schema == schema && strings.HasPrefix(b.name, name+"(") {
			return strings.TrimSuffix(strings.TrimSpace(b.body), ";")
		}
	}
	t.Fatalf("core baseline has no function %s", qualified)
	return ""
}

func splitStatements(blocks []string) []string {
	var out []string
	for _, block := range blocks {
		for _, stmt := range strings.Split(block, ";\n") {
			stmt = strings.TrimSpace(stmt)
			if stmt = strings.TrimSuffix(stmt, ";"); stmt != "" {
				out = append(out, stmt)
			}
		}
	}
	return out
}

// Load runs the whole baseline (header, schema, seed, post-data) into the
// database at connString with psql, in one transaction. It is for a cold test
// database; the baseline's COPY blocks cannot be sent through a driver.
func Load(connString string) error {
	dir, ok := Dir()
	if !ok {
		return fmt.Errorf("core baseline database/baseline not found above %s", mustGetwd())
	}
	psql, err := exec.LookPath("psql")
	if err != nil {
		return fmt.Errorf("loading the core baseline needs psql on PATH: %w", err)
	}
	args := []string{connString, "-X", "-q", "-v", "ON_ERROR_STOP=1", "--single-transaction"}
	for _, name := range []string{"00_header.sql", "10_schema_pre.sql", "20_seed.sql", "30_schema_post.sql"} {
		args = append(args, "-f", filepath.Join(dir, name))
	}
	if out, err := exec.Command(psql, args...).CombinedOutput(); err != nil { //nolint:gosec // fixed psql args and repo files
		return fmt.Errorf("load core baseline: %w\n%s", err, out)
	}
	return nil
}
