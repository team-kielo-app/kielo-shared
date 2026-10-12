package testbaseline

import (
	"strings"
	"testing"
)

func TestSeedRowsReadsCopyBlocks(t *testing.T) {
	SkipUnlessAvailable(t)
	rows := SeedRows(t, "users.achievement_definitions")
	if len(rows) == 0 || rows[0]["code"] == "" {
		t.Fatalf("expected seeded achievement codes, got %v", rows)
	}
	if got := SeedColumn(t, "localization.languages", "code"); len(got) == 0 {
		t.Fatal("expected seeded languages")
	}
}

func TestTableDDLCarriesTableAndIndexes(t *testing.T) {
	SkipUnlessAvailable(t)
	stmts := TableDDL(t, "communications.notification_created_outbox")
	joined := strings.Join(stmts, "\n")
	for _, want := range []string{"CREATE TABLE communications.notification_created_outbox", "PRIMARY KEY", "CREATE INDEX idx_notification_created_outbox_ready"} {
		if !strings.Contains(joined, want) {
			t.Errorf("DDL lacks %q:\n%s", want, joined)
		}
	}
}

func TestInsertSQLQuotesLiterals(t *testing.T) {
	SkipUnlessAvailable(t)
	sql := InsertSQL(t, "localization.llm_routes", func(r map[string]string) bool { return r["family"] == "juka_hints" }, "ON CONFLICT DO NOTHING")
	if !strings.HasPrefix(sql, "INSERT INTO localization.llm_routes (family,") || !strings.Contains(sql, "'juka_hints'") || !strings.Contains(sql, "NULL") {
		t.Fatalf("unexpected INSERT: %s", sql)
	}
}

func TestFunctionDDLReturnsTheCreateStatement(t *testing.T) {
	SkipUnlessAvailable(t)
	ddl := FunctionDDL(t, "users.effective_utc_offset_minutes")
	if !strings.HasPrefix(ddl, "CREATE FUNCTION users.effective_utc_offset_minutes(") || !strings.Contains(ddl, "LANGUAGE plpgsql") {
		t.Fatalf("unexpected function DDL: %s", ddl)
	}
}
