package db

// MigrationBookkeepingTables are tables that test cleanups must NEVER
// truncate or delete, regardless of how they enumerate tables.
//
// Bare-name enumeration under a per-language search_path resolves these
// to the FIRST schema on the path — three real incidents in one week
// (2026-08): the engine's pytest conftest truncated
// klearn_fi.flyway_schema_history (the next `make dev-up` then failed
// V001 with "relation already exists"), cms's SetupTestDB deleted the
// migration-seeded convo copy from localization.dynamic_translations,
// and comms `go test` truncated the live dev DB.
//
// Any cleanup that discovers tables dynamically (information_schema,
// inspector, pg_tables) must union its skip set with this list.
// Python twin: kielo_shared.db_utils.MIGRATION_BOOKKEEPING_TABLES.
var MigrationBookkeepingTables = []string{
	"alembic_version",
	"flyway_schema_history",
}
