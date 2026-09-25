package dynamicregistry

import (
	"regexp"
	"testing"
)

var statusInClause = regexp.MustCompile(`status\s+IN\s*\(([^)]*)\)`)

// The registry must serve every status its coverage report counts as
// overridden; otherwise the admin grid reports rows learners never see.
func TestLookupServesEveryCoveredStatus(t *testing.T) {
	lookup := statusInClause.FindStringSubmatch(dbLookupQuery)
	coverage := statusInClause.FindStringSubmatch(dbCoverageQuery)
	if lookup == nil || coverage == nil {
		t.Fatal("status IN clause missing from a registry query")
	}
	if lookup[1] != coverage[1] {
		t.Fatalf("lookup serves %s but coverage counts %s", lookup[1], coverage[1])
	}
}
