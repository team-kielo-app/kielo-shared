package learnerintent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/team-kielo-app/kielo-shared/locale"
	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

func TestGoalScenarioCategoriesExist(t *testing.T) {
	seed, ok := locale.ConversationCategorySeed().(*supportregistry.MapRegistry)
	require.True(t, ok)
	known := map[string]bool{}
	for _, k := range seed.Keys() {
		known[strings.TrimPrefix(string(k), "ui.conversation.category.")] = true
	}
	for goal, categories := range GoalScenarioCategories {
		assert.NotEmptyf(t, categories, "%s", goal)
		for _, c := range categories {
			assert.Truef(t, known[c], "%s maps to unknown category %q", goal, c)
		}
	}
	assert.NotContains(t, GoalScenarioCategories, "other")
}
