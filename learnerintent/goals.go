package learnerintent

// GoalScenarioCategories are the conversation scenario categories an onboarding
// goal (users.learning_reason) points to. It is the one map every surface that
// ranks scenes by goal reads (Juka "For you", conversation pushes), so they agree
// on what a goal means. "other" names nothing and stays unmapped.
var GoalScenarioCategories = map[string][]string{
	"living_here":     {"everyday-life", "shopping-services"},
	"work":            {"work-professional"},
	"healthcare_work": {"health-wellbeing"},
	"partner_family":  {"social-relationships"},
	"citizenship":     {"finnish-society"},
	"study":           {"education-learning"},
	"travel":          {"transport-travel", "food-dining"},
	"heritage":        {"culture-leisure", "social-relationships"},
	"curiosity":       {"culture-leisure"},
}
