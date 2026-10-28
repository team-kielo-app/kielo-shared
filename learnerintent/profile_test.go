package learnerintent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)

func day(daysAgo int) time.Time {
	return time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -daysAgo)
}

func row(feature string, daysAgo, n int) UsageRow {
	return UsageRow{Feature: feature, PeriodStart: day(daysAgo), UsageCount: n}
}

func sum(m map[string]float64) float64 {
	total := 0.0
	for _, v := range m {
		total += v
	}
	return total
}

func TestResolveEmptyLearnerIsColdStart(t *testing.T) {
	p := Resolve("", nil, now, 0)
	assert.Equal(t, DefaultWindowDays, p.WindowDays)
	assert.Equal(t, "", p.Goal)
	assert.Equal(t, "", p.TopType)
	assert.Equal(t, "", p.SessionLen)
	assert.Zero(t, p.ActiveDays)
	for _, typ := range ContentTypes {
		assert.Zero(t, p.TypeMinutes[typ])
		assert.InDelta(t, 0.25, p.TypeShare[typ], 1e-9)
	}
	require.Len(t, p.Sources, 7)
	for field, src := range p.Sources {
		assert.Equal(t, SourceColdStart, src, field)
	}
	assert.Equal(t, now, p.ComputedAt)
}

func TestResolveGoalOnly(t *testing.T) {
	p := Resolve("  Work ", nil, now, 30)
	assert.Equal(t, "work", p.Goal)
	assert.Equal(t, SourceGoal, p.Sources["goal"])
	assert.Equal(t, SourceGoal, p.Sources["type_share"])
	assert.InDelta(t, 0.35, p.TypeShare[TypeConversation], 1e-9)
	assert.Equal(t, 30, p.WindowDays)
	assert.Equal(t, "", p.TopType)
}

func TestResolveThinEvidenceDoesNotNameATopType(t *testing.T) {
	p := Resolve("", []UsageRow{row(FeatureVideoSeconds, 1, 180)}, now, 0)
	assert.InDelta(t, 3, p.TypeMinutes[TypeVideo], 1e-9)
	assert.Less(t, p.TypeShare[TypeVideo], 0.4)
	assert.Greater(t, p.TypeShare[TypeVideo], 0.25)
	assert.Equal(t, "", p.TopType)
	assert.Equal(t, SourceBehavior, p.Sources["type_minutes"])
	assert.Equal(t, SourceColdStart, p.Sources["top_type"])
	assert.InDelta(t, 1, sum(p.TypeShare), 0.005)
}

func TestResolveClearPreference(t *testing.T) {
	rows := []UsageRow{
		row(FeatureReading, 1, 60),
		row(FeatureReading, 2, 40),
		row(FeaturePractice, 3, 10),
		row(FeatureVideoSeconds, 4, 300),
	}
	p := Resolve("study", rows, now, 0)
	assert.Equal(t, TypeReading, p.TopType)
	assert.Equal(t, SourceBehavior, p.Sources["top_type"])
	assert.InDelta(t, 100, p.TypeMinutes[TypeReading], 1e-9)
	assert.InDelta(t, 1, sum(p.TypeShare), 0.005)
	assert.Greater(t, p.TypeShare[TypeReading], p.TypeShare[TypePractice])
}

func TestResolveCloseRaceHasNoTopType(t *testing.T) {
	rows := []UsageRow{row(FeatureReading, 1, 30), row(FeaturePractice, 1, 28)}
	p := Resolve("", rows, now, 0)
	assert.Equal(t, "", p.TopType)
}

func TestResolveUnitConversions(t *testing.T) {
	rows := []UsageRow{
		row(FeatureVideoSeconds, 1, 600),
		row(FeatureConvoSeconds, 1, 90),
		row(FeatureReading, 1, 7),
		row(FeaturePractice, 1, 4),
	}
	p := Resolve("", rows, now, 0)
	assert.InDelta(t, 10, p.TypeMinutes[TypeVideo], 1e-9)
	assert.InDelta(t, 1.5, p.TypeMinutes[TypeConversation], 1e-9)
	assert.InDelta(t, 7, p.TypeMinutes[TypeReading], 1e-9)
	assert.InDelta(t, 4, p.TypeMinutes[TypePractice], 1e-9)
}

func TestResolveSecondsAcrossDaysSumBeforeDividing(t *testing.T) {
	rows := []UsageRow{row(FeatureConvoSeconds, 1, 30), row(FeatureConvoSeconds, 2, 30)}
	p := Resolve("", rows, now, 0)
	assert.InDelta(t, 1, p.TypeMinutes[TypeConversation], 1e-9)
}

func TestResolveWindowBoundary(t *testing.T) {
	rows := []UsageRow{
		row(FeatureReading, 9, 10),
		row(FeatureReading, 10, 99),
		row(FeatureVisit, 10, 5),
	}
	p := Resolve("", rows, now, 10)
	assert.InDelta(t, 10, p.TypeMinutes[TypeReading], 1e-9)
	assert.Equal(t, 1, p.ActiveDays)
	assert.Equal(t, day(9), WindowStart(now, 10))
}

func TestResolveIgnoresUnknownFeaturesAndNonPositive(t *testing.T) {
	rows := []UsageRow{
		row("words_viewed", 1, 500),
		row("kielotv_watch", 1, 9),
		row("ai_conversations", 1, 3),
		row(FeatureReading, 1, 0),
		row(FeatureReading, 1, -5),
	}
	p := Resolve("", rows, now, 0)
	assert.Zero(t, p.ActiveDays)
	assert.Zero(t, sum(p.TypeMinutes))
	assert.Equal(t, SourceColdStart, p.Sources["type_minutes"])
}

func TestResolveSessionBuckets(t *testing.T) {
	cases := []struct {
		name    string
		minutes []int
		want    string
		perDay  float64
		active  int
		perSrc  string
	}{
		{"short", []int{2, 3, 4}, SessionShort, 3, 3, SourceBehavior},
		{"lower edge is medium", []int{5, 5, 5}, SessionMedium, 5, 3, SourceBehavior},
		{"upper edge is medium", []int{12, 12, 12}, SessionMedium, 12, 3, SourceBehavior},
		{"long", []int{13, 20, 30}, SessionLong, 20, 3, SourceBehavior},
		{"median ignores a marathon day", []int{3, 4, 90}, SessionShort, 4, 3, SourceBehavior},
		{"even count averages middle", []int{4, 4, 6, 6}, SessionMedium, 5, 4, SourceBehavior},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rows []UsageRow
			for i, v := range c.minutes {
				rows = append(rows, row(FeaturePractice, i+1, v), row(FeatureVisit, i+1, 5))
			}
			p := Resolve("", rows, now, 0)
			assert.Equal(t, c.want, p.SessionLen)
			assert.InDelta(t, c.perDay, p.SessionMinutesPerDay, 1e-9)
			assert.Equal(t, c.active, p.ActiveDays)
			assert.Equal(t, c.perSrc, p.Sources["session_len"])
		})
	}
}

func TestResolveSessionMixesContentTypesPerDay(t *testing.T) {
	var rows []UsageRow
	for d := 1; d <= SessionMinDays; d++ {
		rows = append(rows, row(FeaturePractice, d, 4), row(FeatureVideoSeconds, d, 300), row(FeatureConvoSeconds, d, 240))
	}
	p := Resolve("", rows, now, 0)
	assert.Equal(t, SessionMinDays, p.ActiveDays)
	assert.InDelta(t, 13, p.SessionMinutesPerDay, 1e-9)
	assert.Equal(t, SessionLong, p.SessionLen)
}

func TestResolveTooFewDaysNamesNoSessionLen(t *testing.T) {
	p := Resolve("", []UsageRow{row(FeaturePractice, 1, 8), row(FeaturePractice, 2, 3)}, now, 0)
	assert.Equal(t, 2, p.ActiveDays)
	assert.Equal(t, "", p.SessionLen)
	assert.Equal(t, SourceColdStart, p.Sources["session_len"])
}

func TestResolveVisitOnlyDayIsActiveWithoutSessionLen(t *testing.T) {
	p := Resolve("", []UsageRow{row(FeatureVisit, 1, 5)}, now, 0)
	assert.Equal(t, 1, p.ActiveDays)
	assert.Equal(t, "", p.SessionLen)
	assert.Equal(t, SourceColdStart, p.Sources["session_len"])
	assert.Equal(t, SourceBehavior, p.Sources["active_days"])
}

func TestResolveGoalPriorHook(t *testing.T) {
	saved := GoalPrior["work"]
	GoalPrior["work"] = map[string]float64{TypeConversation: 3, TypeReading: 1}
	t.Cleanup(func() { GoalPrior["work"] = saved })

	p := Resolve("work", nil, now, 0)
	assert.Equal(t, SourceGoal, p.Sources["type_share"])
	assert.InDelta(t, 0.75, p.TypeShare[TypeConversation], 1e-9)
	assert.InDelta(t, 0.25, p.TypeShare[TypeReading], 1e-9)
	assert.InDelta(t, 0, p.TypeShare[TypeVideo], 1e-9)

	other := Resolve("other", nil, now, 0)
	assert.InDelta(t, 0.25, other.TypeShare[TypeConversation], 1e-9)
	assert.Equal(t, SourceColdStart, other.Sources["type_share"])
}

func TestGoalPriorsAreGentleAndComplete(t *testing.T) {
	for goal, prior := range GoalPrior {
		sum := 0.0
		for _, typ := range ContentTypes {
			share, ok := prior[typ]
			assert.Truef(t, ok, "%s lacks %s", goal, typ)
			assert.GreaterOrEqualf(t, share, 0.15, "%s %s", goal, typ)
			assert.LessOrEqualf(t, share, 0.40, "%s %s", goal, typ)
			sum += share
		}
		assert.InDeltaf(t, 1, sum, 1e-9, "%s sums to %v", goal, sum)
	}
	assert.NotContains(t, GoalPrior, "living_here")
	assert.NotContains(t, GoalPrior, "other")
}

func TestBehaviorOutweighsTheGoalPrior(t *testing.T) {
	p := Resolve("work", []UsageRow{row(FeatureVideoSeconds, 1, 40*60)}, now, 0)
	assert.Equal(t, TypeVideo, p.TopType)
	assert.Equal(t, SourceBehavior, p.Sources["type_share"])
}

func TestProfileJSONShape(t *testing.T) {
	b, err := json.Marshal(Resolve("work", nil, now, 0))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	for _, k := range []string{"goal", "type_minutes", "type_share", "top_type", "active_days",
		"session_minutes_per_day", "session_len", "window_days", "sources", "computed_at"} {
		assert.Contains(t, m, k)
	}
}
