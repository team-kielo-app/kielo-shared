package learnerlevel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestChoose(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	rule := DefaultRule()
	str := func(s string) *string { return &s }
	conf := func(f float64) *float64 { return &f }
	ago := func(d time.Duration) *time.Time { at := now.Add(-d); return &at }
	measured := func(cefr string, c float64, age time.Duration) Measured {
		return Measured{CEFR: str(cefr), Source: str(SourceMeasured), Confidence: conf(c), ComputedAt: ago(age)}
	}

	cases := []struct {
		name     string
		measured Measured
		stated   string
		want     Level
	}{
		{"measured, confident and fresh wins", measured("A2", 0.8, time.Hour), "B1", Level{"A2", SourceMeasured}},
		{"confidence exactly at the floor counts", measured("B1", 0.6, time.Hour), "A1", Level{"B1", SourceMeasured}},
		{"low confidence falls back to stated", measured("A2", 0.59, time.Hour), "B1", Level{"B1", SourceStated}},
		{"exactly 26 h old still counts", measured("A2", 0.9, 26*time.Hour), "B1", Level{"A2", SourceMeasured}},
		{"stale falls back to stated", measured("A2", 0.9, 26*time.Hour+time.Minute), "B1", Level{"B1", SourceStated}},
		{
			"a stated-source profile is not a measurement",
			Measured{CEFR: str("A2"), Source: str(SourceStated), Confidence: conf(0.9), ComputedAt: ago(time.Hour)},
			"B1", Level{"B1", SourceStated},
		},
		{
			"a measured row without a CEFR estimate falls back",
			Measured{Source: str(SourceMeasured), Confidence: conf(0.9), ComputedAt: ago(time.Hour)},
			"B1", Level{"B1", SourceStated},
		},
		{
			"a measured row without confidence falls back",
			Measured{CEFR: str("A2"), Source: str(SourceMeasured), ComputedAt: ago(time.Hour)},
			"B1", Level{"B1", SourceStated},
		},
		{
			"a measured row without a timestamp falls back",
			Measured{CEFR: str("A2"), Source: str(SourceMeasured), Confidence: conf(0.9)},
			"B1", Level{"B1", SourceStated},
		},
		{"a measured label with no CEFR token falls back", measured("beginner", 0.9, time.Hour), "B1", Level{"B1", SourceStated}},
		{"a measured range names its first step", measured("a2/b1", 0.9, time.Hour), "C1", Level{"A2", SourceMeasured}},
		{"no profile uses stated", Measured{}, "B2", Level{"B2", SourceStated}},
		{"stated is normalized", Measured{}, " b1 ", Level{"B1", SourceStated}},
		{"stated with no CEFR token is the default", Measured{}, "native", Level{"A1", SourceDefault}},
		{"no profile and no stated is A1", Measured{}, "", Level{"A1", SourceDefault}},
		{"stale profile and no stated is A1", measured("C1", 0.9, 48*time.Hour), "", Level{"A1", SourceDefault}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, Choose(tc.measured, tc.stated, now, rule))
		})
	}
}

func TestRuleIsConfigurable(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cefr, source, confidence := "A2", SourceMeasured, 0.7
	at := now.Add(-30 * time.Hour)
	m := Measured{CEFR: &cefr, Source: &source, Confidence: &confidence, ComputedAt: &at}

	require.Equal(t, SourceStated, Choose(m, "B1", now, DefaultRule()).Source)
	loose := Rule{MinConfidence: 0.5, MaxAge: 48 * time.Hour}
	require.Equal(t, Level{"A2", SourceMeasured}, Choose(m, "B1", now, loose))
	strict := Rule{MinConfidence: 0.75, MaxAge: 48 * time.Hour}
	require.Equal(t, SourceStated, Choose(m, "B1", now, strict).Source)
}

func TestDefaultRuleConstants(t *testing.T) {
	require.InDelta(t, 0.6, DefaultRule().MinConfidence, 0)
	require.Equal(t, 26*time.Hour, DefaultRule().MaxAge)
}

func TestStageIsFreshOrEmpty(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	rule := DefaultRule()
	stage := "lapsing"
	since := now.Add(-72 * time.Hour)
	row := func(age time.Duration) Measured {
		at := now.Add(-age)
		return Measured{Stage: &stage, StageSince: &since, ComputedAt: &at}
	}

	got, gotSince := Stage(row(time.Hour), now, rule)
	require.Equal(t, "lapsing", got)
	require.Equal(t, &since, gotSince)

	got, _ = Stage(row(26*time.Hour), now, rule)
	require.Equal(t, "lapsing", got, "exactly 26 h old still counts")

	got, gotSince = Stage(row(26*time.Hour+time.Minute), now, rule)
	require.Empty(t, got, "a stale stage is empty")
	require.Nil(t, gotSince)

	got, _ = Stage(Measured{}, now, rule)
	require.Empty(t, got, "no learner_profiles row, no stage")
}

func TestResolveCombinesLevelAndStage(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cefr, source, conf, stage := "B1", SourceMeasured, 0.9, " steady "
	at := now.Add(-time.Hour)
	got := Resolve(Measured{CEFR: &cefr, Source: &source, Confidence: &conf, ComputedAt: &at, Stage: &stage}, "A1", now, DefaultRule())
	require.Equal(t, "B1", got.Level.Level)
	require.Equal(t, SourceMeasured, got.Source)
	require.Equal(t, "steady", got.Stage)
}
