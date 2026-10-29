// Package learnerlevel is the one resolver for the CEFR level a learner is
// taught at. A measured band (klearn.learner_profiles) wins over the stated
// level while it is confident and fresh, then the stated level, then A1. It
// moves kielo-user-service's effective_level.go here unchanged so every
// service resolves a learner's level the same way; the engine's Python twin is
// services/effective_level.py.
package learnerlevel

import (
	"regexp"
	"strings"
	"time"
)

const (
	// StageNew and NewMaxDays mirror the engine's derive_stage
	// (services/learner_profile.py): new is 0-7 whole days since joining.
	StageNew   = "new"
	NewMaxDays = 7
)

const (
	SourceMeasured = "measured"
	SourceStated   = "stated"
	SourceDefault  = "default"

	DefaultMinConfidence = 0.6
	DefaultMaxAgeHours   = 26

	DefaultLevel = "A1"
)

// Rule is when a measured band is trusted over the stated level.
type Rule struct {
	MinConfidence float64
	MaxAge        time.Duration
}

func DefaultRule() Rule {
	return Rule{
		MinConfidence: DefaultMinConfidence,
		MaxAge:        DefaultMaxAgeHours * time.Hour,
	}
}

// Level is a CEFR level and where it came from.
type Level struct {
	Level  string
	Source string
}

// Result is the effective level plus the lifecycle stage of the same
// learner_profiles row (empty when there is no fresh row).
type Result struct {
	Level
	Stage      string
	StageSince *time.Time
}

// Measured is the learner_profiles row for the user and language; all nil when
// there is none.
type Measured struct {
	CEFR       *string
	Source     *string
	Confidence *float64
	ComputedAt *time.Time
	Stage      *string
	StageSince *time.Time
	// JoinedAt is COALESCE(onboarding_completed_at, created_at), the engine's
	// stage anchor; it decides "new" while no fresh stage is stored.
	JoinedAt *time.Time
}

var cefrToken = regexp.MustCompile(`[ABC][12]`)

// Normalize is the first CEFR step a label names ("A2/B1" -> A2), or "".
func Normalize(level string) string {
	return cefrToken.FindString(strings.ToUpper(level))
}

func (m Measured) usable(now time.Time, rule Rule) bool {
	if m.Source == nil || *m.Source != SourceMeasured || m.CEFR == nil || Normalize(*m.CEFR) == "" {
		return false
	}
	if m.Confidence == nil || m.ComputedAt == nil || *m.Confidence < rule.MinConfidence {
		return false
	}
	return now.Sub(*m.ComputedAt) <= rule.MaxAge
}

// Choose picks the effective level: measured when usable, else the stated
// level, else A1.
func Choose(m Measured, stated string, now time.Time, rule Rule) Level {
	if m.usable(now, rule) {
		return Level{Level: Normalize(*m.CEFR), Source: SourceMeasured}
	}
	if level := Normalize(stated); level != "" {
		return Level{Level: level, Source: SourceStated}
	}
	return Level{Level: DefaultLevel, Source: SourceDefault}
}

// Stage is the lifecycle stage of the same row while it is at most rule.MaxAge
// old, else "".
func Stage(m Measured, now time.Time, rule Rule) (stage string, since *time.Time) {
	if m.Stage == nil || m.ComputedAt == nil || now.Sub(*m.ComputedAt) > rule.MaxAge {
		// No fresh profile stage: a learner within the engine's new window
		// (0-7 whole days since joining) is new. A learner who joined today
		// had no profile yet and got the stretch mix new learners do not
		// (tutor walk, 2026-10-29).
		if m.JoinedAt != nil && wholeDays(now.Sub(*m.JoinedAt)) <= NewMaxDays {
			return StageNew, m.JoinedAt
		}
		return "", nil
	}
	return strings.TrimSpace(*m.Stage), m.StageSince
}

// wholeDays floors a duration to whole days, as the engine's _whole_days does.
func wholeDays(d time.Duration) int {
	if d < 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}

// Resolve is Choose and Stage together.
func Resolve(m Measured, stated string, now time.Time, rule Rule) Result {
	stage, since := Stage(m, now, rule)
	return Result{Level: Choose(m, stated, now, rule), Stage: stage, StageSince: since}
}
