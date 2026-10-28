// Package learnerintent is the one definition of a learner's intent profile:
// what they came for (onboarding goal) and what they actually do (minutes per
// content type, how often and how long they show up). It is computed on read
// from users.feature_usage and users.users.learning_reason; nothing is stored.
//
// Resolve is the pure resolver, Load the batch loader. Services must not copy
// either: read the profile from here (or from user-service's internal profile
// response, which embeds it) so every surface agrees on the same learner.
package learnerintent

import (
	"math"
	"sort"
	"strings"
	"time"
)

const (
	TypeReading      = "reading"
	TypeVideo        = "video"
	TypeConversation = "conversation"
	TypePractice     = "practice"
)

// ContentTypes is the closed set of content types, in tie-break order.
var ContentTypes = []string{TypeReading, TypeVideo, TypeConversation, TypePractice}

const (
	SourceBehavior  = "behavior"
	SourceGoal      = "goal"
	SourceColdStart = "cold_start"
)

const (
	SessionShort  = "short"
	SessionMedium = "medium"
	SessionLong   = "long"
)

const (
	// DefaultWindowDays is how far back usage counts. Long enough to smooth a
	// holiday week, short enough that a changed habit shows within weeks.
	DefaultWindowDays = 60

	// PriorWeightMinutes is K: the prior counts as this many minutes of
	// evidence, split across the four types. A learner needs a few multiples of
	// K minutes before behavior dominates the prior.
	PriorWeightMinutes = 30.0

	// TopTypeMinMinutes is the least total minutes in the window before a
	// top_type is named.
	TopTypeMinMinutes = 20.0

	// TopTypeMargin is how far the leading smoothed share must beat the second.
	TopTypeMargin = 0.10

	// ShortSessionBelow and LongSessionAbove bound the medium session bucket
	// (minutes per active day): short < 5, medium 5-12, long > 12.
	ShortSessionBelow = 5.0
	LongSessionAbove  = 12.0
)

// Feature names read from users.feature_usage. Units follow
// user-service internal/featuremap: time_spent:* are minutes, the two
// *_seconds features are seconds.
const (
	FeatureVisit        = "time_spent:visit"
	FeaturePractice     = "time_spent:practice"
	FeatureReading      = "time_spent:reading"
	FeatureVideoSeconds = "kielotv_watch_seconds"
	FeatureConvoSeconds = "convo_seconds_daily"
)

// Features lists every feature the resolver reads; the loader selects only
// these.
func Features() []string {
	return []string{FeatureVisit, FeaturePractice, FeatureReading, FeatureVideoSeconds, FeatureConvoSeconds}
}

// GoalPrior maps an onboarding goal (users.learning_reason) to prior shares
// over ContentTypes. It is deliberately empty: which goal leans toward which
// content is a product decision awaiting review, so every goal currently uses
// the flat prior. Filling it needs no other change; shares are normalized.
var GoalPrior = map[string]map[string]float64{}

// UsageRow is one users.feature_usage row.
type UsageRow struct {
	Feature     string
	PeriodStart time.Time
	UsageCount  int
}

// Profile is the shared learner intent profile.
type Profile struct {
	Goal                 string             `json:"goal"`
	TypeMinutes          map[string]float64 `json:"type_minutes"`
	TypeShare            map[string]float64 `json:"type_share"`
	TopType              string             `json:"top_type"`
	ActiveDays           int                `json:"active_days"`
	SessionMinutesPerDay float64            `json:"session_minutes_per_day"`
	SessionLen           string             `json:"session_len"`
	WindowDays           int                `json:"window_days"`
	Sources              map[string]string  `json:"sources"`
	ComputedAt           time.Time          `json:"computed_at"`
}

// WindowStart is the first day (UTC date) a window ending at now includes.
func WindowStart(now time.Time, window int) time.Time {
	if window <= 0 {
		window = DefaultWindowDays
	}
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(window - 1))
}

type dayTotals struct {
	visit    float64
	activity bool
}

// Resolve computes the profile from a learner's rows. Rows before the window
// and rows for features the resolver does not read are ignored.
//
// session_minutes_per_day is the median, over active days with a visit credit,
// of that day's time_spent:visit minutes; the median keeps one marathon day
// from lifting the bucket.
func Resolve(goal string, rows []UsageRow, now time.Time, window int) Profile {
	if window <= 0 {
		window = DefaultWindowDays
	}
	goal = strings.ToLower(strings.TrimSpace(goal))
	start := WindowStart(now, window)

	seconds, days := aggregate(rows, start)

	minutes := make(map[string]float64, len(ContentTypes))
	total := 0.0
	for _, t := range ContentTypes {
		minutes[t] = seconds[t] / 60
		total += minutes[t]
	}

	p := Profile{
		Goal:        goal,
		TypeMinutes: make(map[string]float64, len(ContentTypes)),
		WindowDays:  window,
		ComputedAt:  now.UTC(),
	}
	for _, t := range ContentTypes {
		p.TypeMinutes[t] = round1(minutes[t])
	}

	prior, goalPrior := priorShares(goal)
	p.TypeShare = smooth(minutes, total, prior)
	p.TopType = topType(p.TypeShare, total)

	var visits []float64
	for _, dt := range days {
		if dt.activity {
			p.ActiveDays++
		}
		if dt.activity && dt.visit > 0 {
			visits = append(visits, dt.visit)
		}
	}
	if len(visits) > 0 {
		p.SessionMinutesPerDay = round1(median(visits))
		p.SessionLen = sessionBucket(p.SessionMinutesPerDay)
	}

	p.Sources = sources(goal != "", total > 0, goalPrior, p, len(visits) > 0)
	return p
}

func sources(hasGoal, hasMinutes, goalPrior bool, p Profile, hasVisits bool) map[string]string {
	s := map[string]string{
		"goal":                    pick(hasGoal, SourceGoal),
		"type_minutes":            pick(hasMinutes, SourceBehavior),
		"top_type":                pick(p.TopType != "", SourceBehavior),
		"active_days":             pick(p.ActiveDays > 0, SourceBehavior),
		"session_minutes_per_day": pick(hasVisits, SourceBehavior),
		"session_len":             pick(p.SessionLen != "", SourceBehavior),
	}
	switch {
	case hasMinutes:
		s["type_share"] = SourceBehavior
	case goalPrior:
		s["type_share"] = SourceGoal
	default:
		s["type_share"] = SourceColdStart
	}
	return s
}

func aggregate(rows []UsageRow, start time.Time) (seconds map[string]float64, days map[string]*dayTotals) {
	seconds = map[string]float64{}
	days = map[string]*dayTotals{}
	for _, r := range rows {
		if r.UsageCount <= 0 {
			continue
		}
		t := classify(r.Feature)
		if t == "" {
			continue
		}
		day := r.PeriodStart.UTC().Truncate(24 * time.Hour)
		if day.Before(start) {
			continue
		}
		key := day.Format("2006-01-02")
		dt := days[key]
		if dt == nil {
			dt = &dayTotals{}
			days[key] = dt
		}
		dt.activity = true
		n := float64(r.UsageCount)
		switch r.Feature {
		case FeatureVisit:
			dt.visit += n
		case FeatureVideoSeconds, FeatureConvoSeconds:
			seconds[t] += n
		default:
			seconds[t] += n * 60
		}
	}
	return seconds, days
}

func classify(feature string) string {
	switch feature {
	case FeatureVisit:
		return "visit"
	case FeaturePractice:
		return TypePractice
	case FeatureReading:
		return TypeReading
	case FeatureVideoSeconds:
		return TypeVideo
	case FeatureConvoSeconds:
		return TypeConversation
	}
	return ""
}

func pick(ok bool, source string) string {
	if ok {
		return source
	}
	return SourceColdStart
}

func priorShares(goal string) (map[string]float64, bool) {
	flat := make(map[string]float64, len(ContentTypes))
	for _, t := range ContentTypes {
		flat[t] = 1 / float64(len(ContentTypes))
	}
	raw, ok := GoalPrior[goal]
	if !ok {
		return flat, false
	}
	sum := 0.0
	for _, t := range ContentTypes {
		if v := raw[t]; v > 0 {
			sum += v
		}
	}
	if sum <= 0 {
		return flat, false
	}
	out := make(map[string]float64, len(ContentTypes))
	for _, t := range ContentTypes {
		out[t] = math.Max(raw[t], 0) / sum
	}
	return out, true
}

func smooth(minutes map[string]float64, total float64, prior map[string]float64) map[string]float64 {
	share := make(map[string]float64, len(ContentTypes))
	for _, t := range ContentTypes {
		share[t] = round3((minutes[t] + PriorWeightMinutes*prior[t]) / (total + PriorWeightMinutes))
	}
	return share
}

func topType(share map[string]float64, total float64) string {
	if total < TopTypeMinMinutes {
		return ""
	}
	order := append([]string(nil), ContentTypes...)
	sort.SliceStable(order, func(i, j int) bool { return share[order[i]] > share[order[j]] })
	if share[order[0]]-share[order[1]] < TopTypeMargin {
		return ""
	}
	return order[0]
}

func sessionBucket(minutes float64) string {
	switch {
	case minutes < ShortSessionBelow:
		return SessionShort
	case minutes > LongSessionAbove:
		return SessionLong
	}
	return SessionMedium
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round3(v float64) float64 { return math.Round(v*1000) / 1000 }
