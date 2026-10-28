package audience

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/team-kielo-app/kielo-shared/events"
)

// compiled renders one validated condition, taking its placeholders from the builder.
type compiled func(b *builder) string

type fieldDef struct {
	spec  FieldSpec
	parse func(f fieldDef, op string, raw json.RawMessage) (compiled, error)
}

var fieldOrder = []string{
	"platform", "support_language", "learning_language", "signed_up", "last_active", "plus", "plus_ends",
	"paywall_viewed", "used_feature", "email_marketing", "push_enabled", "campaign",
}

var languageCode = regexp.MustCompile(`^[a-z]{2,3}(-[a-z0-9]{2,8})?$`)

// featureKeys maps the admin's feature names to the users.feature_usage counters the event spine bumps.
var featureKeys = map[string]string{
	"juka":    "ai_conversations",
	"ktv":     "kielotv_watch",
	"reader":  "articles_read",
	"lessons": "exercises_completed",
}

var fieldDefs = map[string]fieldDef{
	"platform": {
		spec: FieldSpec{
			Field: "platform", Label: "Platform",
			Help:    "Where the learner last used Kielo: iPhone or iPad, Android, or the web.",
			Ops:     []OpSpec{{Op: "in", Label: "is any of"}},
			Value:   ValuePlatforms,
			Options: platformOptions,
		},
		parse: parsePlatform,
	},
	"support_language": {
		spec: FieldSpec{
			Field: "support_language", Label: "App language",
			Help:  "The language the learner reads Kielo in. Use language codes such as en or vi.",
			Ops:   []OpSpec{{Op: "in", Label: "is any of"}},
			Value: ValueLanguages,
		},
		parse: parseSupportLanguage,
	},
	"learning_language": {
		spec: FieldSpec{
			Field: "learning_language", Label: "Learning language",
			Help:    "The language the learner is learning now.",
			Ops:     []OpSpec{{Op: "in", Label: "is any of"}},
			Value:   ValueLanguages,
			Options: learningLanguageOptions,
		},
		parse: parseLearningLanguage,
	},
	"signed_up": {
		spec: FieldSpec{
			Field: "signed_up", Label: "Signed up",
			Help:  "When the learner created their account.",
			Ops:   []OpSpec{{Op: "within_days", Label: "in the last (days)"}, {Op: "before_days", Label: "more than (days) ago"}},
			Value: ValueIntDays,
		},
		parse: parseSignedUp,
	},
	"last_active": {
		spec: FieldSpec{
			Field: "last_active", Label: "Last active",
			Help: "The last time the learner did something real in Kielo, such as reading, practising or talking to Juka. " +
				"Learners who never did anything count as not active.",
			Ops:   []OpSpec{{Op: "within_days", Label: "in the last (days)"}, {Op: "not_within_days", Label: "not in the last (days)"}},
			Value: ValueIntDays,
		},
		parse: parseLastActive,
	},
	"plus": {
		spec: FieldSpec{
			Field: "plus", Label: "Kielo Plus",
			Help:    "Whether the learner has paid for Plus, and whether they have it now.",
			Ops:     []OpSpec{{Op: "is", Label: "is"}},
			Value:   ValuePlusState,
			Options: plusOptions,
		},
		parse: parsePlus,
	},
	"plus_ends": {
		spec: FieldSpec{
			Field: "plus_ends", Label: "Plus ends",
			Help:  "Learners whose Plus access runs out soon. Plus that never runs out is not included.",
			Ops:   []OpSpec{{Op: "within_days", Label: "within the next (days)"}},
			Value: ValueIntDays,
		},
		parse: parsePlusEnds,
	},
	"paywall_viewed": {
		spec: FieldSpec{
			Field: "paywall_viewed", Label: "Saw the paywall",
			Help:  "Learners who opened the Plus screen in this time and have not bought Plus since.",
			Ops:   []OpSpec{{Op: "within_days", Label: "in the last (days), and did not buy since"}},
			Value: ValueIntDays,
		},
		parse: parsePaywallViewed,
	},
	"used_feature": {
		spec: FieldSpec{
			Field: "used_feature", Label: "Used a feature",
			Help:    "Learners who used this part of Kielo in this time.",
			Ops:     []OpSpec{{Op: "within_days", Label: "in the last (days)"}},
			Value:   ValueFeatureDays,
			Options: featureOptions,
		},
		parse: parseUsedFeature,
	},
	"email_marketing": {
		spec: FieldSpec{
			Field: "email_marketing", Label: "Can get marketing email",
			Help: "Learners who agreed to marketing email, have not opted out, and whose address works. " +
				"The same rules as an email campaign.",
			Ops:   []OpSpec{{Op: "is", Label: "is"}},
			Value: ValueBool,
		},
		parse: parseEmailMarketing,
	},
	"push_enabled": {
		spec: FieldSpec{
			Field: "push_enabled", Label: "Can get push notifications",
			Help:  "Learners with the app installed on a phone and push notifications switched on.",
			Ops:   []OpSpec{{Op: "is", Label: "is"}},
			Value: ValueBool,
		},
		parse: parsePushEnabled,
	},
	"campaign": {
		spec: FieldSpec{
			Field: "campaign", Label: "Discount campaign",
			Help: "Learners who were shown, or tapped, a discount campaign in this time.",
			Ops: []OpSpec{
				{Op: "shown_within_days", Label: "was shown it in the last (days)"},
				{Op: "clicked_within_days", Label: "tapped it in the last (days)"},
			},
			Value: ValueCampaignDays,
		},
		parse: parseCampaign,
	},
}

func decodeDays(f fieldDef, raw json.RawMessage) (int, error) {
	var n int
	if err := decodeStrict(raw, &n); err != nil {
		return 0, fmt.Errorf("%s needs a whole number of days from 1 to %d", f.spec.Label, MaxDays)
	}
	return checkDays(f.spec.Label, n)
}

func checkDays(label string, n int) (int, error) {
	if n < 1 || n > MaxDays {
		return 0, fmt.Errorf("%s needs a whole number of days from 1 to %d", label, MaxDays)
	}
	return n, nil
}

func decodeChoices(f fieldDef, raw json.RawMessage, allowed []Option) ([]string, error) {
	var values []string
	if err := decodeStrict(raw, &values); err != nil || len(values) == 0 {
		return nil, fmt.Errorf("%s needs a list with at least one choice", f.spec.Label)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		ok := false
		for _, o := range allowed {
			ok = ok || o.Value == v
		}
		if !ok {
			return nil, fmt.Errorf("%s does not have a choice called %q", f.spec.Label, v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

func decodeLanguages(f fieldDef, raw json.RawMessage) ([]string, error) {
	var values []string
	if err := decodeStrict(raw, &values); err != nil || len(values) == 0 {
		return nil, fmt.Errorf("%s needs a list of language codes such as [\"en\"]", f.spec.Label)
	}
	if len(values) > MaxLanguages {
		return nil, fmt.Errorf("%s can list at most %d languages", f.spec.Label, MaxLanguages)
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		code := strings.ToLower(strings.TrimSpace(v))
		if !languageCode.MatchString(code) {
			return nil, fmt.Errorf("%q is not a language code; use codes such as en or vi", v)
		}
		out = append(out, code)
	}
	return out, nil
}

func requireTrue(f fieldDef, raw json.RawMessage) error {
	var v bool
	if err := decodeStrict(raw, &v); err != nil || !v {
		return fmt.Errorf("%s can only be set to yes (true)", f.spec.Label)
	}
	return nil
}

func parsePlatform(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	platforms, err := decodeChoices(f, raw, platformOptions)
	if err != nil {
		return nil, err
	}
	return func(b *builder) string {
		return "COALESCE(" +
			"(SELECT pt.platform FROM users.push_tokens pt WHERE pt.user_id = u.id ORDER BY pt.updated_at DESC LIMIT 1), " +
			"(SELECT ua.context->>'platform' FROM events.user_actions ua WHERE ua.user_id = u.id " +
			"AND ua.context->>'platform' IS NOT NULL ORDER BY ua.ts DESC LIMIT 1)" +
			") = ANY(" + b.arg(platforms) + "::text[])"
	}, nil
}

func parseSupportLanguage(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	codes, err := decodeLanguages(f, raw)
	if err != nil {
		return nil, err
	}
	return func(b *builder) string {
		return "COALESCE(NULLIF(lower(btrim(u.support_language_code)), ''), 'en') = ANY(" + b.arg(codes) + "::text[])"
	}, nil
}

func parseLearningLanguage(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	codes, err := decodeLanguages(f, raw)
	if err != nil {
		return nil, err
	}
	return func(b *builder) string {
		return "lower(btrim(u.learning_language)) = ANY(" + b.arg(codes) + "::text[])"
	}, nil
}

func parseSignedUp(f fieldDef, op string, raw json.RawMessage) (compiled, error) {
	days, err := decodeDays(f, raw)
	if err != nil {
		return nil, err
	}
	cmp := ">="
	if op == "before_days" {
		cmp = "<"
	}
	return func(b *builder) string {
		return "u.created_at " + cmp + " now() - make_interval(days => " + b.arg(days) + "::int)"
	}, nil
}

func parseLastActive(f fieldDef, op string, raw json.RawMessage) (compiled, error) {
	days, err := decodeDays(f, raw)
	if err != nil {
		return nil, err
	}
	not := ""
	if op == "not_within_days" {
		not = "NOT "
	}
	return func(b *builder) string {
		return not + "EXISTS (SELECT 1 FROM users.meaningful_activity_v1 ma WHERE ma.user_id = u.id " +
			"AND ma.last_meaningful_activity_at >= now() - make_interval(days => " + b.arg(days) + "::int))"
	}, nil
}

const (
	entitled      = "EXISTS (SELECT 1 FROM users.entitlement_v1 e WHERE e.user_id = u.id AND e.entitled"
	everPaid      = "EXISTS (SELECT 1 FROM users.growth_charges_v1 c WHERE c.user_id = u.id)"
	plusSQLNone   = "NOT " + entitled + ")"
	plusSQLAny    = entitled + ")"
	plusSQLPaid   = entitled + " AND e.source = 'store')"
	plusSQLPromo  = entitled + " AND e.source <> 'store')"
	plusSQLNever  = "NOT " + everPaid
	plusSQLBefore = everPaid + " AND " + plusSQLNone
)

var plusStates = map[string]string{
	"never_paid":   plusSQLNever,
	"paid_before":  plusSQLBefore,
	"paid_active":  plusSQLPaid,
	"promo_active": plusSQLPromo,
	"any_active":   plusSQLAny,
	"none":         plusSQLNone,
}

func parsePlus(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	var state string
	if err := decodeStrict(raw, &state); err != nil {
		return nil, fmt.Errorf("%s needs one choice from the list", f.spec.Label)
	}
	sql, ok := plusStates[state]
	if !ok {
		return nil, fmt.Errorf("%s does not have a choice called %q", f.spec.Label, state)
	}
	return func(*builder) string { return sql }, nil
}

func parsePlusEnds(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	days, err := decodeDays(f, raw)
	if err != nil {
		return nil, err
	}
	return func(b *builder) string {
		return entitled + " AND e.expires_at IS NOT NULL AND e.expires_at > now() " +
			"AND e.expires_at <= now() + make_interval(days => " + b.arg(days) + "::int))"
	}, nil
}

func parsePaywallViewed(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	days, err := decodeDays(f, raw)
	if err != nil {
		return nil, err
	}
	return func(b *builder) string {
		return "EXISTS (SELECT 1 FROM events.user_actions v WHERE v.user_id = u.id " +
			"AND v.event_type = " + b.arg(string(events.EventPaywallViewed)) + "::text " +
			"AND v.ts >= now() - make_interval(days => " + b.arg(days) + "::int) " +
			"AND NOT EXISTS (SELECT 1 FROM users.growth_charges_v1 c WHERE c.user_id = u.id " +
			"AND c.kind = 'new' AND c.charged_at > v.ts))"
	}, nil
}

func parseUsedFeature(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	var v struct {
		Feature string `json:"feature"`
		Days    int    `json:"days"`
	}
	if err := decodeStrict(raw, &v); err != nil {
		return nil, errors.New(f.spec.Label + ` needs a feature and a number of days, such as {"feature":"juka","days":7}`)
	}
	key, ok := featureKeys[v.Feature]
	if !ok {
		return nil, fmt.Errorf("%s does not have a choice called %q", f.spec.Label, v.Feature)
	}
	days, err := checkDays(f.spec.Label, v.Days)
	if err != nil {
		return nil, err
	}
	return func(b *builder) string {
		return "EXISTS (SELECT 1 FROM users.feature_usage fu WHERE fu.user_id = u.id " +
			"AND fu.feature = " + b.arg(key) + "::text AND fu.usage_count > 0 " +
			"AND fu.period_start >= (now() - make_interval(days => " + b.arg(days) + "::int))::date)"
	}, nil
}

func parseEmailMarketing(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	if err := requireTrue(f, raw); err != nil {
		return nil, err
	}
	return func(*builder) string {
		return "u.newsletter_consent IS TRUE AND btrim(u.email) <> '' " +
			"AND lower(u.email) NOT LIKE '%@guest.kielo.invalid' AND lower(btrim(u.email)) NOT LIKE '%@kielo.app' " +
			"AND NOT EXISTS (SELECT 1 FROM communications.email_opt_outs o WHERE o.user_id = u.id AND o.category = 'marketing') " +
			"AND NOT EXISTS (SELECT 1 FROM communications.email_suppression_list sl WHERE sl.email_address = lower(btrim(u.email)) " +
			"AND (sl.category <> 'soft_bounce' OR sl.suppressed_until IS NULL OR sl.suppressed_until > now()))"
	}, nil
}

func parsePushEnabled(f fieldDef, _ string, raw json.RawMessage) (compiled, error) {
	if err := requireTrue(f, raw); err != nil {
		return nil, err
	}
	return func(*builder) string {
		return "EXISTS (SELECT 1 FROM users.push_tokens pt WHERE pt.user_id = u.id) " +
			"AND NOT EXISTS (SELECT 1 FROM users.device_preferences dp WHERE dp.user_id = u.id " +
			"AND COALESCE(dp.notifications->'push'->>'enabled', dp.notifications->>'enabled') = 'false')"
	}, nil
}

func parseCampaign(f fieldDef, op string, raw json.RawMessage) (compiled, error) {
	var v struct {
		CampaignID string `json:"campaign_id"`
		Days       int    `json:"days"`
	}
	if err := decodeStrict(raw, &v); err != nil {
		return nil, errors.New(f.spec.Label + ` needs a campaign and a number of days, such as {"campaign_id":"...","days":14}`)
	}
	id, err := uuid.Parse(v.CampaignID)
	if err != nil {
		return nil, fmt.Errorf("%s needs a valid campaign id", f.spec.Label)
	}
	days, err := checkDays(f.spec.Label, v.Days)
	if err != nil {
		return nil, err
	}
	event := "shown"
	if op == "clicked_within_days" {
		event = "clicked"
	}
	return func(b *builder) string {
		return "EXISTS (SELECT 1 FROM users.discount_campaign_events dce WHERE dce.user_id = u.id " +
			"AND dce.campaign_id = " + b.arg(id.String()) + "::uuid AND dce.event = " + b.arg(event) + "::text AND NOT dce.sandbox " +
			"AND dce.at >= now() - make_interval(days => " + b.arg(days) + "::int))"
	}, nil
}
