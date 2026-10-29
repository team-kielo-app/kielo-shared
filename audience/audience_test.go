package audience

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const campaignID = "0b8f7f0e-5a39-4c3c-9c53-5d0c4b6d7a11"

func cond(field, op, value string) Condition {
	return Condition{Field: field, Op: op, Value: json.RawMessage(value)}
}

func def(conds ...Condition) Definition { return Definition{Version: Version, All: conds} }

func TestValidate_RejectsBadShapes(t *testing.T) {
	tooMany := make([]Condition, MaxConditions+1)
	for i := range tooMany {
		tooMany[i] = cond("plus", "is", `"none"`)
	}
	tests := []struct {
		name string
		def  Definition
		want string
	}{
		{"wrong version", Definition{Version: 2}, "only version 1"},
		{"zero version", Definition{}, "only version 1"},
		{"too many conditions", Definition{Version: Version, All: tooMany}, "at most 20 conditions"},
		{"unknown field", def(cond("shoe_size", "is", `1`)), `"shoe_size" is not something`},
		{"unknown op", def(cond("platform", "is", `["ios"]`)), `Platform cannot be combined with "is"; use "in"`},
		{"op of another field", def(cond("signed_up", "not_within_days", `3`)), `use "within_days" or "before_days"`},
		{"missing value", def(Condition{Field: "signed_up", Op: "within_days"}), "whole number of days"},
		{"platform not a list", def(cond("platform", "in", `"ios"`)), "needs a list with at least one choice"},
		{"platform empty", def(cond("platform", "in", `[]`)), "needs a list with at least one choice"},
		{"platform unknown", def(cond("platform", "in", `["windows"]`)), `does not have a choice called "windows"`},
		{"support language not a code", def(cond("support_language", "in", `["English"]`)), `"English" is not a language code`},
		{"support language empty", def(cond("support_language", "in", `[]`)), "list of language codes"},
		{"learning language number", def(cond("learning_language", "in", `[1]`)), "list of language codes"},
		{"days zero", def(cond("signed_up", "within_days", `0`)), "from 1 to 3650"},
		{"days negative", def(cond("last_active", "within_days", `-3`)), "from 1 to 3650"},
		{"days too big", def(cond("plus_ends", "within_days", `3651`)), "from 1 to 3650"},
		{"days fraction", def(cond("paywall_viewed", "within_days", `1.5`)), "whole number of days"},
		{"days string", def(cond("signed_up", "before_days", `"7"`)), "whole number of days"},
		{"plus unknown state", def(cond("plus", "is", `"gold"`)), `does not have a choice called "gold"`},
		{"plus not a string", def(cond("plus", "is", `["none"]`)), "needs one choice"},
		{"feature unknown", def(cond("used_feature", "within_days", `{"feature":"chess","days":3}`)), `does not have a choice called "chess"`},
		{"feature days missing", def(cond("used_feature", "within_days", `{"feature":"juka"}`)), "from 1 to 3650"},
		{"feature extra key", def(cond("used_feature", "within_days", `{"feature":"juka","days":3,"x":1}`)), "needs a feature and a number of days"},
		{"feature not an object", def(cond("used_feature", "within_days", `7`)), "needs a feature and a number of days"},
		{"email false", def(cond("email_marketing", "is", `false`)), "can only be set to yes"},
		{"push string", def(cond("push_enabled", "is", `"true"`)), "can only be set to yes"},
		{"campaign bad id", def(cond("campaign", "shown_within_days", `{"campaign_id":"abc","days":3}`)), "valid campaign id"},
		{"campaign days", def(cond("campaign", "clicked_within_days", `{"campaign_id":"`+campaignID+`","days":0}`)), "from 1 to 3650"},
		{"campaign not an object", def(cond("campaign", "clicked_within_days", `"x"`)), "needs a campaign and a number of days"},
		{"second condition reported by number", def(cond("plus", "is", `"none"`), cond("plus", "is", `"gold"`)), "condition 2:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.def.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestValidate_AcceptsEmptyAndFullDefinitions(t *testing.T) {
	require.NoError(t, Definition{Version: Version}.Validate())
	require.NoError(t, def(
		cond("platform", "in", `["ios","android","web"]`),
		cond("support_language", "in", `["en","vi","pt-br"]`),
		cond("learning_language", "in", `["fi"]`),
		cond("signed_up", "before_days", `30`),
		cond("last_active", "not_within_days", `14`),
		cond("plus", "is", `"never_paid"`),
		cond("plus_ends", "within_days", `3`),
		cond("paywall_viewed", "within_days", `7`),
		cond("used_feature", "within_days", `{"feature":"ktv","days":7}`),
		cond("email_marketing", "is", `true`),
		cond("push_enabled", "is", `true`),
		cond("campaign", "clicked_within_days", `{"campaign_id":"`+campaignID+`","days":14}`),
	).Validate())
	all := make([]Condition, MaxConditions)
	for i := range all {
		all[i] = cond("plus", "is", `"none"`)
	}
	require.NoError(t, Definition{Version: Version, All: all}.Validate())
}

func TestParse(t *testing.T) {
	d, err := Parse([]byte(`{"version":1,"all":[{"field":"plus","op":"is","value":"none"}]}`))
	require.NoError(t, err)
	require.Len(t, d.All, 1)
	assert.Equal(t, "plus", d.All[0].Field)

	d, err = Parse([]byte(`{"version":1,"all":[]}`))
	require.NoError(t, err)
	assert.Empty(t, d.All)

	for name, raw := range map[string]string{
		"not json":      `nope`,
		"unknown key":   `{"version":1,"all":[],"any":[]}`,
		"trailing data": `{"version":1,"all":[]} {}`,
		"bad version":   `{"version":3,"all":[]}`,
		"bad condition": `{"version":1,"all":[{"field":"plus","op":"is","value":"gold"}]}`,
		"condition key": `{"version":1,"all":[{"field":"plus","op":"is","value":"none","extra":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(raw))
			assert.Error(t, err)
		})
	}
}

const (
	realSQL = "EXISTS (SELECT 1 FROM users.learner_class_v1 lc WHERE lc.user_id = u.id AND lc.class = 'real')"
	entSQL  = "EXISTS (SELECT 1 FROM users.entitlement_v1 e WHERE e.user_id = u.id AND e.entitled"
	paidSQL = "EXISTS (SELECT 1 FROM users.growth_charges_v1 c WHERE c.user_id = u.id)"
)

func TestMembers_GoldenSQLPerCondition(t *testing.T) {
	tests := []struct {
		name     string
		cond     Condition
		wantSQL  string
		wantArgs []any
	}{
		{
			"platform", cond("platform", "in", `["ios","web","ios"]`),
			"COALESCE((SELECT pt.platform FROM users.push_tokens pt WHERE pt.user_id = u.id ORDER BY pt.updated_at DESC LIMIT 1), " +
				"(SELECT ua.context->>'platform' FROM events.user_actions ua WHERE ua.user_id = u.id " +
				"AND ua.context->>'platform' IS NOT NULL ORDER BY ua.ts DESC LIMIT 1)) = ANY($1::text[])",
			[]any{[]string{"ios", "web"}},
		},
		{
			"support_language", cond("support_language", "in", `["EN"," vi "]`),
			"COALESCE(NULLIF(lower(btrim(u.support_language_code)), ''), 'en') = ANY($1::text[])",
			[]any{[]string{"en", "vi"}},
		},
		{
			"learning_language", cond("learning_language", "in", `["fi"]`),
			"lower(btrim(u.learning_language)) = ANY($1::text[])",
			[]any{[]string{"fi"}},
		},
		{
			"signed_up within", cond("signed_up", "within_days", `7`),
			"u.created_at >= now() - make_interval(days => $1::int)", []any{7},
		},
		{
			"signed_up before", cond("signed_up", "before_days", `30`),
			"u.created_at < now() - make_interval(days => $1::int)", []any{30},
		},
		{
			"last_active within", cond("last_active", "within_days", `3`),
			"EXISTS (SELECT 1 FROM users.meaningful_activity_v1 ma WHERE ma.user_id = u.id " +
				"AND ma.last_meaningful_activity_at >= now() - make_interval(days => $1::int))",
			[]any{3},
		},
		{
			"last_active not within", cond("last_active", "not_within_days", `14`),
			"NOT EXISTS (SELECT 1 FROM users.meaningful_activity_v1 ma WHERE ma.user_id = u.id " +
				"AND ma.last_meaningful_activity_at >= now() - make_interval(days => $1::int))",
			[]any{14},
		},
		{"plus never_paid", cond("plus", "is", `"never_paid"`), "NOT " + paidSQL, nil},
		{"plus paid_before", cond("plus", "is", `"paid_before"`), paidSQL + " AND NOT " + entSQL + ")", nil},
		{"plus paid_active", cond("plus", "is", `"paid_active"`), entSQL + " AND e.source = 'store')", nil},
		{"plus promo_active", cond("plus", "is", `"promo_active"`), entSQL + " AND e.source <> 'store')", nil},
		{"plus any_active", cond("plus", "is", `"any_active"`), entSQL + ")", nil},
		{"plus none", cond("plus", "is", `"none"`), "NOT " + entSQL + ")", nil},
		{
			"plus_ends", cond("plus_ends", "within_days", `3`),
			entSQL + " AND e.expires_at IS NOT NULL AND e.expires_at > now() " +
				"AND e.expires_at <= now() + make_interval(days => $1::int))",
			[]any{3},
		},
		{
			"paywall_viewed", cond("paywall_viewed", "within_days", `7`),
			"EXISTS (SELECT 1 FROM events.user_actions v WHERE v.user_id = u.id AND v.event_type = $1::text " +
				"AND v.ts >= now() - make_interval(days => $2::int) " +
				"AND NOT EXISTS (SELECT 1 FROM users.growth_charges_v1 c WHERE c.user_id = u.id " +
				"AND c.kind = 'new' AND c.charged_at > v.ts))",
			[]any{"paywall.viewed", 7},
		},
		{
			"used_feature juka", cond("used_feature", "within_days", `{"feature":"juka","days":7}`),
			"EXISTS (SELECT 1 FROM users.feature_usage fu WHERE fu.user_id = u.id AND fu.feature = $1::text AND fu.usage_count > 0 " +
				"AND fu.period_start >= (now() - make_interval(days => $2::int))::date)",
			[]any{"ai_conversations", 7},
		},
		{
			"email_marketing", cond("email_marketing", "is", `true`),
			"u.newsletter_consent IS TRUE AND btrim(u.email) <> '' " +
				"AND lower(u.email) NOT LIKE '%@guest.kielo.invalid' AND lower(btrim(u.email)) NOT LIKE '%@kielo.app' " +
				"AND NOT EXISTS (SELECT 1 FROM communications.email_opt_outs o WHERE o.user_id = u.id AND o.category = 'marketing') " +
				"AND NOT EXISTS (SELECT 1 FROM communications.email_suppression_list sl WHERE sl.email_address = lower(btrim(u.email)) " +
				"AND (sl.category <> 'soft_bounce' OR sl.suppressed_until IS NULL OR sl.suppressed_until > now()))",
			nil,
		},
		{
			"push_enabled", cond("push_enabled", "is", `true`),
			"EXISTS (SELECT 1 FROM users.push_tokens pt WHERE pt.user_id = u.id) " +
				"AND NOT EXISTS (SELECT 1 FROM users.device_preferences dp WHERE dp.user_id = u.id " +
				"AND COALESCE(dp.notifications->'push'->>'enabled', dp.notifications->>'enabled') = 'false')",
			nil,
		},
		{
			"campaign shown", cond("campaign", "shown_within_days", `{"campaign_id":"`+campaignID+`","days":14}`),
			"EXISTS (SELECT 1 FROM users.discount_campaign_events dce WHERE dce.user_id = u.id " +
				"AND dce.campaign_id = $1::uuid AND dce.event = $2::text AND NOT dce.sandbox " +
				"AND dce.at >= now() - make_interval(days => $3::int))",
			[]any{campaignID, "shown", 14},
		},
		{
			"campaign clicked", cond("campaign", "clicked_within_days", `{"campaign_id":"`+campaignID+`","days":2}`),
			"EXISTS (SELECT 1 FROM users.discount_campaign_events dce WHERE dce.user_id = u.id " +
				"AND dce.campaign_id = $1::uuid AND dce.event = $2::text AND NOT dce.sandbox " +
				"AND dce.at >= now() - make_interval(days => $3::int))",
			[]any{campaignID, "clicked", 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := def(tt.cond).Members(1)
			require.NoError(t, err)
			assert.Equal(t, "SELECT u.id FROM users.users u WHERE "+realSQL+" AND "+tt.wantSQL, q.SQL)
			assert.Equal(t, tt.wantArgs, q.Args)
		})
	}
}

func TestMembers_FeatureKeys(t *testing.T) {
	want := map[string]string{"juka": "ai_conversations", "ktv": "kielotv_watch", "reader": "articles_read", "lessons": "exercises_completed"}
	for feature, key := range want {
		q, err := def(cond("used_feature", "within_days", fmt.Sprintf(`{"feature":%q,"days":1}`, feature))).Members(1)
		require.NoError(t, err)
		assert.Equal(t, []any{key, 1}, q.Args, feature)
	}
}

func TestMembers_EmptyDefinitionIsEveryRealLearner(t *testing.T) {
	q, err := Definition{Version: Version}.Members(1)
	require.NoError(t, err)
	assert.Equal(t, "SELECT u.id FROM users.users u WHERE "+realSQL, q.SQL)
	assert.Empty(t, q.Args)
}

func TestMembers_NumbersPlaceholdersFromFirstArg(t *testing.T) {
	d := def(
		cond("signed_up", "within_days", `7`),
		cond("platform", "in", `["ios"]`),
		cond("used_feature", "within_days", `{"feature":"reader","days":30}`),
	)
	q, err := d.Members(4)
	require.NoError(t, err)
	assert.Equal(t, []any{7, []string{"ios"}, "articles_read", 30}, q.Args)
	assert.Contains(t, q.SQL, "make_interval(days => $4::int)")
	assert.Contains(t, q.SQL, "= ANY($5::text[])")
	assert.Contains(t, q.SQL, "fu.feature = $6::text")
	assert.Contains(t, q.SQL, "make_interval(days => $7::int)")
	assert.NotContains(t, q.SQL, "$1")
	assert.NotContains(t, q.SQL, "$8")
}

func TestMembers_NeverInterpolatesValues(t *testing.T) {
	d := def(
		cond("support_language", "in", `["en"]`),
		cond("used_feature", "within_days", `{"feature":"juka","days":99}`),
		cond("campaign", "shown_within_days", `{"campaign_id":"`+campaignID+`","days":77}`),
	)
	q, err := d.Members(1)
	require.NoError(t, err)
	for _, v := range []string{"99", "77", campaignID, "ai_conversations"} {
		assert.NotContains(t, q.SQL, v)
	}
}

func TestMembers_RejectsInvalidInputs(t *testing.T) {
	_, err := def(cond("plus", "is", `"gold"`)).Members(1)
	require.Error(t, err)
	_, err = Definition{Version: Version}.Members(0)
	require.Error(t, err)
}

func TestCount_Shape(t *testing.T) {
	d := def(cond("signed_up", "within_days", `7`))
	q, err := d.Count(3)
	require.NoError(t, err)
	assert.Equal(t, "SELECT count(*) FROM users.users u WHERE "+realSQL+" AND u.created_at >= now() - make_interval(days => $3::int)", q.SQL)
	assert.Equal(t, []any{7}, q.Args)
}

func TestMember_Shape(t *testing.T) {
	d := def(cond("signed_up", "within_days", `7`))
	q, err := d.Member(1, 2)
	require.NoError(t, err)
	assert.Equal(t, "SELECT EXISTS (SELECT 1 FROM users.users u WHERE u.id = $1::uuid AND "+realSQL+
		" AND u.created_at >= now() - make_interval(days => $2::int))", q.SQL)
	assert.Equal(t, []any{7}, q.Args)

	q, err = d.Member(9, 2)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(q.SQL, "SELECT EXISTS (SELECT 1 FROM users.users u WHERE u.id = $9::uuid AND "))

	_, err = d.Member(2, 2)
	require.Error(t, err, "learner placeholder inside the audience's range")
	_, err = d.Member(0, 1)
	require.Error(t, err)
}

func TestMember_UserArgMayShareNumberWithEmptyAudience(t *testing.T) {
	q, err := Definition{Version: Version}.Member(1, 1)
	require.NoError(t, err)
	assert.Empty(t, q.Args)
}

func TestCatalog_Complete(t *testing.T) {
	catalog := Catalog()
	assert.Len(t, catalog, len(fieldDefs))
	valueKinds := map[string]bool{
		ValueLanguages: true, ValuePlatforms: true, ValueIntDays: true, ValuePlusState: true,
		ValueFeatureDays: true, ValueCampaignDays: true, ValueBool: true,
	}
	seen := map[string]bool{}
	for _, f := range catalog {
		assert.False(t, seen[f.Field], f.Field)
		seen[f.Field] = true
		assert.NotEmpty(t, f.Label, f.Field)
		assert.NotEmpty(t, f.Help, f.Field)
		assert.True(t, valueKinds[f.Value], f.Field)
		require.NotEmpty(t, f.Ops, f.Field)
		for _, op := range f.Ops {
			assert.NotEmpty(t, op.Op, f.Field)
			assert.NotEmpty(t, op.Label, f.Field)
		}
		for _, o := range f.Options {
			assert.NotEmpty(t, o.Value, f.Field)
			assert.NotEmpty(t, o.Label, f.Field)
		}
		_, ok := fieldDefs[f.Field]
		assert.True(t, ok, f.Field)
	}
	for _, name := range fieldOrder {
		assert.True(t, seen[name], name)
	}
	assert.Len(t, fieldOrder, 12)
}

func TestCatalog_OptionsMatchWhatValidateAccepts(t *testing.T) {
	for _, f := range Catalog() {
		for _, o := range f.Options {
			var c Condition
			switch f.Value {
			case ValuePlatforms, ValueLanguages:
				c = cond(f.Field, f.Ops[0].Op, fmt.Sprintf(`[%q]`, o.Value))
			case ValuePlusState:
				c = cond(f.Field, f.Ops[0].Op, fmt.Sprintf(`%q`, o.Value))
			case ValueFeatureDays:
				c = cond(f.Field, f.Ops[0].Op, fmt.Sprintf(`{"feature":%q,"days":1}`, o.Value))
			}
			assert.NoError(t, def(c).Validate(), "%s/%s", f.Field, o.Value)
		}
	}
}

func TestCatalog_OpsAllCompile(t *testing.T) {
	values := map[string]string{
		ValueLanguages: `["en"]`, ValuePlatforms: `["ios"]`, ValueIntDays: `5`, ValuePlusState: `"none"`,
		ValueFeatureDays: `{"feature":"juka","days":5}`, ValueCampaignDays: `{"campaign_id":"` + campaignID + `","days":5}`, ValueBool: `true`,
	}
	for _, f := range Catalog() {
		for _, op := range f.Ops {
			require.NoError(t, def(cond(f.Field, op.Op, values[f.Value])).Validate(), "%s/%s", f.Field, op.Op)
		}
	}
}

func TestCatalog_ReturnsCopies(t *testing.T) {
	a := Catalog()
	a[0].Ops[0].Label = "changed"
	a[0].Options[0].Label = "changed"
	b := Catalog()
	assert.NotEqual(t, "changed", b[0].Ops[0].Label)
	assert.NotEqual(t, "changed", b[0].Options[0].Label)
}

func TestCatalogListsAreNeverNullInJSON(t *testing.T) {
	raw, err := json.Marshal(Catalog())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"options":null`) || strings.Contains(string(raw), `"ops":null`) {
		t.Fatalf("the admin editor reads options[0]; a null list crashed it: %s", raw)
	}
}
