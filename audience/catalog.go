package audience

// FieldSpec describes one field to the admin editor.
type FieldSpec struct {
	Field   string   `json:"field"`
	Label   string   `json:"label"`
	Help    string   `json:"help"`
	Ops     []OpSpec `json:"ops"`
	Value   string   `json:"value"`
	Options []Option `json:"options,omitempty"`
}

// OpSpec is one operator of a field.
type OpSpec struct {
	Op    string `json:"op"`
	Label string `json:"label"`
}

// Option is one choice of a field's value.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Value kinds a FieldSpec can ask the editor for.
const (
	ValueLanguages    = "languages"
	ValuePlatforms    = "platforms"
	ValueIntDays      = "int_days"
	ValuePlusState    = "plus_state"
	ValueFeatureDays  = "feature_days"
	ValueCampaignDays = "campaign_days"
	ValueBool         = "bool"
)

var platformOptions = []Option{
	{Value: "ios", Label: "iPhone and iPad"},
	{Value: "android", Label: "Android"},
	{Value: "web", Label: "Web"},
}

var plusOptions = []Option{
	{Value: "never_paid", Label: "Never paid"},
	{Value: "paid_before", Label: "Paid before, not Plus now"},
	{Value: "paid_active", Label: "Paying now (store subscription)"},
	{Value: "promo_active", Label: "Has Plus for free (promo code, gift or referral)"},
	{Value: "any_active", Label: "Has Plus now, any way"},
	{Value: "none", Label: "Does not have Plus now"},
}

var featureOptions = []Option{
	{Value: "juka", Label: "Juka conversations"},
	{Value: "ktv", Label: "Kielo TV"},
	{Value: "reader", Label: "Reading articles"},
	{Value: "lessons", Label: "Lessons and exercises"},
}

var learningLanguageOptions = []Option{
	{Value: "fi", Label: "Finnish"},
	{Value: "sv", Label: "Swedish"},
}

// Catalog lists every field the editor offers, in display order.
func Catalog() []FieldSpec {
	specs := make([]FieldSpec, 0, len(fieldOrder))
	for _, name := range fieldOrder {
		s := fieldDefs[name].spec
		s.Ops = append([]OpSpec(nil), s.Ops...)
		s.Options = append([]Option(nil), s.Options...)
		specs = append(specs, s)
	}
	return specs
}
