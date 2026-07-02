package media

import "time"

// Media profiles are the single control plane for the media-lifecycle
// platform (see docs/architecture/media-lifecycle-platform.md). ONE profile
// per media use-case, defined here in kielo-shared and imported by every
// service (upload-api, processor, cms, content-service, user-service, the
// lifecycle worker). A profile carries: storage layout, the variant set the
// processor must render, access class, retention/lifecycle, GDPR class, and
// alerting — so adding a use-case is a profile entry, not edits across an
// enum + a storage registry + per-MIME processor branches.
//
// Profile DEFINITIONS live in code (reviewed/audited). The numeric KNOBS
// (retention days, alert lookahead) are intended to be overridable via env
// set by Terraform, so ops can retune retention without a logic redeploy —
// the override layer is applied by the consuming service, not here.

// AccessClass controls how a profile's served objects are exposed.
type AccessClass string

const (
	AccessPublic    AccessClass = "public"     // allUsers reader (public bucket/prefix)
	AccessSignedCDN AccessClass = "signed_cdn" // served via Cloud CDN signed URLs
	AccessPrivate   AccessClass = "private"    // service-account only, no public read
)

// VariantSpec declares one rendition the processor should produce. The set is
// per-profile (per use-case), not inferred from MIME type alone.
type VariantSpec struct {
	Name     string // "main" | "preview" | "thumb"
	MaxWidth int    // 0 = keep source width
	Quality  int    // codec quality (webp/mp3/…); 0 = processor default
	Format   string // "webp" | "mp3" | "mp4"; "" = keep source
}

// RetentionPolicy is a profile's lifecycle contract — the single source of
// truth for when media is deleted. ALL business deletion (TTL expiry, orphan
// sweep, owner-delete cascade) is enforced by the lifecycle reconciler against
// these fields, NOT by GCS object-lifecycle rules. GCS rules in Terraform are
// demoted to two reference-blind jobs only: the temp-upload safety-net (delete
// abandoned signed-URL bytes) and ColdlineAfter cost tiering (a storage-class
// transition, never a delete). Encoding retention as a dumb GCS age rule is
// what previously hard-deleted live article media; the reconciler is
// reference-aware and audited, so it owns deletion.
type RetentionPolicy struct {
	TTL                 time.Duration // 0 = keep indefinitely
	ColdlineAfter       time.Duration // 0 = no storage-class transition (cost only, not deletion)
	DeleteOnOwnerDelete bool          // cascade when the owning entity is deleted
	OrphanGrace         time.Duration // reap if uploaded but never linked past this (0 = never reap orphans)
}

// GDPRClass declares whether a profile's media is personal data and how it is
// erased on a data-subject deletion request.
type GDPRClass struct {
	ContainsPII bool
	// SubjectFrom names how subject_user_id is derived: "owner" (the owning
	// entity is the user), "uploader" (the uploader is the subject), or
	// "none" (not personal data).
	SubjectFrom         string
	ErasureSLA          time.Duration // max request→purge time for compliance
	DedupAcrossSubjects bool          // MUST be false for PII (no cross-subject hash dedup)
}

// AlertPolicy configures upcoming-lifecycle alerts for designated profiles.
type AlertPolicy struct {
	Enabled       bool
	LookaheadDays int      // warn this many days before TTL-driven deletion
	Channels      []string // "slack:ops" | "email:compliance"
	AlertOnDelete bool     // page if any delete is attempted (legal-hold-grade)
}

// MediaProfile is one media use-case's complete policy.
type MediaProfile struct {
	Key             string
	EntityType      EntityType // back-compat bridge to the legacy enum until retired
	PathPrefix      string     // base prefix; owner/media segments appended per flags
	IncludeOwnerID  bool
	IncludeEntityID bool
	AllowedMimes    []string // empty = any
	Variants        []VariantSpec
	Access          AccessClass
	Retention       RetentionPolicy
	GDPR            GDPRClass
	Alerts          AlertPolicy
	LegalHoldable   bool
}

const day = 24 * time.Hour

// profiles is the canonical registry. Keys are stable wire identifiers used in
// the upload contract + media_assets.profile column.
//
// NOTE on retention/GDPR numbers: TTL + ErasureSLA values for PII profiles are
// legal/compliance decisions — the values below are conservative placeholders
// flagged in the RFC's "open decisions". Override per env via Terraform vars.
var profiles = map[string]MediaProfile{
	"user-avatar": {
		Key: "user-avatar", EntityType: EntityTypeUserAvatar,
		PathPrefix: "user-assets", IncludeOwnerID: true,
		AllowedMimes: []string{"image/jpeg", "image/png", "image/webp"},
		Variants:     []VariantSpec{{Name: "main", MaxWidth: 256, Format: "webp"}},
		Access:       AccessSignedCDN,
		Retention:    RetentionPolicy{DeleteOnOwnerDelete: true, OrphanGrace: 7 * day},
		GDPR:         GDPRClass{ContainsPII: true, SubjectFrom: "owner", ErasureSLA: 30 * day, DedupAcrossSubjects: false},
	},
	"article-thumbnail": {
		Key: "article-thumbnail", EntityType: EntityTypeArticleThumbnail,
		PathPrefix: "articles", IncludeEntityID: true,
		AllowedMimes: []string{"image/jpeg", "image/png", "image/webp"},
		Variants:     []VariantSpec{{Name: "main", MaxWidth: 1200, Format: "webp"}},
		Access:       AccessSignedCDN,
		// Articles are re-scraped daily — media is ephemeral. 30d TTL (reaped by
		// the reconciler, replacing the old blind GCS articles/ age-delete).
		Retention: RetentionPolicy{TTL: 30 * day, DeleteOnOwnerDelete: true, OrphanGrace: 7 * day},
		GDPR:      GDPRClass{ContainsPII: false, SubjectFrom: "none", DedupAcrossSubjects: true},
	},
	"article-content": {
		Key: "article-content", EntityType: EntityTypeArticleContent,
		PathPrefix: "articles", IncludeEntityID: true,
		Variants: []VariantSpec{{Name: "main", MaxWidth: 1200, Format: "webp"}},
		Access:   AccessSignedCDN,
		// Ephemeral (daily re-scrape): 30d TTL, reconciler-reaped.
		Retention: RetentionPolicy{TTL: 30 * day, DeleteOnOwnerDelete: true, OrphanGrace: 7 * day},
		GDPR:      GDPRClass{SubjectFrom: "none", DedupAcrossSubjects: true},
	},
	"kielotv-video": {
		Key: "kielotv-video", EntityType: EntityTypeKieloTVVideo,
		PathPrefix: "kielotv", IncludeEntityID: true,
		Variants:  []VariantSpec{{Name: "preview", MaxWidth: 300, Format: "webp"}, {Name: "main", Format: "mp4"}},
		Access:    AccessSignedCDN,
		Retention: RetentionPolicy{DeleteOnOwnerDelete: true, OrphanGrace: 14 * day},
		GDPR:      GDPRClass{SubjectFrom: "none", DedupAcrossSubjects: true},
	},
	"kielotv-thumbnail": {
		Key: "kielotv-thumbnail", EntityType: EntityTypeKieloTVThumbnail,
		PathPrefix: "kielotv", IncludeEntityID: true,
		Variants:  []VariantSpec{{Name: "main", MaxWidth: 1200, Format: "webp"}},
		Access:    AccessSignedCDN,
		Retention: RetentionPolicy{DeleteOnOwnerDelete: true, OrphanGrace: 14 * day},
		GDPR:      GDPRClass{SubjectFrom: "none", DedupAcrossSubjects: true},
	},
	"voice-agent-avatar": {
		Key: "voice-agent-avatar",
		// New use-case (no legacy EntityType): voice-agent avatars currently
		// stored as raw external URLs — migration target.
		PathPrefix: "voice-agents", IncludeEntityID: true,
		AllowedMimes: []string{"image/jpeg", "image/png", "image/webp"},
		Variants:     []VariantSpec{{Name: "main", MaxWidth: 512, Format: "webp"}},
		Access:       AccessSignedCDN,
		Retention:    RetentionPolicy{DeleteOnOwnerDelete: true, OrphanGrace: 14 * day},
		GDPR:         GDPRClass{SubjectFrom: "none", DedupAcrossSubjects: true},
	},
	"curriculum-thumbnail": {
		Key: "curriculum-thumbnail",
		// New use-case: track/level/chapter/lesson thumbnails currently raw
		// String(500) URLs in kielolearn-engine — primary migration target.
		PathPrefix: "curriculum", IncludeEntityID: true,
		AllowedMimes: []string{"image/jpeg", "image/png", "image/webp"},
		Variants:     []VariantSpec{{Name: "main", MaxWidth: 1200, Format: "webp"}},
		Access:       AccessSignedCDN,
		Retention:    RetentionPolicy{DeleteOnOwnerDelete: true, OrphanGrace: 14 * day},
		GDPR:         GDPRClass{SubjectFrom: "none", DedupAcrossSubjects: true},
	},
	"support-attachment": {
		Key: "support-attachment",
		// Support-chat (feedback thread) attachments: screenshots a user sends
		// with a bug report, or images support staff send back. Owner = the
		// feedback message row (users.feedback_messages). User-uploaded
		// screenshots routinely contain personal data → PII with the uploader
		// as data subject; erased with the account. Legal-holdable: support
		// threads can become dispute evidence.
		PathPrefix: "support", IncludeOwnerID: true,
		AllowedMimes: []string{"image/jpeg", "image/png", "image/webp"},
		Variants: []VariantSpec{
			{Name: "main", MaxWidth: 1600, Format: "webp"},
			{Name: "preview", MaxWidth: 300, Format: "webp"},
		},
		Access:        AccessSignedCDN,
		Retention:     RetentionPolicy{TTL: 365 * day, DeleteOnOwnerDelete: true, OrphanGrace: 7 * day},
		GDPR:          GDPRClass{ContainsPII: true, SubjectFrom: "uploader", ErasureSLA: 30 * day, DedupAcrossSubjects: false},
		LegalHoldable: true,
	},
	"convo-transcript": {
		Key: "convo-transcript", EntityType: EntityTypeConvoTranscript,
		PathPrefix: "convo", IncludeOwnerID: true,
		Access: AccessPrivate,
		// User conversation data = PII. TTL + erasure are compliance-driven.
		Retention:     RetentionPolicy{TTL: 365 * day, DeleteOnOwnerDelete: true, OrphanGrace: 7 * day},
		GDPR:          GDPRClass{ContainsPII: true, SubjectFrom: "owner", ErasureSLA: 30 * day, DedupAcrossSubjects: false},
		Alerts:        AlertPolicy{Enabled: true, LookaheadDays: 7, Channels: []string{"slack:ops"}},
		LegalHoldable: true,
	},
}

// Profiles returns the registry (read-only snapshot reference).
func Profiles() map[string]MediaProfile { return profiles }

// ProfileFor returns the profile by key.
func ProfileFor(key string) (MediaProfile, bool) {
	p, ok := profiles[key]
	return p, ok
}

// ProfileForEntityType bridges the legacy EntityType enum to a profile during
// migration. Returns false for entity types not yet mapped.
func ProfileForEntityType(t EntityType) (MediaProfile, bool) {
	for _, p := range profiles {
		if p.EntityType != "" && p.EntityType == t {
			return p, true
		}
	}
	return MediaProfile{}, false
}

// relatedEntityAliases maps free-form related_entity_type wire strings (from
// clients whose upload request predates the explicit `profile` field) onto
// profile keys. Server-side inference so lifecycle/GDPR stamping doesn't
// depend on every client remembering to send `profile`.
var relatedEntityAliases = map[string]string{
	"support-attachment": "support-attachment",
	"FeedbackMessage":    "support-attachment",
}

// ProfileForRelatedEntity resolves a profile from a related_entity_type wire
// string: first via the legacy EntityType bridge, then via the alias table.
// Use when an upload request carries no explicit profile key.
func ProfileForRelatedEntity(entityType string) (MediaProfile, bool) {
	if p, ok := ProfileForEntityType(EntityType(entityType)); ok {
		return p, true
	}
	if key, ok := relatedEntityAliases[entityType]; ok {
		return ProfileFor(key)
	}
	return MediaProfile{}, false
}

// ComputeExpiresAt returns the absolute expiry for an asset created at
// createdAt under this profile, or the zero time if the profile keeps media
// indefinitely (TTL == 0). The lifecycle reconciler indexes on this.
func (p MediaProfile) ComputeExpiresAt(createdAt time.Time) time.Time {
	if p.Retention.TTL <= 0 {
		return time.Time{}
	}
	return createdAt.Add(p.Retention.TTL)
}

// SubjectUserID returns the GDPR data-subject user id for an asset created under
// this profile, or "" when the profile is not personal data. Derived from
// GDPRClass.SubjectFrom: "owner" → the owning entity is the user (ownerID),
// "uploader" → the uploader is the subject (uploaderID). The media-upload write
// path stamps this onto media_assets.subject_user_id so the GDPR erasure pass
// can enumerate a subject's media without guessing.
func (p MediaProfile) SubjectUserID(ownerID, uploaderID string) string {
	if !p.GDPR.ContainsPII {
		return ""
	}
	switch p.GDPR.SubjectFrom {
	case "owner":
		return ownerID
	case "uploader":
		return uploaderID
	default:
		return ""
	}
}
