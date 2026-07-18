package media

// Hero-media payload keys — the wire contract for a notification's hero
// image, carried in notification job data, communications.logs metadata,
// the inbox outbox payload, users.notifications.data, and the push wire
// shape. One source of truth: these same JSON keys are read by the mobile
// app (NotificationHistoryRow) and re-resolved at inbox read time by
// user-service (refreshHeroMedia: HeroMediaIDKey → fresh MediaRef URL).
// The URL persisted at send time is an expiring fallback; the ID is the
// stable identity. Changing any of these is a cross-service +
// mobile-client breaking change.
const (
	HeroMediaURLKey       = "hero_media_url"
	HeroMediaThumbhashKey = "hero_media_thumbhash"
	HeroMediaIDKey        = "hero_media_id"
)
