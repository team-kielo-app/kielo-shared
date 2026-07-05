package media

import (
	"path"
	"strings"
)

// Attachment is a generic owner↔media link (mirrors the media.media_attachments
// table). Source of truth for ownership across all entity types.
type Attachment struct {
	MediaID   string
	OwnerType string
	OwnerID   string
	Role      string
}

// ResolveStoragePath builds an asset's storage path prefix from its profile +
// identifiers. Replaces the hardcoded per-entity registry in
// kielo-media-upload-api: prefix + which id segments to include come from the
// profile, so a new use-case needs no path code.
//
// Layout: <PathPrefix>[/<ownerID>]/<mediaID>
func ResolveStoragePath(p MediaProfile, ownerID, mediaID string) string {
	segs := []string{strings.Trim(p.PathPrefix, "/")}
	if (p.IncludeOwnerID || p.IncludeEntityID) && ownerID != "" {
		segs = append(segs, ownerID)
	}
	if mediaID != "" {
		segs = append(segs, mediaID)
	}
	return path.Join(segs...)
}
