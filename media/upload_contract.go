package media

import (
	"fmt"
	"slices"
	"strings"
)

// UploadRequest is the generic, profile-driven upload contract. It replaces
// the closed entity-type enum on the client side: a caller names a profile +
// the owner, and the storage path + variant policy come from the profile
// (see ResolveStoragePath + MediaProfile.Variants). Adding a use-case needs no
// client/registry code change.
type UploadRequest struct {
	Profile  string   `json:"profile"`
	Owner    OwnerRef `json:"owner"`
	Role     string   `json:"role,omitempty"`
	Filename string   `json:"filename"`
	MimeType string   `json:"mime_type"`
	Hash     string   `json:"file_hash_sha256,omitempty"`
}

// Validate checks the request against the profile registry: the profile must
// exist, the owner must be present, and the MIME type must be allowed by the
// profile (when it constrains MIME types).
func (r UploadRequest) Validate() error {
	p, ok := ProfileFor(r.Profile)
	if !ok {
		return fmt.Errorf("media: unknown profile %q", r.Profile)
	}
	if strings.TrimSpace(r.Owner.Type) == "" || strings.TrimSpace(r.Owner.ID) == "" {
		return fmt.Errorf("media: owner type+id required")
	}
	if strings.TrimSpace(r.MimeType) == "" {
		return fmt.Errorf("media: mime_type required")
	}
	if len(p.AllowedMimes) > 0 && !slices.Contains(p.AllowedMimes, r.MimeType) {
		return fmt.Errorf("media: mime %q not allowed for profile %q", r.MimeType, r.Profile)
	}
	return nil
}
