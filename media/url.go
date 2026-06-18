package media

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/team-kielo-app/kielo-shared/gcs"
)

// Variant describes a single processed media variant emitted by the
// media-processor and stored in media_assets.variants (JSONB).
//
// Only the fields that callers actually need to construct serve URLs are
// modeled here; additional metadata in the JSON is ignored on unmarshal.
type Variant struct {
	Path     string  `json:"path"`
	MimeType string  `json:"mime_type,omitempty"`
	Size     int64   `json:"size,omitempty"`
	Width    int     `json:"width,omitempty"`
	Height   int     `json:"height,omitempty"`
	Duration float64 `json:"duration,omitempty"`
	Codec    string  `json:"codec,omitempty"`
}

// VariantsFromJSON unmarshals a media_assets.variants JSONB column.
// An empty/nil input returns nil (not an error) so callers can treat
// "no variants" the same as "row missing".
func VariantsFromJSON(raw []byte) (map[string]Variant, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := map[string]Variant{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("media: unmarshal variants: %w", err)
	}
	return out, nil
}

// ServeBaseURL returns the URL prefix under which a media asset's variants
// are served. Delegates to gcs.BuildServeBaseURL, which is environment-aware:
// in dev (STORAGE_EMULATOR_HOST set) it produces a fake-gcs-server URL;
// in prod it produces an https://storage.googleapis.com URL (or a CDN URL
// when one is provided).
//
// The URL produced in dev uses the internal Docker hostname
// ("gcs-emulator:<port>"). For external/client-visible URLs use
// ServeBaseURLForRequest instead, which rewrites the host for loopback
// and LAN callers.
func ServeBaseURL(storageBucket, storagePathPrefix string) string {
	return gcs.BuildServeBaseURL(storageBucket, storagePathPrefix, "")
}

// ServeBaseURLWithCDN is the same as ServeBaseURL but allows a CDN base
// override (e.g., for cms-served media that goes through CloudFront).
func ServeBaseURLWithCDN(storageBucket, storagePathPrefix, cdnBaseURL string) string {
	return gcs.BuildServeBaseURL(storageBucket, storagePathPrefix, cdnBaseURL)
}

// ServeBaseURLForRequest returns a serve-base URL contextualized for the
// calling client's Host header. Internal Docker callers (single-label
// hostnames) get the raw internal URL; external callers (loopback, LAN
// IP, or FQDN) get an HOST_IP-rewritten URL in dev and an unchanged
// real GCS URL in prod.
//
// Use this at the API boundary (public/mobile BFF endpoints) so clients
// receive URLs they can actually reach, eliminating the need for a
// response-rewriting middleware.
func ServeBaseURLForRequest(requestHost, storageBucket, storagePathPrefix string) string {
	base := ServeBaseURL(storageBucket, storagePathPrefix)
	if base == "" {
		return ""
	}
	return gcs.ContextualizeStorageURL(requestHost, base)
}

// PreferredVariantURLForRequest is the caller-aware variant of
// PreferredVariantURL. It builds the serve-base URL for the calling
// client and then composes the variant URL. Preferred for any URL that
// will be returned in an HTTP response body — internal-to-internal
// service calls should keep using PreferredVariantURL + ServeBaseURL.
func PreferredVariantURLForRequest(
	requestHost, storageBucket, storagePathPrefix string,
	variants map[string]Variant,
	keyPriority ...string,
) string {
	base := ServeBaseURLForRequest(requestHost, storageBucket, storagePathPrefix)
	if base == "" {
		return ""
	}
	return PreferredVariantURL(base, variants, keyPriority...)
}

// PreferredVariantURL returns the URL of the first matching variant in
// keyPriority order. Variants whose Path is empty are skipped.
//
// Typical usage:
//
//	video.URL = media.PreferredVariantURL(serveBase, variants, "main", "original")
//	video.Thumb = media.PreferredVariantURL(serveBase, variants, "preview")
func PreferredVariantURL(serveBaseURL string, variants map[string]Variant, keyPriority ...string) string {
	base := strings.TrimSpace(serveBaseURL)
	if base == "" || len(variants) == 0 {
		return ""
	}
	for _, key := range keyPriority {
		v, ok := variants[key]
		if !ok || strings.TrimSpace(v.Path) == "" {
			continue
		}
		if joined := gcs.JoinServeBaseAndObjectPath(base, v.Path); joined != "" {
			return joined
		}
	}
	return ""
}
