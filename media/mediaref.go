package media

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AssetMetadata is the subset of media_assets.metadata (JSONB) that clients
// need to render placeholders and intrinsic dimensions.
type AssetMetadata struct {
	Thumbhash      string `json:"thumbhash,omitempty"`
	LqipDataURI    string `json:"lqip_data_uri,omitempty"`
	OriginalWidth  int    `json:"original_width,omitempty"`
	OriginalHeight int    `json:"original_height,omitempty"`
}

// AssetMetadataFromJSON unmarshals media_assets.metadata; empty input → zero value.
func AssetMetadataFromJSON(raw []byte) (AssetMetadata, error) {
	var m AssetMetadata
	if len(raw) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("media: unmarshal metadata: %w", err)
	}
	return m, nil
}

// MediaRef is the canonical read shape returned to clients for any media
// asset: the primary display URL + placeholder hash + every variant URL. One
// shape across all services so each rendering surface gets a thumbhash/blurhash
// placeholder for free (no more bare thumbnail_url strings).
type MediaRef struct {
	URL       string            `json:"url"`
	Thumbhash string            `json:"thumbhash,omitempty"`
	LqipURI   string            `json:"lqip_data_uri,omitempty"`
	Variants  map[string]string `json:"variants,omitempty"`
	Width     int               `json:"width,omitempty"`
	Height    int               `json:"height,omitempty"`
}

// BuildMediaRef composes a MediaRef from a serve-base URL, the asset's variant
// map, and its metadata. primaryKeys is the priority order for the display URL
// (e.g. "main","original" for images; "preview" for a video poster). Returns a
// MediaRef with placeholder/dimensions populated even when no variant matches
// (URL stays empty), so callers can still render the blurhash.
func BuildMediaRef(serveBaseURL string, variants map[string]Variant, meta AssetMetadata, primaryKeys ...string) MediaRef {
	ref := MediaRef{
		Thumbhash: meta.Thumbhash,
		LqipURI:   meta.LqipDataURI,
		Width:     meta.OriginalWidth,
		Height:    meta.OriginalHeight,
	}
	if len(variants) == 0 || serveBaseURL == "" {
		return ref
	}
	base := strings.TrimRight(serveBaseURL, "/")
	ref.Variants = make(map[string]string, len(variants))
	for name, v := range variants {
		if v.Path == "" {
			continue
		}
		ref.Variants[name] = base + "/" + strings.TrimLeft(v.Path, "/")
	}
	ref.URL = PreferredVariantURL(serveBaseURL, variants, primaryKeys...)
	if primary, ok := pickPrimaryVariant(variants, primaryKeys...); ok {
		if ref.Width == 0 {
			ref.Width = primary.Width
		}
		if ref.Height == 0 {
			ref.Height = primary.Height
		}
	}
	return ref
}

func pickPrimaryVariant(variants map[string]Variant, keys ...string) (Variant, bool) {
	for _, k := range keys {
		if v, ok := variants[k]; ok {
			return v, true
		}
	}
	return Variant{}, false
}
