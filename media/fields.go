package media

// Media-backed fields: the owner contract for columns that show media.
//
// An owner (the service whose table holds the column) stores the media_id as
// the source of truth and the display URL the media service minted for it
// (MediaRef.URL) as a copy, so reads stay a single query. The owner never
// calls the media service: the admin edge (kielo-cms) resolves media_ids on
// writes and runs migrations over this contract
// (docs/architecture/media-platform-access-and-storage.md §4):
//
//	GET  /internal/media-fields                  → MediaFieldsSummary
//	GET  /internal/media-fields/{field}/rows      → MediaFieldRowsPage (state=url_only|linked)
//	POST /internal/media-fields/{field}/rows      MediaFieldUpdateRequest → MediaFieldUpdateResult
//
// A row is url_only when it has a URL but no media_id (a legacy raw URL, to be
// adopted), linked when it has a media_id (its URL is refreshed from the
// media service), empty when it has neither.

// MediaFieldSummary describes one media-backed field and its row states.
type MediaFieldSummary struct {
	Field     string `json:"field"`
	Label     string `json:"label"`
	Profile   string `json:"profile"`
	OwnerType string `json:"owner_type"`
	Rows      int    `json:"rows"`
	Linked    int    `json:"linked"`
	URLOnly   int    `json:"url_only"`
	Empty     int    `json:"empty"`
}

// MediaFieldsSummary is an owner's media-backed fields.
type MediaFieldsSummary struct {
	Owner  string              `json:"owner"`
	Fields []MediaFieldSummary `json:"fields"`
}

// MediaFieldRow is one owner row's current value. Language is set when the
// owner keeps the row in a per-language schema.
type MediaFieldRow struct {
	OwnerID  string `json:"owner_id"`
	Language string `json:"language,omitempty"`
	URL      string `json:"url"`
	MediaID  string `json:"media_id,omitempty"`
}

// MediaFieldRowsPage is one keyset page of rows (pass Next as after).
type MediaFieldRowsPage struct {
	Rows []MediaFieldRow `json:"rows"`
	Next string          `json:"next,omitempty"`
}

// MediaFieldUpdate sets a row's media_id and display URL, only while the row
// still holds ExpectedURL (an admin edit in between wins).
type MediaFieldUpdate struct {
	OwnerID     string `json:"owner_id"`
	Language    string `json:"language,omitempty"`
	ExpectedURL string `json:"expected_url"`
	MediaID     string `json:"media_id"`
	URL         string `json:"url"`
}

// MediaFieldUpdateRequest is a batch of row updates for one field.
type MediaFieldUpdateRequest struct {
	Updates []MediaFieldUpdate `json:"updates"`
}

// MediaFieldUpdateResult counts applied updates and lists the rows skipped
// because they changed since they were read.
type MediaFieldUpdateResult struct {
	Updated int      `json:"updated"`
	Changed []string `json:"changed"`
}

// MediaFieldRowStates are the row states a rows page can be filtered by.
const (
	MediaFieldURLOnly = "url_only"
	MediaFieldLinked  = "linked"
)
