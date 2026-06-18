package pagination

// Envelope is the canonical admin-table pagination shape.
// Use for admin endpoints with offset-based pagination.
type Envelope[T any] struct {
	Items []T  `json:"items"`
	Page  Page `json:"page"`
}

// Page describes the pagination window of an Envelope.
type Page struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	Total   int  `json:"total"`
	HasMore bool `json:"has_more"`
}

// NewEnvelope builds an Envelope from a slice plus the offset/limit/total.
// HasMore is computed from offset + len(items) < total.
func NewEnvelope[T any](items []T, limit, offset, total int) Envelope[T] {
	if items == nil {
		items = []T{}
	}
	return Envelope[T]{
		Items: items,
		Page: Page{
			Limit:   limit,
			Offset:  offset,
			Total:   total,
			HasMore: offset+len(items) < total,
		},
	}
}
