package pagination

// Singleton wraps a single object response in the canonical /api/v3 shape:
//
//	{ "data": { ...the resource fields... } }
//
// Use for endpoints that return ONE thing (a profile, a single
// notification, a config payload). The wrapper exists so the response
// shape is stable when fields are added — clients always read
// `response.data.foo`, never `response.foo` — and so it lines up with
// the list shape's `items` field for trivial "is this the data?"
// reasoning across response types.
//
// Pairs with CursorPage[T] (list shape) and Envelope[T] (admin-table
// offset-paginated). The naming distinction:
//
//   - Singleton[T] : one object,         { "data": { ... } }            (v3 mobile)
//   - CursorPage[T]: cursor-paginated list, { "items": [...], "next_page_key": "..." } (v3 mobile)
//   - Envelope[T]  : offset-paginated list, { "items": [...], "page": {...} }          (v1 admin-table; pre-v3)
//
// ADR-004 refers to the singleton shape as "Singleton[T]"; this is the
// type that name maps to.
type Singleton[T any] struct {
	Data T `json:"data"`
}

// NewSingleton wraps a value into the canonical singleton envelope. Type
// inference handles the parameter; callers write `pagination.NewSingleton(profile)`.
func NewSingleton[T any](data T) Singleton[T] {
	return Singleton[T]{Data: data}
}
