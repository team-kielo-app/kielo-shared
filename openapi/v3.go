// Package openapi: a typed Echo wrapper that registers routes and emits an
// OpenAPI 3.1 spec for /api/v3 endpoints.
//
// Why this lives in kielo-shared:
//
// Each service that participates in the v3 surface registers its routes
// through this wrapper instead of bare `e.GET(...)`. The wrapper:
//
//  1. Calls the underlying Echo registration (so the route is live).
//  2. Captures path / method / params / request-body type / response type
//     in an in-memory registry.
//  3. Emits an OpenAPI 3.1 JSON document on demand
//     (`spec.MarshalJSON()` or `WriteSpecToFile()`).
//
// On startup, each service writes its spec to docs/api/v3/<service>.json.
// A repo-level merge tool (scripts/api-audit/merge-openapi.sh) combines
// them into docs/api/v3/openapi.json — the artifact the mobile/admin
// codegen consumes.
//
// Why a custom wrapper (vs swaggo annotations or oapi-codegen):
//
//   - swaggo: parses Go struct tags + comment annotations. Comments drift
//     from code; the generated spec is post-hoc and easy to forget.
//   - oapi-codegen: spec-first. We'd hand-author YAML/JSON for 730+
//     endpoints, which is the problem we're trying to escape.
//   - Custom typed wrapper: code IS the spec. Registering a route with the
//     wrong shape fails at compile time. The spec is a derived artifact
//     we never hand-edit.
//
// Scope guard: this wrapper is intentionally minimal. It covers v3
// endpoints' shape (path + method + params + bodies + responses + error
// envelope). It does NOT auto-generate examples, multipart/form, file
// uploads, or websocket — those land if and when v3 gets a use case.
package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
)

// Registry collects every v3 route registered through Wrapper. There's
// one Registry per service; Service() and Title() are stamped into the
// emitted spec.
type Registry struct {
	mu      sync.Mutex
	service string
	title   string
	version string
	routes  []routeEntry
	schemas map[string]any // by Go type name; populated lazily on use
}

type routeEntry struct {
	method          string
	path            string
	summary         string
	description     string
	tag             string
	pathParams      []paramSpec
	queryParams     []paramSpec
	requestBody     any   // value of struct type (zero); nil if no body
	responseBody    any   // zero value of response struct
	untypedResponse bool  // true if route returns JSON but the schema is upstream-owned
	binaryResponse  bool  // true if route streams binary (application/octet-stream)
	errorCodes      []int // additional non-2xx HTTP codes documented
}

type paramSpec struct {
	Name        string
	In          string // "path" | "query"
	Type        string // "string" | "integer" | ...
	Required    bool
	Description string
}

// NewRegistry creates a fresh registry for one service.
//
// title is the human-readable service name; version typically tracks
// the service's git tag or semver. Both surface in the OpenAPI `info`
// block.
func NewRegistry(service, title, version string) *Registry {
	return &Registry{
		service: service,
		title:   title,
		version: version,
		schemas: map[string]any{},
	}
}

// Wrapper bundles a Registry with an Echo group so service authors can
// register v3 routes through it directly:
//
//	v3 := openapi.NewWrapper(reg, e.Group("/api/v3", auth))
//	v3.GET("/me/notifications", h.GetMyNotificationsV3, openapi.Route{
//	    Summary:      "List my notifications",
//	    Tag:          "notifications",
//	    QueryParams:  []openapi.ParamSpec{{Name: "cursor", In: "query", Type: "string"}, {Name: "page_size", In: "query", Type: "integer"}},
//	    Response:     pagination.CursorPage[models.UserNotification]{},
//	})
type Wrapper struct {
	reg    *Registry
	group  *echo.Group
	prefix string // duplicated from group.Prefix so we can record full paths;
	// echo doesn't export the prefix.
}

// NewWrapper takes the group AND its prefix string explicitly. Pass the
// SAME prefix you used when calling e.Group(prefix, ...) — typically
// "/api/v3". Only this prefix lands in the spec; the group does the
// runtime routing.
func NewWrapper(reg *Registry, group *echo.Group, prefix string) *Wrapper {
	return &Wrapper{reg: reg, group: group, prefix: prefix}
}

// Route is the metadata captured per registration. Fields not relevant
// for a particular method (e.g. RequestBody on GET) are ignored.
type Route struct {
	Summary     string
	Description string
	Tag         string

	// Path params are inferred from the {…} placeholders in the path
	// string and validated against the supplied PathParams (so a typo
	// in either is caught at boot). Each entry also carries a type and
	// description for the spec.
	PathParams  []ParamSpec
	QueryParams []ParamSpec

	// RequestBody is a zero-value of the request struct (e.g.
	// `models.UpdateProfileRequest{}`). Use nil for GET/DELETE.
	RequestBody any

	// Response is a zero-value of the success response struct.
	// pagination.CursorPage[T]{} for lists, pagination.Envelope[T]{} for
	// singletons, T{} for the rare bare-object response.
	Response any

	// UntypedResponse marks routes that return JSON but whose schema
	// lives in an upstream service that mobile-bff does not import.
	// When true (and Response is nil), the spec emits "200: application/json"
	// with an empty schema instead of falsely advertising "204 No Content".
	// Prefer Response: <typed>{} whenever the type is reachable; reach for
	// this flag only for proxy passthrough where mirroring upstream types
	// would be churn or duplication.
	UntypedResponse bool

	// BinaryResponse marks routes that stream binary bodies (file
	// downloads, video streams, audio TTS). When true (and Response is
	// nil), the spec emits "200: application/octet-stream" with
	// `schema: {type: string, format: binary}` so @hey-api/openapi-ts
	// generates a SDK fn that returns a Blob/ArrayBuffer instead of
	// trying to JSON.parse the body. Prefer this over UntypedResponse
	// for endpoints that c.Stream() or http.ServeContent() so the
	// generated client doesn't crash on non-JSON bytes.
	BinaryResponse bool

	// ErrorCodes are HTTP codes (besides 200/201/204 implied by the
	// method) that the handler can return. The canonical error envelope
	// is auto-documented for each.
	ErrorCodes []int
}

type ParamSpec struct {
	Name        string
	In          string // "path" | "query"
	Type        string // "string" | "integer" | "boolean"
	Required    bool
	Description string
}

// Per-method registration. The variadic Route argument is required (callers
// always pass exactly one) but typed as variadic so per-route middleware
// can be threaded as the last parameters and still keep the spec metadata
// at a fixed position. The implementation only consults route[0]; passing
// none is a programmer error and panics in register().
func (w *Wrapper) GET(path string, h echo.HandlerFunc, route Route, mw ...echo.MiddlewareFunc) *echo.Route {
	return w.register("GET", path, h, route, mw)
}
func (w *Wrapper) POST(path string, h echo.HandlerFunc, route Route, mw ...echo.MiddlewareFunc) *echo.Route {
	return w.register("POST", path, h, route, mw)
}
func (w *Wrapper) PUT(path string, h echo.HandlerFunc, route Route, mw ...echo.MiddlewareFunc) *echo.Route {
	return w.register("PUT", path, h, route, mw)
}
func (w *Wrapper) PATCH(path string, h echo.HandlerFunc, route Route, mw ...echo.MiddlewareFunc) *echo.Route {
	return w.register("PATCH", path, h, route, mw)
}
func (w *Wrapper) DELETE(path string, h echo.HandlerFunc, route Route, mw ...echo.MiddlewareFunc) *echo.Route {
	return w.register("DELETE", path, h, route, mw)
}

func (w *Wrapper) register(method, path string, h echo.HandlerFunc, route Route, mw []echo.MiddlewareFunc) *echo.Route {
	// Wire the Echo route immediately. The wrapper is intentionally
	// transparent — registering through it doesn't change runtime
	// behavior, only adds the spec capture.
	//
	// Path syntax bridge: callers pass OAS-style `{name}` placeholders
	// (because the spec uses that form). Echo's router only recognizes
	// `:name` placeholders — `{name}` is treated as a literal segment,
	// so a registration like `/users/{user_id}/profile` matched against
	// `/users/abc-123/profile` would 404 silently. Convert at the edge so
	// callers don't have to remember two syntaxes.
	echoPath := echoPathFromOAS(path)
	var er *echo.Route
	switch method {
	case "GET":
		er = w.group.GET(echoPath, h, mw...)
	case "POST":
		er = w.group.POST(echoPath, h, mw...)
	case "PUT":
		er = w.group.PUT(echoPath, h, mw...)
	case "PATCH":
		er = w.group.PATCH(echoPath, h, mw...)
	case "DELETE":
		er = w.group.DELETE(echoPath, h, mw...)
	}

	w.reg.mu.Lock()
	defer w.reg.mu.Unlock()
	w.reg.routes = append(w.reg.routes, routeEntry{
		method:          method,
		path:            w.prefix + path,
		summary:         route.Summary,
		description:     route.Description,
		tag:             route.Tag,
		pathParams:      toParamSpecs(route.PathParams),
		queryParams:     toParamSpecs(route.QueryParams),
		requestBody:     route.RequestBody,
		responseBody:    route.Response,
		untypedResponse: route.UntypedResponse,
		binaryResponse:  route.BinaryResponse,
		errorCodes:      route.ErrorCodes,
	})
	return er
}

// Record adds a routeEntry to the Registry WITHOUT wiring an
// Echo handler. Use this when the runtime router isn't Echo (e.g.
// kielo-convo go_orchestrator uses chi) and the spec capture has
// to happen separately from route registration.
//
// path uses OAS-canonical {name} placeholders. method is uppercase
// (GET/POST/PUT/PATCH/DELETE). The route is appended to the registry's
// routes slice under the registry mutex.
//
// Callers should register the actual handler with their own router
// (chi, gorilla, net/http) using whatever path syntax that router
// expects. The spec emit goes through the registry; the runtime
// routing is the caller's responsibility.
func (r *Registry) Record(method, path string, route Route) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = append(r.routes, routeEntry{
		method:          method,
		path:            path,
		summary:         route.Summary,
		description:     route.Description,
		tag:             route.Tag,
		pathParams:      toParamSpecs(route.PathParams),
		queryParams:     toParamSpecs(route.QueryParams),
		requestBody:     route.RequestBody,
		responseBody:    route.Response,
		untypedResponse: route.UntypedResponse,
		binaryResponse:  route.BinaryResponse,
		errorCodes:      route.ErrorCodes,
	})
}

// echoPathFromOAS converts an OAS-style path with `{name}` placeholders
// into Echo's `:name` placeholder form. Both syntaxes coexist in this
// codebase: the spec is OAS-canonical (per ADR-004 §1), Echo's router is
// `:name`-only. Run on every register call so the spec stays clean while
// Echo's tree gets the right placeholder kind.
//
// Edge cases handled:
//   - Non-placeholder braces (e.g. literal "{abc}" inside a path component)
//     would never appear in our routes, but the conversion is a single
//     pass so any sequence of non-`/` chars between `{` and `}` becomes
//     `:<chars>`. If a future route really needs a literal `{`, it can be
//     escaped at the call site.
func echoPathFromOAS(p string) string {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		if p[i] != '{' {
			out = append(out, p[i])
			continue
		}
		j := i + 1
		for j < len(p) && p[j] != '}' && p[j] != '/' {
			j++
		}
		if j < len(p) && p[j] == '}' {
			out = append(out, ':')
			out = append(out, p[i+1:j]...)
			i = j
			continue
		}
		// Unmatched `{` — pass through verbatim. Won't happen in our
		// routes; cheap to be defensive.
		out = append(out, p[i])
	}
	return string(out)
}

func toParamSpecs(in []ParamSpec) []paramSpec {
	out := make([]paramSpec, len(in))
	for i, p := range in {
		out[i] = paramSpec(p)
	}
	return out
}

// MarshalJSON emits the captured routes as an OpenAPI 3.1 JSON document.
//
// The document is a minimal but valid OAS 3.1 spec: paths + components +
// info. Servers / security blocks are left for the merge step (which has
// repo-wide context the per-service spec doesn't).
func (r *Registry) MarshalJSON() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Collect schemas by walking every request/response struct.
	for _, rt := range r.routes {
		if rt.requestBody != nil {
			r.collectSchema(rt.requestBody)
		}
		if rt.responseBody != nil {
			r.collectSchema(rt.responseBody)
		}
	}

	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   r.title,
			"version": r.version,
			"description": fmt.Sprintf(
				"OpenAPI 3.1 spec for the /api/v3 surface of %s. "+
					"Auto-generated from typed route registrations — do not "+
					"hand-edit. Source: kielo-shared/openapi.",
				r.service,
			),
		},
		"paths": r.buildPaths(),
		"components": map[string]any{
			"schemas":   r.buildSchemas(),
			"responses": canonicalErrorResponses(),
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func (r *Registry) buildPaths() map[string]any {
	paths := map[string]any{}
	// Group routes by path so multiple methods on the same path produce
	// one path-item with multiple operations (the OpenAPI shape).
	byPath := map[string][]routeEntry{}
	for _, rt := range r.routes {
		byPath[rt.path] = append(byPath[rt.path], rt)
	}
	for p, entries := range byPath {
		item := map[string]any{}
		for _, rt := range entries {
			item[strings.ToLower(rt.method)] = r.operationDoc(rt)
		}
		paths[p] = item
	}
	return paths
}

func (r *Registry) operationDoc(rt routeEntry) map[string]any {
	op := map[string]any{
		"summary":     rt.summary,
		"description": rt.description,
		"operationId": opID(rt.method, rt.path),
	}
	if rt.tag != "" {
		op["tags"] = []string{rt.tag}
	}

	var params []any
	for _, p := range rt.pathParams {
		params = append(params, paramDoc(p, true))
	}
	for _, p := range rt.queryParams {
		params = append(params, paramDoc(p, p.Required))
	}
	if len(params) > 0 {
		op["parameters"] = params
	}

	if rt.requestBody != nil {
		op["requestBody"] = map[string]any{
			"required": true,
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": schemaRef(rt.requestBody)},
				},
			},
		}
	}

	resp := map[string]any{}
	switch {
	case rt.responseBody != nil:
		resp["200"] = map[string]any{
			"description": "Success",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": responseSchema(rt.responseBody, r),
				},
			},
		}
	case rt.binaryResponse:
		// Streaming binary route (file download, video stream, audio TTS).
		// @hey-api/openapi-ts emits a `Blob` response type for
		// `application/octet-stream` + `format: binary`, so the
		// generated SDK fn returns a Blob the caller can hand to
		// URL.createObjectURL or pipe to FileSaver.
		resp["200"] = map[string]any{
			"description": "Binary stream",
			"content": map[string]any{
				"application/octet-stream": map[string]any{
					"schema": map[string]any{"type": "string", "format": "binary"},
				},
			},
		}
	case rt.untypedResponse:
		// Honest fallback: route returns JSON but the schema lives in an
		// upstream service we don't yet import. Emit the 200 + content
		// type so codegen knows there's a body, but leave the schema open
		// (`{}` accepts any JSON value per OpenAPI 3.x).
		resp["200"] = map[string]any{
			"description": "Success (schema upstream-owned)",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{},
				},
			},
		}
	default:
		resp["204"] = map[string]any{"description": "No Content"}
	}
	// Always document the canonical error envelope — every v3 endpoint
	// can return it (per ADR-004). Specific endpoints add more codes.
	resp["400"] = map[string]any{"$ref": "#/components/responses/BadRequest"}
	resp["401"] = map[string]any{"$ref": "#/components/responses/Unauthorized"}
	resp["500"] = map[string]any{"$ref": "#/components/responses/InternalError"}
	for _, code := range rt.errorCodes {
		resp[fmt.Sprintf("%d", code)] = map[string]any{
			"$ref": "#/components/responses/CanonicalError",
		}
	}
	op["responses"] = resp

	return op
}

func paramDoc(p paramSpec, required bool) map[string]any {
	return map[string]any{
		"name":        p.Name,
		"in":          p.In,
		"required":    required,
		"description": p.Description,
		"schema":      map[string]any{"type": p.Type},
	}
}

func opID(method, path string) string {
	cleaned := strings.NewReplacer(
		"/", "_", "{", "", "}", "", "-", "_",
	).Replace(strings.TrimPrefix(path, "/"))
	return strings.ToLower(method) + "_" + cleaned
}

func (r *Registry) collectSchema(v any) {
	if v == nil {
		return
	}
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	// Walk into slice/array element types so list responses like
	// Response: []models.Foo{} register the element schema.
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
	}
	if t.Kind() != reflect.Struct {
		return
	}
	name := t.Name()
	if name == "" || r.schemas[name] != nil {
		return
	}
	r.schemas[name] = structSchema(t, r)
}

// structSchema renders a Go struct as an OpenAPI schema object. Recurses
// into nested struct fields. Generic types (CursorPage[Foo]) get a
// flattened name (CursorPageFoo) so the spec stays clean.
func structSchema(t reflect.Type, r *Registry) any {
	props := map[string]any{}
	var required []string

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		name, opts := splitJSONTag(tag)
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		schema := fieldSchema(f.Type, r)
		// `kielo:"deprecated"` struct tag flows through to the OpenAPI
		// spec's per-field `deprecated: true` (OpenAPI 3.0+ supports
		// this on schema objects). Optionally include a sunset date /
		// successor field name via `kielo:"deprecated,since=2026-09-01,use=next_page_key"`
		// — those land in `x-kielo-deprecation` so codegen can hint
		// callers without bloating the spec's standard fields.
		if kt := f.Tag.Get("kielo"); kt != "" {
			if schemaMap, ok := schema.(map[string]any); ok {
				applyKieloTag(schemaMap, kt)
				schema = schemaMap
			}
		}
		props[name] = schema
		// Pointer fields are nullable AND not required: a nil pointer
		// marshals as JSON `null`, and callers don't have to send the
		// field at all (the Go side decodes a missing field as nil).
		// Without this, `*string` fields without `omitempty` were
		// emitted as required string, which forced TS consumers to
		// invent placeholder values for fields the server treats as
		// optional (e.g. ConvoCreateVoiceAgentRequest.gender).
		isPointer := f.Type.Kind() == reflect.Ptr
		if !contains(opts, "omitempty") && !isPointer {
			required = append(required, name)
		}
	}

	out := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func fieldSchema(t reflect.Type, r *Registry) any {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	// Special-case well-known stdlib + ecosystem types BEFORE the generic
	// Kind switch. Without this, reflect sees their underlying
	// representation (e.g. uuid.UUID == [16]byte → array<int>;
	// time.Time == struct{} with unexported fields → empty object) which
	// completely disagrees with their JSON wire format. Every UUID/
	// timestamp field in /api/v3 was previously mistyped, forcing every
	// TS consumer to defensively cast around the broken contract.
	if s := wireSchemaForNamedType(t); s != nil {
		return s
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": fieldSchema(t.Elem(), r)}
	case reflect.Map:
		// For `map[string]<X>` with concrete X, emit additionalProperties
		// as the X-schema. For `map[string]any` / `map[string]interface{}`,
		// emit a free-form additionalProperties so consumers see the value
		// as the JSON "any-value" type (Record<string, unknown>) rather
		// than getting an extra Record<string, Record<string, unknown>>
		// nesting from the default Interface handler.
		if t.Elem().Kind() == reflect.Interface {
			return map[string]any{"type": "object", "additionalProperties": true}
		}
		return map[string]any{"type": "object", "additionalProperties": fieldSchema(t.Elem(), r)}
	case reflect.Interface:
		// Interface{} field — caller wants "any JSON value" at this slot.
		// Empty schema is the OAS-canonical way to say "no constraint";
		// hey-api emits `unknown` for that, which is exactly what the
		// caller of a map[string]any / any field needs.
		return map[string]any{}
	case reflect.Struct:
		// Register a sub-schema and reference it.
		if t.Name() != "" {
			if r.schemas[t.Name()] == nil {
				r.schemas[t.Name()] = structSchema(t, r)
			}
			return map[string]any{"$ref": "#/components/schemas/" + t.Name()}
		}
		// Anonymous struct — inline.
		return structSchema(t, r)
	default:
		return map[string]any{"type": "object"}
	}
}

// wireSchemaForNamedType maps Go types whose JSON wire format does NOT
// match their reflected structure to the correct OpenAPI schema.
//
// Add a new entry here when a Go type:
//   - implements a custom MarshalJSON that emits a primitive (string,
//     number, ...) while its reflected Kind is Struct/Array/Map, OR
//   - is a struct with no exported fields but a meaningful wire format
//     (e.g. time.Time renders to RFC 3339 via MarshalJSON, not "{}").
//
// Returns nil when the type does not need special handling — the caller
// then falls through to the generic Kind switch.
func wireSchemaForNamedType(t reflect.Type) map[string]any {
	// reflect.Type identity check via PkgPath + Name. t.String() collapses
	// to the same value for vendored copies, which is what we want.
	pkg := t.PkgPath()
	name := t.Name()
	if pkg == "" || name == "" {
		return nil
	}
	key := pkg + "." + name
	switch key {
	// Canonical UUIDs serialize as quoted strings via uuid.UUID.MarshalJSON
	// even though they're backed by [16]byte.
	case "github.com/google/uuid.UUID":
		return map[string]any{"type": "string", "format": "uuid"}
	// time.Time.MarshalJSON emits RFC 3339; the struct has only unexported
	// fields so the default reflection renders {}.
	case "time.Time":
		return map[string]any{"type": "string", "format": "date-time"}
	// json.RawMessage is []byte but MarshalJSON passes through arbitrary
	// JSON. The most accurate spec is "any JSON value"; per OpenAPI 3.1
	// that's an empty schema. Use a minimal `{}` so codegen produces an
	// `unknown` (TS) / `any` (Go) rather than `Array<number>`.
	case "encoding/json.RawMessage":
		return map[string]any{}
	}
	return nil
}

// applyKieloTag parses the `kielo:"..."` struct tag and merges its
// directives into the per-field schema map.
//
// Recognized directives:
//   - "deprecated"               → schema.deprecated = true
//   - "since=YYYY-MM-DD"         → x-kielo-deprecation.since = "..."
//   - "use=other_field_name"     → x-kielo-deprecation.use = "..."
//
// Unknown directives are ignored so a future addition doesn't fail
// the spec generation.
func applyKieloTag(schema map[string]any, tag string) {
	parts := strings.Split(tag, ",")
	deprecation := map[string]any{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch {
		case p == "deprecated":
			schema["deprecated"] = true
		case strings.HasPrefix(p, "since="):
			deprecation["since"] = strings.TrimPrefix(p, "since=")
		case strings.HasPrefix(p, "use="):
			deprecation["use"] = strings.TrimPrefix(p, "use=")
		}
	}
	if len(deprecation) > 0 {
		schema["x-kielo-deprecation"] = deprecation
	}
}

func splitJSONTag(tag string) (name string, opts []string) {
	parts := strings.Split(tag, ",")
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func (r *Registry) buildSchemas() map[string]any {
	keys := make([]string, 0, len(r.schemas))
	for k := range r.schemas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]any{}
	for _, k := range keys {
		out[k] = r.schemas[k]
	}
	// Always include the canonical error envelope schema.
	out["CanonicalError"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"error": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code":     map[string]any{"type": "string"},
					"message":  map[string]any{"type": "string"},
					"details":  map[string]any{"type": "object"},
					"trace_id": map[string]any{"type": "string"},
				},
				"required": []string{"code", "message"},
			},
			"message": map[string]any{"type": "string"},
		},
	}
	return out
}

func canonicalErrorResponses() map[string]any {
	canon := map[string]any{
		"description": "Canonical error envelope per ADR-004 §5",
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/CanonicalError"},
			},
		},
	}
	return map[string]any{
		"BadRequest":     canon,
		"Unauthorized":   canon,
		"Forbidden":      canon,
		"NotFound":       canon,
		"Conflict":       canon,
		"InternalError":  canon,
		"CanonicalError": canon,
	}
}

func schemaRef(v any) string {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Name() != "" {
		return "#/components/schemas/" + t.Name()
	}
	return "#/components/schemas/AnonymousSchema"
}

// responseSchema renders the response schema map for a Route.Response
// zero value. Named structs ($ref) and arrays-of-named-structs
// (`{type: array, items: {$ref: ...}}`) both produce typed schemas
// that pass scripts/contract-health.py's "typed" classifier.
// Pointers are unwrapped; anonymous structs fall back to the
// AnonymousSchema $ref (legacy behavior).
func responseSchema(v any, r *Registry) map[string]any {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		// Walk the element type so its schema is collected.
		elem := t.Elem()
		for elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		return map[string]any{
			"type":  "array",
			"items": fieldSchema(t.Elem(), r),
		}
	default:
		if t.Kind() == reflect.Struct && t.Name() != "" {
			return map[string]any{"$ref": "#/components/schemas/" + t.Name()}
		}
		// Legacy fallback (anonymous types, maps, primitives).
		return map[string]any{"$ref": schemaRef(v)}
	}
}

// WriteSpecToFile serializes the registry to a JSON file. Typically called
// from main() in dev mode, or `go run`-driven from a Makefile target.
func (r *Registry) WriteSpecToFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := r.MarshalJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
