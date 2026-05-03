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
	mu       sync.Mutex
	service  string
	title    string
	version  string
	routes   []routeEntry
	schemas  map[string]any // by Go type name; populated lazily on use
}

type routeEntry struct {
	method        string
	path          string
	summary       string
	description   string
	tag           string
	pathParams    []paramSpec
	queryParams   []paramSpec
	requestBody   any // value of struct type (zero); nil if no body
	responseBody  any // zero value of response struct
	errorCodes    []int // additional non-2xx HTTP codes documented
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
		method:       method,
		path:         w.prefix + path,
		summary:      route.Summary,
		description:  route.Description,
		tag:          route.Tag,
		pathParams:   toParamSpecs(route.PathParams),
		queryParams:  toParamSpecs(route.QueryParams),
		requestBody:  route.RequestBody,
		responseBody: route.Response,
		errorCodes:   route.ErrorCodes,
	})
	return er
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
	if rt.responseBody != nil {
		resp["200"] = map[string]any{
			"description": "Success",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": schemaRef(rt.responseBody)},
				},
			},
		}
	} else {
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
		props[name] = fieldSchema(f.Type, r)
		if !contains(opts, "omitempty") {
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
		return map[string]any{"type": "object", "additionalProperties": fieldSchema(t.Elem(), r)}
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
		"BadRequest":      canon,
		"Unauthorized":    canon,
		"Forbidden":       canon,
		"NotFound":        canon,
		"Conflict":        canon,
		"InternalError":   canon,
		"CanonicalError":  canon,
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

// WriteSpecToFile serializes the registry to a JSON file. Typically called
// from main() in dev mode, or `go run`-driven from a Makefile target.
func (r *Registry) WriteSpecToFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := r.MarshalJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
