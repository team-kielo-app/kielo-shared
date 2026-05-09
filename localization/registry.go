package localization

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ErrUnknownProvider is returned when a route resolves to a provider id
// that has not been registered. Fail-loud over silently routing to a
// default.
var ErrUnknownProvider = errors.New("localization: unknown provider id")

// ErrNoRouteAndNoDefault is returned when neither a matching route nor a
// default provider has been set.
var ErrNoRouteAndNoDefault = errors.New("localization: no route and no default")

// Registry maps provider ids to providers and resolves (source, target)
// locale pairs to a registered provider. Mirrors the Python registry.
//
// Routing precedence:
//
//	(source, target) → (source, "*") → ("*", target) → ("*", "*") → default
type Registry struct {
	mu              sync.RWMutex
	providers       map[string]Provider
	routes          map[routeKey]string
	defaultProvider string
}

type routeKey struct {
	source string
	target string
}

// NewRegistry builds an empty registry. Use SetDefault + Register +
// Route to populate, then Resolve to look up at call sites.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		routes:    make(map[routeKey]string),
	}
}

// Register adds (or replaces) a provider by id.
func (r *Registry) Register(id string, p Provider) error {
	if id == "" {
		return errors.New("localization: provider id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[id] = p
	return nil
}

// Route adds a (source, target) → provider id mapping. Use "*" for either
// slot as a wildcard.
func (r *Registry) Route(source, target, providerID string) error {
	if providerID == "" {
		return errors.New("localization: provider id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[routeKey{source: source, target: target}] = providerID
	return nil
}

// SetDefault marks a provider id as the fallback when no route matches.
func (r *Registry) SetDefault(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultProvider = id
}

// Resolve returns the provider for a (source, target) locale pair. Errors:
//
//   - ErrNoRouteAndNoDefault when nothing matches and no default is set.
//   - ErrUnknownProvider when the resolved id was never registered.
func (r *Registry) Resolve(source, target string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id := r.resolveID(source, target)
	if id == "" {
		return nil, fmt.Errorf("%w: source=%q target=%q", ErrNoRouteAndNoDefault, source, target)
	}
	p, ok := r.providers[id]
	if !ok {
		return nil, fmt.Errorf("%w: id=%q", ErrUnknownProvider, id)
	}
	return p, nil
}

func (r *Registry) resolveID(source, target string) string {
	for _, key := range []routeKey{
		{source: source, target: target},
		{source: source, target: "*"},
		{source: "*", target: target},
		{source: "*", target: "*"},
	} {
		if id, ok := r.routes[key]; ok {
			return id
		}
	}
	return r.defaultProvider
}

// BuildRegistryFromEnv reads `LOC_*` environment variables and populates a
// Registry. Mirrors the Python loader; provider instances are NOT
// registered here — call sites do that after construction.
func BuildRegistryFromEnv(env []string) *Registry {
	if env == nil {
		env = os.Environ()
	}
	r := NewRegistry()
	for _, kv := range env {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		key, value := kv[:idx], kv[idx+1:]
		switch {
		case key == "LOC_PROVIDER_DEFAULT":
			if value != "" {
				r.SetDefault(value)
			}
		case strings.HasPrefix(key, "LOC_ROUTE_"):
			suffix := key[len("LOC_ROUTE_"):]
			parts := strings.SplitN(suffix, "_", 2)
			if len(parts) != 2 || value == "" {
				continue
			}
			source := strings.ToLower(parts[0])
			target := strings.ToLower(parts[1])
			if source == "star" {
				source = "*"
			}
			if target == "star" {
				target = "*"
			}
			_ = r.Route(source, target, value)
		}
	}
	return r
}
