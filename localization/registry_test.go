package localization

import (
	"context"
	"errors"
	"testing"
)

type stubProvider struct {
	id      string
	batches int
}

func (s *stubProvider) ProviderID() string { return s.id }

func (s *stubProvider) TranslateBatch(
	_ context.Context,
	items []TranslationItem,
	_ TranslateOptions,
) ([]TranslationResult, error) {
	s.batches++
	out := make([]TranslationResult, 0, len(items))
	for _, item := range items {
		out = append(out, TranslationResult{Text: item.Text, Provider: s.id})
	}
	return out, nil
}

func TestExactRouteWinsOverWildcardAndDefault(t *testing.T) {
	r := NewRegistry()
	r.SetDefault("default")
	_ = r.Register("default", &stubProvider{id: "default"})
	_ = r.Register("exact", &stubProvider{id: "exact"})
	_ = r.Register("wild", &stubProvider{id: "wild"})
	_ = r.Route("en", "vi", "exact")
	_ = r.Route("en", "*", "wild")

	p, err := r.Resolve("en", "vi")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.ProviderID() != "exact" {
		t.Fatalf("expected exact; got %s", p.ProviderID())
	}
}

func TestWildcardTargetRoute(t *testing.T) {
	r := NewRegistry()
	r.SetDefault("default")
	_ = r.Register("default", &stubProvider{id: "default"})
	_ = r.Register("wild", &stubProvider{id: "wild"})
	_ = r.Route("en", "*", "wild")

	p, _ := r.Resolve("en", "de")
	if p.ProviderID() != "wild" {
		t.Fatalf("expected wild; got %s", p.ProviderID())
	}
}

func TestUnknownProviderFailsLoud(t *testing.T) {
	r := NewRegistry()
	r.SetDefault("ghost")
	_, err := r.Resolve("en", "vi")
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("expected ErrUnknownProvider; got %v", err)
	}
}

func TestNoRouteNoDefaultFailsLoud(t *testing.T) {
	r := NewRegistry()
	_ = r.Register("only", &stubProvider{id: "only"})
	_, err := r.Resolve("en", "vi")
	if !errors.Is(err, ErrNoRouteAndNoDefault) {
		t.Fatalf("expected ErrNoRouteAndNoDefault; got %v", err)
	}
}

func TestBuildRegistryFromEnv(t *testing.T) {
	env := []string{
		"LOC_PROVIDER_DEFAULT=openai",
		"LOC_ROUTE_EN_VI=openai_pro",
		"LOC_ROUTE_EN_STAR=openai_general",
		"UNRELATED=ignore",
	}
	r := BuildRegistryFromEnv(env)
	if r.defaultProvider != "openai" {
		t.Fatalf("default = %q", r.defaultProvider)
	}
	if r.routes[routeKey{source: "en", target: "vi"}] != "openai_pro" {
		t.Fatalf("en/vi = %q", r.routes[routeKey{source: "en", target: "vi"}])
	}
	if r.routes[routeKey{source: "en", target: "*"}] != "openai_general" {
		t.Fatalf("en/* = %q", r.routes[routeKey{source: "en", target: "*"}])
	}
}

func TestCacheKeyUsesItemCacheKeyWhenSet(t *testing.T) {
	a := CacheKey("openai", "en", "vi", TranslationItem{Text: "hello", Role: RolePlain})
	b := CacheKey("openai", "en", "vi", TranslationItem{Text: "different", Role: RolePlain, CacheKey: "hello"})
	// b's CacheKey is "hello" so digest matches a's digest.
	if a != b {
		t.Fatalf("cache key collision expected; a=%s b=%s", a, b)
	}
}

func TestCacheKeyIsolatesByRoleAndProvider(t *testing.T) {
	plain := CacheKey("openai", "en", "vi", TranslationItem{Text: "hello", Role: RolePlain})
	gloss := CacheKey("openai", "en", "vi", TranslationItem{Text: "hello", Role: RoleGloss})
	other := CacheKey("gemini", "en", "vi", TranslationItem{Text: "hello", Role: RolePlain})
	if plain == gloss {
		t.Fatalf("role must isolate")
	}
	if plain == other {
		t.Fatalf("provider must isolate")
	}
}
