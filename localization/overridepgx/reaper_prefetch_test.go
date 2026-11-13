package overridepgx

import (
	"context"
	"reflect"
	"testing"
)

func TestDistinctResources_FirstSeenOrderNoDuplicates(t *testing.T) {
	batch := []scanRow{
		{ResourceType: "a", ResourceID: "1", LanguageCode: "vi"},
		{ResourceType: "a", ResourceID: "1", LanguageCode: "sv"},
		{ResourceType: "a", ResourceID: "2", LanguageCode: "vi"},
		{ResourceType: "b", ResourceID: "1", LanguageCode: "vi"},
	}
	want := [][2]string{{"a", "1"}, {"a", "2"}, {"b", "1"}}
	if got := distinctResources(batch); !reflect.DeepEqual(got, want) {
		t.Fatalf("distinctResources = %v, want %v", got, want)
	}
}

func TestWithPagePrefetch_SetsHook(t *testing.T) {
	r := NewReaper(nil, nil, WithPagePrefetch(nil))
	if r.prefetch != nil {
		t.Fatal("nil hook must stay unset")
	}
	r = NewReaper(nil, nil, WithPagePrefetch(func(context.Context, [][2]string) {}))
	if r.prefetch == nil {
		t.Fatal("hook not set")
	}
}
