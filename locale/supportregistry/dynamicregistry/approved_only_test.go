package dynamicregistry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestApprovedOnlyDoesNotReuseMachineCapableCache(t *testing.T) {
	ctx := context.Background()
	seed, cache := buildSeed(t), newStubCache()
	regular := New(seed, nil, cache)
	version, _, _ := regular.sourceVersionFor(ctx, "ui.greeting")
	key := regular.cacheKeyFor("ui.greeting", version, "sv")
	require.NoError(t, cache.Set(ctx, key, "Unreviewed cached copy", time.Minute))
	require.Equal(t, "Unreviewed cached copy", regular.Resolve(ctx, "ui.greeting", "sv"))

	for _, opts := range [][]Option{
		{WithApprovedOnly(), WithTranslator(newRecordingTranslator())},
		{WithTranslator(newRecordingTranslator()), WithApprovedOnly()},
	} {
		r := New(seed, nil, cache, opts...)
		require.Equal(t, "Hej", r.Resolve(ctx, "ui.greeting", "sv"))
		require.IsType(t, NoopTranslator{}, r.translator)
		require.NotEqual(t, key, r.cacheKeyFor("ui.greeting", version, "sv"))
	}
}
