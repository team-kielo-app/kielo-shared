package locale

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// Tests for the ADR-008 Phase 5 wire-up of conversationCategoryRegistry.
//
// Round 6 C10 (2026-06-09): regression coverage for the inert-wrap
// defect class — every dynamicregistry-wrapped registry MUST seed
// English. Recon confirmed this registry DOES seed English correctly
// (line 76, 89); these tests pin that contract so a future commit
// can't silently regress it.

// TestConversationCategorySeed_EnglishIsSeededForAllKeys is the
// canonical regression invariant.
func TestConversationCategorySeed_EnglishIsSeededForAllKeys(t *testing.T) {
	ctx := context.Background()

	// Categories (line 64-78 in conversation_category.go).
	for _, cat := range []string{
		"everyday-life",
		"shopping-services",
		"food-dining",
		"transport-travel",
		"work-professional",
		"social-relationships",
		"health-wellbeing",
		"education-learning",
		"finnish-society",
		"culture-leisure",
		"digital-modern",
		"advanced-real-life",
		"other",
	} {
		key := supportregistry.Key("ui.conversation.category." + cat)
		got := conversationCategorySeed.Resolve(ctx, key, "en")
		if got == string(key) {
			t.Errorf("English seed missing for conversation category %q "+
				"(would silently disable dynamicregistry override probe)", cat)
		}
	}

	// Buckets.
	for _, bucket := range []string{"main", "other"} {
		key := supportregistry.Key("ui.conversation.bucket." + bucket)
		got := conversationCategorySeed.Resolve(ctx, key, "en")
		if got == string(key) {
			t.Errorf("English seed missing for conversation bucket %q "+
				"(would silently disable dynamicregistry override probe)", bucket)
		}
	}
}

// TestConversationCategorySeed_ReturnsRegistry confirms the public
// ConversationCategorySeed() accessor returns a non-nil registry
// (consumer-side wire-up at user-service main.go + convo orchestrator
// main.go depends on this contract).
func TestConversationCategorySeed_ReturnsRegistry(t *testing.T) {
	got := ConversationCategorySeed()
	if got == nil {
		t.Fatal("ConversationCategorySeed() returned nil")
	}
}

// TestConversationCategoryRegistry_DefaultResolvesViaSeed: pre-Set
// state returns the static vi translation.
func TestConversationCategoryRegistry_DefaultResolvesViaSeed(t *testing.T) {
	got := ConversationCategoryLabel("food-dining", "vi")
	assert.Equal(t, "Ẩm thực & ăn uống", got)
	got = ConversationBucketLabel("main", "vi")
	assert.Equal(t, "Chính", got)
}

// TestSetConversationCategoryRegistry_NilIsNoOp verifies that
// passing nil to SetConversationCategoryRegistry preserves the
// current registry rather than clobbering it.
func TestSetConversationCategoryRegistry_NilIsNoOp(t *testing.T) {
	restoreConversationCategorySeed(t)

	// Sanity: initial state resolves correctly.
	assert.Equal(t, "Khác", ConversationCategoryLabel("other", "vi"))

	// nil swap must not clobber the existing registry.
	SetConversationCategoryRegistry(nil)
	assert.Equal(t, "Khác", ConversationCategoryLabel("other", "vi"))
}

// restoreConversationCategorySeed restores the package registry to
// seed state at test cleanup so tests are order-independent.
func restoreConversationCategorySeed(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		conversationCategoryRegistryMu.Lock()
		conversationCategoryRegistry = conversationCategorySeed
		conversationCategoryRegistryMu.Unlock()
	})
}
