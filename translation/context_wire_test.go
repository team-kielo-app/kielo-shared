package translation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The seam's whole fix depends on `contexts` actually reaching the engine, and
// on un-hinted batches serializing exactly as before (the engine caches on the
// texts, so a changed payload shape would orphan every existing entry).
func TestTranslateBatchWithContexts_WirePayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"translations":["x"]}`))
	}))
	defer srv.Close()

	c := NewClient("", srv.URL, "k", srv.Client())

	t.Run("hints are sent", func(t *testing.T) {
		got = nil
		c.TranslateBatchWithContexts(context.Background(),
			[]string{"Sun"}, []string{"UI string ui.day_abbr.Sun"}, "en", "vi")
		raw, ok := got["contexts"]
		if !ok {
			t.Fatalf("contexts absent from payload: %v", got)
		}
		arr, _ := raw.([]any)
		if len(arr) != 1 || arr[0] != "UI string ui.day_abbr.Sun" {
			t.Fatalf("unexpected contexts: %v", raw)
		}
	})

	t.Run("blank hints are omitted entirely", func(t *testing.T) {
		got = nil
		c.TranslateBatchWithContexts(context.Background(),
			[]string{"Sun"}, []string{"  "}, "en", "vi")
		if _, ok := got["contexts"]; ok {
			t.Fatalf("blank contexts must be omitted, got: %v", got)
		}
	})

	t.Run("legacy TranslateBatch payload is unchanged", func(t *testing.T) {
		got = nil
		c.TranslateBatch(context.Background(), []string{"Sun"}, "en", "vi")
		if _, ok := got["contexts"]; ok {
			t.Fatalf("un-hinted batch must not carry contexts: %v", got)
		}
	})
}
