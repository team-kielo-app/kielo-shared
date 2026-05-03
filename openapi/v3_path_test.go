package openapi

import "testing"

// echoPathFromOAS bridges OAS `{name}` and Echo `:name`. Pin the cases that
// matter for ADR-004 routes so a future "simplification" of the helper
// doesn't silently 404 every parameter route.
func TestEchoPathFromOAS(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/me/profile", "/me/profile"},
		{"/users/{user_id}/profile", "/users/:user_id/profile"},
		{"/me/notifications/{notification_id}/read", "/me/notifications/:notification_id/read"},
		{"/me/saved-items/{item_type}/{item_id}", "/me/saved-items/:item_type/:item_id"},
		{"/me/items/{item_type}/{item_id}/learning-status", "/me/items/:item_type/:item_id/learning-status"},
		// Trailing brace, no close → pass through (defensive; not used in real routes).
		{"/foo/{abc", "/foo/{abc"},
	}

	for _, c := range cases {
		got := echoPathFromOAS(c.in)
		if got != c.want {
			t.Errorf("echoPathFromOAS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
