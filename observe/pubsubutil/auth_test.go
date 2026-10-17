package pubsubutil

import "testing"

func TestCheckPushIdentity(t *testing.T) {
	ok := map[string]any{"email": "Push@p.iam.gserviceaccount.com", "email_verified": true}
	cases := []struct {
		name    string
		claims  map[string]any
		allowed string
		wantErr bool
	}{
		{"unset keeps audience-only", map[string]any{}, "", false},
		{"listed account", ok, "x@p.iam.gserviceaccount.com, push@p.iam.gserviceaccount.com", false},
		{"stranger account", map[string]any{"email": "evil@other.iam.gserviceaccount.com", "email_verified": true}, "push@p.iam.gserviceaccount.com", true},
		{"unverified email", map[string]any{"email": "push@p.iam.gserviceaccount.com", "email_verified": false}, "push@p.iam.gserviceaccount.com", true},
		{"no email claim", map[string]any{"email_verified": true}, "push@p.iam.gserviceaccount.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkPushIdentity(tc.claims, tc.allowed); (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
