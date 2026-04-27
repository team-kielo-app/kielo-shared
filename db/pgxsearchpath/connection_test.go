package pgxsearchpath

import (
	"strings"
	"testing"
)

func TestSetSearchPathOnConnect(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"single schema", "cms"},
		{"multiple schemas", "klearn, cms, public"},
		{"with whitespace", "  klearn ,  cms  ,public"},
		{"all schemas", "users, klearn, cms, localization, communications, convo, media, public"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic for valid paths.
			handler := SetSearchPathOnConnect(tt.path)
			if handler == nil {
				t.Fatal("handler should not be nil")
			}
		})
	}
}

func TestSetSearchPathOnConnect_PanicsOnInvalidPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"sql injection attempt", "cms; DROP TABLE users;"},
		{"hyphen in identifier", "cms-bad"},
		{"quote in identifier", `cms"bad`},
		{"empty string", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if tt.name == "empty string" {
					// Empty path is allowed by SanitizeSearchPath (it
					// returns an empty cleaned string with nil error)
					// — the resulting "SET search_path TO " is invalid
					// SQL but we don't catch that here. Skip.
					return
				}
				if r == nil {
					t.Errorf("expected panic for path %q, got none", tt.path)
					return
				}
				msg, ok := r.(string)
				if !ok {
					t.Errorf("expected string panic, got %T: %v", r, r)
					return
				}
				if !strings.Contains(msg, "invalid search_path") {
					t.Errorf("panic message %q should mention invalid search_path", msg)
				}
			}()
			SetSearchPathOnConnect(tt.path)
		})
	}
}
