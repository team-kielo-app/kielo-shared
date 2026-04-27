package middleware

import (
	"reflect"
	"testing"
)

func TestCORSAllowedOrigins(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback string
		want     []string
	}{
		{
			name:     "env set wins over fallback",
			env:      "https://app.example.com,https://admin.example.com",
			fallback: "https://fallback.example.com",
			want:     []string{"https://app.example.com", "https://admin.example.com"},
		},
		{
			name:     "fallback used when env unset",
			env:      "",
			fallback: "https://app.example.com",
			want:     []string{"https://app.example.com"},
		},
		{
			name:     "fallback used when env is whitespace",
			env:      "   ",
			fallback: "https://app.example.com",
			want:     []string{"https://app.example.com"},
		},
		{
			name:     "trims and drops empties",
			env:      "  https://a.com  ,, https://b.com ,",
			fallback: "",
			want:     []string{"https://a.com", "https://b.com"},
		},
		{
			name:     "empty list returns null sentinel + WARN",
			env:      "",
			fallback: "",
			want:     []string{"null"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CORS_ALLOWED_ORIGINS", tt.env)
			got := CORSAllowedOrigins(tt.fallback)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CORSAllowedOrigins(%q) with env=%q = %v, want %v", tt.fallback, tt.env, got, tt.want)
			}
		})
	}
}
