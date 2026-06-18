package db

import (
	"testing"
	"time"
)

func TestEnvInt32(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback int32
		want     int32
	}{
		{"unset returns fallback", "", 25, 25},
		{"valid positive value", "100", 25, 100},
		{"unparseable returns fallback", "abc", 25, 25},
		{"negative returns fallback", "-5", 25, 25},
		{"zero returns fallback", "0", 25, 25},
		{"overflow returns fallback", "99999999999", 25, 25},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KIELO_TEST_INT", tt.env)
			if got := EnvInt32("KIELO_TEST_INT", tt.fallback); got != tt.want {
				t.Errorf("EnvInt32 with env=%q fallback=%d = %d, want %d", tt.env, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestEnvString(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback string
		want     string
	}{
		{"unset returns fallback", "", "fallback", "fallback"},
		{"explicit value used", "explicit", "fallback", "explicit"},
		{"whitespace trimmed", "  trimmed  ", "fallback", "trimmed"},
		{"all-whitespace returns fallback", "   ", "fallback", "fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KIELO_TEST_STR", tt.env)
			if got := EnvString("KIELO_TEST_STR", tt.fallback); got != tt.want {
				t.Errorf("EnvString with env=%q fallback=%q = %q, want %q", tt.env, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback bool
		want     bool
	}{
		{"unset returns fallback false", "", false, false},
		{"unset returns fallback true", "", true, true},
		{"true literal", "true", false, true},
		{"TRUE uppercase", "TRUE", false, true},
		{"1 numeric", "1", false, true},
		{"false literal", "false", true, false},
		{"0 numeric", "0", true, false},
		{"unparseable returns fallback", "yes", true, true},
		{"unparseable returns fallback false", "yes", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KIELO_TEST_BOOL", tt.env)
			if got := EnvBool("KIELO_TEST_BOOL", tt.fallback); got != tt.want {
				t.Errorf("EnvBool with env=%q fallback=%t = %t, want %t", tt.env, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestEnvDuration(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback time.Duration
		want     time.Duration
	}{
		{"unset returns fallback", "", 30 * time.Second, 30 * time.Second},
		{"valid seconds", "5s", 30 * time.Second, 5 * time.Second},
		{"valid minutes", "2m", 30 * time.Second, 2 * time.Minute},
		{"unparseable returns fallback", "abc", 30 * time.Second, 30 * time.Second},
		{"negative returns fallback", "-5s", 30 * time.Second, 30 * time.Second},
		{"zero returns fallback", "0s", 30 * time.Second, 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KIELO_TEST_DUR", tt.env)
			if got := EnvDuration("KIELO_TEST_DUR", tt.fallback); got != tt.want {
				t.Errorf("EnvDuration with env=%q fallback=%s = %s, want %s", tt.env, tt.fallback, got, tt.want)
			}
		})
	}
}
