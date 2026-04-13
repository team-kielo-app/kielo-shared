package gcs

import (
	"testing"
)

func TestContextualizeStorageURL(t *testing.T) {
	tests := []struct {
		name            string
		requestHostname string
		rawURL          string
		envHostIP       string
		envEmulatorHost string
		want            string
	}{
		{
			name:            "empty URL returns empty",
			requestHostname: "localhost",
			rawURL:          "",
			want:            "",
		},
		{
			name:            "whitespace URL returns empty",
			requestHostname: "localhost",
			rawURL:          "   ",
			want:            "",
		},
		{
			name:            "non-storage URL unchanged",
			requestHostname: "localhost",
			rawURL:          "http://example.com/some/path",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://example.com/some/path",
		},
		{
			name:            "empty request hostname returns unchanged",
			requestHostname: "",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
		},
		{
			name:            "loopback request rewrites to HOST_IP",
			requestHostname: "localhost",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
			envHostIP:       "192.168.1.70",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://192.168.1.70:4443/storage/v1/b/bucket/o/obj",
		},
		{
			name:            "loopback 127.0.0.1 request rewrites to HOST_IP",
			requestHostname: "127.0.0.1",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
			envHostIP:       "10.0.0.5",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://10.0.0.5:4443/storage/v1/b/bucket/o/obj",
		},
		{
			name:            "loopback without HOST_IP falls back to localhost",
			requestHostname: "localhost",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
			envHostIP:       "",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://localhost:4443/storage/v1/b/bucket/o/obj",
		},
		{
			name:            "internal docker hostname rewrites to internal emulator",
			requestHostname: "kielo-cms",
			rawURL:          "http://somehost:4443/storage/v1/b/bucket/o/obj",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
		},
		{
			name:            "external hostname with dots unchanged",
			requestHostname: "api.kielo.app",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
		},
		{
			name:            "no emulator configured returns unchanged",
			requestHostname: "localhost",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
			envEmulatorHost: "",
			want:            "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOST_IP", tt.envHostIP)
			t.Setenv("STORAGE_EMULATOR_HOST", tt.envEmulatorHost)

			got := ContextualizeStorageURL(tt.requestHostname, tt.rawURL)
			if got != tt.want {
				t.Errorf("ContextualizeStorageURL(%q, %q) = %q, want %q",
					tt.requestHostname, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestContextualizeServiceURL(t *testing.T) {
	tests := []struct {
		name            string
		requestHostname string
		rawURL          string
		envHostIP       string
		envEmulatorHost string
		want            string
	}{
		{
			name:            "empty URL returns empty",
			requestHostname: "localhost",
			rawURL:          "",
			want:            "",
		},
		{
			name:            "whitespace URL returns empty",
			requestHostname: "localhost",
			rawURL:          "   ",
			want:            "",
		},
		{
			name:            "URL without host returns unchanged",
			requestHostname: "localhost",
			rawURL:          "/relative/path",
			want:            "/relative/path",
		},
		{
			name:            "GCS storage URL delegates to ContextualizeStorageURL",
			requestHostname: "localhost",
			rawURL:          "http://gcs-emulator:4443/storage/v1/b/bucket/o/obj?alt=media",
			envHostIP:       "192.168.1.70",
			envEmulatorHost: "gcs-emulator:4443",
			want:            "http://192.168.1.70:4443/storage/v1/b/bucket/o/obj?alt=media",
		},
		{
			name:            "internal docker hostname rewritten for loopback request",
			requestHostname: "localhost",
			rawURL:          "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
			envHostIP:       "192.168.1.70",
			want:            "http://192.168.1.70:8080/api/v1/outputs/video.mp4",
		},
		{
			name:            "internal docker hostname without HOST_IP falls back to localhost",
			requestHostname: "127.0.0.1",
			rawURL:          "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
			envHostIP:       "",
			want:            "http://localhost:8080/api/v1/outputs/video.mp4",
		},
		{
			name:            "port is preserved during rewrite",
			requestHostname: "localhost",
			rawURL:          "http://kielo-cms:9999/some/path",
			envHostIP:       "10.0.0.5",
			want:            "http://10.0.0.5:9999/some/path",
		},
		{
			name:            "query string preserved during rewrite",
			requestHostname: "localhost",
			rawURL:          "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4?token=abc",
			envHostIP:       "192.168.1.70",
			want:            "http://192.168.1.70:8080/api/v1/outputs/video.mp4?token=abc",
		},
		{
			name:            "external hostname with dots not rewritten",
			requestHostname: "localhost",
			rawURL:          "https://storage.googleapis.com/bucket/obj",
			envHostIP:       "192.168.1.70",
			want:            "https://storage.googleapis.com/bucket/obj",
		},
		{
			name:            "non-loopback request does not rewrite internal hostname",
			requestHostname: "kielo-cms",
			rawURL:          "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
			envHostIP:       "192.168.1.70",
			want:            "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
		},
		{
			name:            "production hostname does not rewrite",
			requestHostname: "api.kielo.app",
			rawURL:          "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
			envHostIP:       "192.168.1.70",
			want:            "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
		},
		{
			name:            "empty request hostname does not rewrite",
			requestHostname: "",
			rawURL:          "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
			envHostIP:       "192.168.1.70",
			want:            "http://kielo-ktv-api:8080/api/v1/outputs/video.mp4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOST_IP", tt.envHostIP)
			t.Setenv("STORAGE_EMULATOR_HOST", tt.envEmulatorHost)

			got := ContextualizeServiceURL(tt.requestHostname, tt.rawURL)
			if got != tt.want {
				t.Errorf("ContextualizeServiceURL(%q, %q) = %q, want %q",
					tt.requestHostname, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestParseEmulatorPort(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{"empty returns default", "", "4443"},
		{"host:port", "gcs-emulator:4443", "4443"},
		{"host:custom-port", "gcs-emulator:9999", "9999"},
		{"http URL with port", "http://gcs-emulator:4443", "4443"},
		{"http URL with custom port", "http://localhost:5555", "5555"},
		{"host only no port", "gcs-emulator", "4443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STORAGE_EMULATOR_HOST", tt.env)
			got := ParseEmulatorPort()
			if got != tt.want {
				t.Errorf("ParseEmulatorPort() with env=%q = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}

func TestIsLoopbackHostname(t *testing.T) {
	tests := []struct {
		hostname string
		want     bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"::1", true},
		{"gcs-emulator", false},
		{"kielo-cms", false},
		{"192.168.1.70", false},
		{"10.0.0.5", false},
		{"api.kielo.app", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			got := IsLoopbackHostname(tt.hostname)
			if got != tt.want {
				t.Errorf("IsLoopbackHostname(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestExternalEmulatorBaseURL(t *testing.T) {
	tests := []struct {
		name        string
		envEmulator string
		envHostIP   string
		want        string
	}{
		{"no emulator configured", "", "", ""},
		{"emulator with HOST_IP", "gcs-emulator:4443", "192.168.1.70", "http://192.168.1.70:4443"},
		{"emulator without HOST_IP", "gcs-emulator:4443", "", "http://localhost:4443"},
		{"emulator with custom port", "gcs-emulator:9999", "10.0.0.5", "http://10.0.0.5:9999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STORAGE_EMULATOR_HOST", tt.envEmulator)
			t.Setenv("HOST_IP", tt.envHostIP)
			got := ExternalEmulatorBaseURL()
			if got != tt.want {
				t.Errorf("ExternalEmulatorBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
