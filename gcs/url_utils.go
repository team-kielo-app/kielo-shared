package gcs

import (
	"net"
	"net/url"
	"os"
	"strings"
)

// IsLoopbackHostname returns true if the hostname is a loopback address (localhost, 127.x, ::1).
func IsLoopbackHostname(hostname string) bool {
	h := strings.TrimSpace(strings.ToLower(hostname))
	if h == "localhost" || h == "::1" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ExternalEmulatorBaseURL returns the GCS emulator base URL suitable for external/browser access.
// It uses HOST_IP if set, otherwise falls back to localhost.
// Returns empty string if no emulator is configured.
func ExternalEmulatorBaseURL() string {
	port := strings.TrimSpace(os.Getenv("PORT_GCS_EMULATOR"))
	if port == "" {
		port = "4443"
	}

	// Check if emulator is configured
	if os.Getenv("STORAGE_EMULATOR_HOST") == "" && os.Getenv("PORT_GCS_EMULATOR") == "" {
		return ""
	}

	hostIP := strings.TrimSpace(os.Getenv("HOST_IP"))
	if hostIP != "" {
		return "http://" + net.JoinHostPort(hostIP, port)
	}
	return "http://localhost:" + port
}

// InternalEmulatorBaseURL returns the GCS emulator base URL suitable for internal Docker service-to-service calls.
// Returns empty string if no emulator is configured.
func InternalEmulatorBaseURL() string {
	if emu := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST")); emu != "" {
		if !strings.HasPrefix(emu, "http://") && !strings.HasPrefix(emu, "https://") {
			emu = "http://" + emu
		}
		return strings.TrimRight(emu, "/")
	}

	port := strings.TrimSpace(os.Getenv("PORT_GCS_EMULATOR"))
	if port == "" {
		return ""
	}
	return "http://gcs-emulator:" + port
}

// ContextualizeStorageURL rewrites a GCS storage URL based on the request context.
// For loopback requests (localhost/127.x): rewrites to external emulator URL (using HOST_IP).
// For internal Docker requests: rewrites to internal emulator URL (gcs-emulator:port).
// For non-storage URLs or production: returns the URL unchanged.
func ContextualizeStorageURL(requestHostname, rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed == nil {
		return trimmed
	}

	// Only rewrite GCS storage API paths
	if !strings.HasPrefix(parsed.Path, "/storage/v1/") && !strings.HasPrefix(parsed.Path, "/upload/storage/v1/") {
		return trimmed
	}

	hostname := strings.TrimSpace(strings.ToLower(requestHostname))
	if hostname == "" {
		return trimmed
	}

	var targetBase string
	if IsLoopbackHostname(hostname) {
		targetBase = ExternalEmulatorBaseURL()
	} else if !strings.Contains(hostname, ".") {
		// Internal Docker hostname (no dots)
		targetBase = InternalEmulatorBaseURL()
	}

	if targetBase == "" {
		return trimmed
	}

	parsedTarget, err := url.Parse(targetBase)
	if err != nil || parsedTarget == nil || strings.TrimSpace(parsedTarget.Host) == "" {
		return trimmed
	}

	parsed.Scheme = parsedTarget.Scheme
	parsed.Host = parsedTarget.Host
	return parsed.String()
}

// NormalizeInternalStorageURL rewrites an external GCS emulator URL to use the internal Docker hostname.
// Useful when CMS receives URLs with HOST_IP but needs to fetch from inside Docker.
func NormalizeInternalStorageURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed == nil {
		return trimmed
	}

	if !strings.HasPrefix(parsed.Path, "/storage/v1/") && !strings.HasPrefix(parsed.Path, "/upload/storage/v1/") {
		return trimmed
	}

	internalBase := InternalEmulatorBaseURL()
	if internalBase == "" {
		return trimmed
	}

	// Don't rewrite if already pointing to the internal Docker hostname
	currentHost := strings.ToLower(parsed.Hostname())
	if currentHost == "gcs-emulator" {
		return trimmed
	}

	// Don't rewrite if the internal base itself is loopback (no Docker networking)
	parsedInternal, err := url.Parse(internalBase)
	if err != nil || parsedInternal == nil {
		return trimmed
	}
	if IsLoopbackHostname(parsedInternal.Hostname()) {
		return trimmed
	}

	parsed.Scheme = parsedInternal.Scheme
	parsed.Host = parsedInternal.Host
	return parsed.String()
}
