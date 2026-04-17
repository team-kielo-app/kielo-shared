package gcs

import (
	"net"
	"net/url"
	"os"
	"strings"
)

// ParseEmulatorPort extracts the port from a STORAGE_EMULATOR_HOST value.
// Handles: "host:port", "http://host:port", "http://host:port/path".
// Returns "4443" as default if not parseable.
func ParseEmulatorPort() string {
	raw := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST"))
	if raw == "" {
		return "4443"
	}
	// Try parsing as URL first
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Port() != "" {
			return u.Port()
		}
	}
	// Try host:port
	if _, port, err := net.SplitHostPort(raw); err == nil && port != "" {
		return port
	}
	return "4443"
}

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
	if strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST")) == "" {
		return ""
	}
	port := ParseEmulatorPort()
	hostIP := strings.TrimSpace(os.Getenv("HOST_IP"))
	if hostIP != "" {
		return "http://" + net.JoinHostPort(hostIP, port)
	}
	return "http://localhost:" + port
}

// InternalEmulatorBaseURL returns the GCS emulator base URL suitable for internal Docker service-to-service calls.
// Returns empty string if no emulator is configured.
func InternalEmulatorBaseURL() string {
	raw := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST"))
	if raw == "" {
		return ""
	}
	normalized := NormalizeEmulatorHost(raw)
	if normalized == "" {
		return ""
	}
	return normalized
}

// ContextualizeStorageURL rewrites a GCS storage URL based on the request context.
// For loopback requests (localhost/127.x): rewrites to external emulator URL (using HOST_IP).
// For internal Docker requests (single-word hostname): rewrites to internal emulator URL (gcs-emulator:port).
// For any other caller (LAN IP, FQDN) in emulator mode: rewrites to external emulator URL. In
// production (no emulator configured) ExternalEmulatorBaseURL returns empty and the URL is
// returned unchanged, so real GCS URLs like storage.googleapis.com are never touched.
// For non-storage URLs: returns the URL unchanged.
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
	if !IsStorageAPIPath(parsed.Path) {
		return trimmed
	}

	hostname := strings.TrimSpace(strings.ToLower(requestHostname))
	if hostname == "" {
		return trimmed
	}

	// Strip :port so downstream classification works for "host:port" inputs.
	if h, _, splitErr := net.SplitHostPort(hostname); splitErr == nil {
		hostname = h
	}

	var targetBase string
	switch {
	case IsLoopbackHostname(hostname):
		targetBase = ExternalEmulatorBaseURL()
	case !strings.Contains(hostname, "."):
		// Single-label hostname ⇒ internal Docker service
		targetBase = InternalEmulatorBaseURL()
	default:
		// LAN IP or FQDN. In emulator mode this is an external dev caller
		// that needs the HOST_IP-based URL; in production ExternalEmulatorBaseURL
		// returns empty, so real GCS URLs pass through untouched.
		targetBase = ExternalEmulatorBaseURL()
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

// ContextualizeServiceURL rewrites any internal Docker service URL for external access.
// It handles both GCS storage URLs and arbitrary service URLs (e.g., kielo-ktv-api:8080).
// For GCS URLs it delegates to ContextualizeStorageURL.
// For other internal Docker hostnames (no dots in hostname), it rewrites to HOST_IP
// when the caller is external (loopback, LAN IP, or FQDN). Internal Docker callers
// get the URL unchanged so service-to-service traffic stays on the Docker network.
// Pass the requesting client's Host header to determine rewrite direction.
func ContextualizeServiceURL(requestHostname, rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed == nil || parsed.Host == "" {
		return trimmed
	}

	// GCS storage URLs — delegate to the specialized handler
	if IsStorageAPIPath(parsed.Path) {
		return ContextualizeStorageURL(requestHostname, rawURL)
	}

	// Internal Docker hostnames have no dots (e.g., "kielo-ktv-api", "gcs-emulator").
	// Only those are candidates for rewriting — FQDN/IP URLs are left alone.
	hostname := parsed.Hostname()
	if hostname == "" || strings.Contains(hostname, ".") {
		return trimmed
	}

	// Classify the caller. Strip :port first so "localhost:8080" works.
	reqHost := strings.TrimSpace(strings.ToLower(requestHostname))
	if reqHost == "" {
		return trimmed
	}
	if h, _, splitErr := net.SplitHostPort(reqHost); splitErr == nil {
		reqHost = h
	}

	// Another internal Docker service is calling us — keep the internal hostname
	// so service-to-service traffic stays on the Docker network.
	if !IsLoopbackHostname(reqHost) && !strings.Contains(reqHost, ".") {
		return trimmed
	}

	// External caller (loopback, LAN IP, or FQDN). Rewrite to HOST_IP (or localhost).
	// We preserve the original port: Docker services are expected to expose
	// matching host ports (e.g. "8080:8080"), not gratuitously-renumbered ones.
	hostIP := strings.TrimSpace(os.Getenv("HOST_IP"))
	if hostIP == "" {
		hostIP = "localhost"
	}
	parsed.Host = net.JoinHostPort(hostIP, parsed.Port())
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

	if !IsStorageAPIPath(parsed.Path) {
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

	// Don't rewrite loopback URLs when the configured emulator is also loopback.
	// STORAGE_EMULATOR_HOST=localhost:4443 means no Docker networking — loopback
	// URLs (127.0.0.1, localhost) should stay as-is.
	rawEmulator := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST"))
	if rawEmulator != "" {
		rawHost := rawEmulator
		if strings.Contains(rawHost, "://") {
			if u, err := url.Parse(rawHost); err == nil {
				rawHost = u.Hostname()
			}
		} else if h, _, err := net.SplitHostPort(rawHost); err == nil {
			rawHost = h
		}
		if IsLoopbackHostname(rawHost) && IsLoopbackHostname(currentHost) {
			return trimmed
		}
	}

	parsedInternal, err := url.Parse(internalBase)
	if err != nil || parsedInternal == nil {
		return trimmed
	}
	parsed.Scheme = parsedInternal.Scheme
	parsed.Host = parsedInternal.Host
	return parsed.String()
}
