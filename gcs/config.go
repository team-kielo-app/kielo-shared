package gcs

import (
	"fmt"
	"os"
	"strings"
)

// isRunningInDocker checks if the process is running inside a Docker container
func isRunningInDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		return strings.Contains(string(data), "docker")
	}
	return false
}

// NormalizeEmulatorHost normalizes the emulator endpoint so the storage SDK can use it.
// Ensures a scheme exists, rewrites localhost to docker host when needed, strips the
// JSON API path suffix, and trims redundant trailing slashes.
func NormalizeEmulatorHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// When running inside docker we can't reach localhost of the host machine.
	if isRunningInDocker() {
		raw = strings.ReplaceAll(raw, "localhost", "gcs-emulator")
	}

	// Ensure the value includes a scheme for the storage client.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	raw = strings.TrimRight(raw, "/")
	raw = strings.TrimSuffix(raw, "/storage/v1")
	raw = strings.TrimSuffix(raw, "/storage")
	return raw
}

// Config holds GCS configuration for all services
type Config struct {
	ProjectID            string
	EmulatorHost         string
	SignedURLHost        string
	ServingBaseURL       string
	MediaUploadsBucket   string
	ProcessedMediaBucket string
	ConvoCacheBucket     string
	// Deprecated: ContentStorageBucket is no longer used. All media is stored in ProcessedMediaBucket.
	ContentStorageBucket string
	ManageBuckets        bool
}

// Bucket names - centralized constants
const (
	MediaUploadsBucketBase   = "kielo-media-uploads"
	ProcessedMediaBucketBase = "kielo-processed-media"
	ConvoCacheBucketBase     = "kielo-convo-cache"
	// Deprecated: ContentStorageBucketBase is no longer used. Bucket has been removed.
	ContentStorageBucketBase = "kielo-content-storage"
)

// LoadConfig creates a GCS config from environment variables
func LoadConfig() Config {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		projectID = "demo-project"
	}

	servingBaseURL := strings.TrimSpace(os.Getenv("CDN_SERVING_BASE_URL"))
	servingBaseURL = strings.TrimRight(servingBaseURL, "/")

	var emulatorHost, signedURLHost string

	// Use PORT_GCS_EMULATOR if set, otherwise fall back to legacy vars
	if portStr := os.Getenv("PORT_GCS_EMULATOR"); portStr != "" {
		// For internal container-to-container communication, use docker DNS
		internalHost := "gcs-emulator"
		if !isRunningInDocker() {
			internalHost = "localhost"
		}
		base := fmt.Sprintf("http://%s:%s", internalHost, portStr)
		emulatorHost = NormalizeEmulatorHost(base)

		// For external client access (mobile/browser), use HOST_IP
		externalHost := strings.TrimSpace(os.Getenv("HOST_IP"))
		if externalHost == "" {
			// Fallback: if HOST_IP not set, use localhost
			externalHost = "localhost"
		}
		signedURLHost = fmt.Sprintf("%s:%s", externalHost, portStr)

		// Allow explicit override even when PORT_GCS_EMULATOR is set
		if override := strings.TrimSpace(os.Getenv("GCS_SIGNED_URL_HOST")); override != "" {
			signedURLHost = override
		}
	} else {
		// Legacy support
		emulatorHost = os.Getenv("STORAGE_EMULATOR_HOST")
		if external := os.Getenv("HOST_IP"); external != "" {
			emulatorHost = fmt.Sprintf("http://%s:4443/storage/v1/", external)
		}
		emulatorHost = NormalizeEmulatorHost(emulatorHost)
		signedURLHost = os.Getenv("GCS_SIGNED_URL_HOST")
		if signedURLHost == "" && emulatorHost != "" {
			// Default to HOST_IP (or localhost) when using emulator without explicit override
			host := strings.TrimSpace(os.Getenv("HOST_IP"))
			if host == "" {
				host = "localhost"
			}
			signedURLHost = fmt.Sprintf("%s:%d", host, 4443)
		}
	}

	env := strings.ToLower(firstNonEmpty(os.Getenv("ENVIRONMENT"), os.Getenv("APP_ENV"), os.Getenv("ENV")))
	if env == "" {
		if os.Getenv("K_SERVICE") != "" {
			env = "production"
		} else {
			env = "development"
		}
	}

	manageBuckets := parseBoolEnv("GCS_MANAGE_BUCKETS")
	if manageBuckets == nil {
		if emulatorHost != "" {
			manageBuckets = boolPtr(true)
		} else if env == "production" || env == "prod" {
			manageBuckets = boolPtr(false)
		} else {
			manageBuckets = boolPtr(true)
		}
	}

	cfg := Config{
		ProjectID:            projectID,
		EmulatorHost:         emulatorHost,
		SignedURLHost:        signedURLHost,
		ServingBaseURL:       servingBaseURL,
		MediaUploadsBucket:   GetBucketName(MediaUploadsBucketBase, env, projectID),
		ProcessedMediaBucket: GetBucketName(ProcessedMediaBucketBase, env, projectID),
		ConvoCacheBucket:     GetBucketName(ConvoCacheBucketBase, env, projectID),
		ContentStorageBucket: GetBucketName(ContentStorageBucketBase, env, projectID),
		ManageBuckets:        *manageBuckets,
	}

	if override := strings.TrimSpace(os.Getenv("ORIGINAL_UPLOAD_GCS_BUCKET")); override != "" {
		cfg.MediaUploadsBucket = override
	}
	if override := strings.TrimSpace(os.Getenv("PROCESSED_GCS_BUCKET")); override != "" {
		cfg.ProcessedMediaBucket = override
	}
	if override := strings.TrimSpace(os.Getenv("CONVO_CACHE_GCS_BUCKET")); override != "" {
		cfg.ConvoCacheBucket = override
	}
	if override := strings.TrimSpace(os.Getenv("CONTENT_STORAGE_BUCKET")); override != "" {
		cfg.ContentStorageBucket = override
	}

	// Propagate normalized emulator host so callers using the default storage client honor the same endpoint.
	if cfg.EmulatorHost != "" {
		_ = os.Setenv("STORAGE_EMULATOR_HOST", cfg.EmulatorHost)
	}

	return cfg
}

// GetBucketName returns environment-appropriate bucket name
func GetBucketName(baseName, env, projectID string) string {
	if env == "production" || env == "prod" {
		return fmt.Sprintf("%s-%s", baseName, projectID)
	}
	return baseName
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func parseBoolEnv(key string) *bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	value = strings.ToLower(value)
	switch value {
	case "1", "true", "yes", "y", "on":
		return boolPtr(true)
	case "0", "false", "no", "n", "off":
		return boolPtr(false)
	default:
		return nil
	}
}

func boolPtr(value bool) *bool {
	return &value
}
