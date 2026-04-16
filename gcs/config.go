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
	LocalizationBucket   string
	WhisperModelsBucket  string
	PublicAssetsBucket   string
	SocialMediaBucket    string
}

// Bucket names - centralized constants
const (
	MediaUploadsBucketBase   = "kielo-media-uploads"
	ProcessedMediaBucketBase = "kielo-media-processor"
	ConvoCacheBucketBase     = "kielo-convo-cache"
	LocalizationBucketBase   = "kielo-localization"
	WhisperModelsBucketBase  = "kielo-whisper-models"
	PublicAssetsBucketBase   = "kielo-public-assets"
	SocialMediaBucketBase    = "kielo-social-media"
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

	// Emulator configuration: single path via STORAGE_EMULATOR_HOST
	if raw := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST")); raw != "" {
		emulatorHost = NormalizeEmulatorHost(raw)

		// Derive signed URL host for external access (browser/mobile)
		port := ParseEmulatorPort()
		externalHost := strings.TrimSpace(os.Getenv("HOST_IP"))
		if externalHost == "" {
			externalHost = "localhost"
		}
		signedURLHost = fmt.Sprintf("%s:%s", externalHost, port)
	}

	env := strings.ToLower(firstNonEmpty(os.Getenv("ENVIRONMENT"), os.Getenv("APP_ENV"), os.Getenv("ENV")))
	if env == "" {
		if os.Getenv("K_SERVICE") != "" {
			env = "production"
		} else {
			env = "development"
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
		LocalizationBucket:   GetBucketName(LocalizationBucketBase, env, projectID),
		WhisperModelsBucket:  GetBucketName(WhisperModelsBucketBase, env, projectID),
		PublicAssetsBucket:   GetBucketName(PublicAssetsBucketBase, env, projectID),
		SocialMediaBucket:    SocialMediaBucketBase,
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
	if override := strings.TrimSpace(os.Getenv("LOCALIZATION_BUCKET")); override != "" {
		cfg.LocalizationBucket = override
	}
	if override := strings.TrimSpace(os.Getenv("WHISPER_MODELS_BUCKET")); override != "" {
		cfg.WhisperModelsBucket = override
	}
	if override := strings.TrimSpace(os.Getenv("PUBLIC_ASSETS_BUCKET")); override != "" {
		cfg.PublicAssetsBucket = override
	}
	if override := strings.TrimSpace(firstNonEmpty(os.Getenv("SOCIAL_MEDIA_BUCKET"), os.Getenv("KTV_SOCIAL_MEDIA_BUCKET"))); override != "" {
		cfg.SocialMediaBucket = override
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
