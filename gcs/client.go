package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// ClientInterface defines the interface for GCS operations
type ClientInterface interface {
	DownloadBlob(ctx context.Context, bucketName, objectName, destinationFile string) error
	DownloadToBytes(ctx context.Context, bucketName, objectName string) ([]byte, error)
	UploadBlob(ctx context.Context, sourceFile, bucketName, objectName, contentType string) error
	DeleteBlob(ctx context.Context, bucketName, objectName string) error
	CopyBlob(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string) error
	CopyPrefix(ctx context.Context, bucket, srcPrefix, dstPrefix string) error
	DeletePrefix(ctx context.Context, bucket, prefix string) error
	EnsureBucketExists(ctx context.Context, bucketName string) error
	EnsureAllBucketsExist(ctx context.Context) error
	GenerateSignedURL(ctx context.Context, bucketName, objectName string, opts *storage.SignedURLOptions) (string, error)
	Close() error
}

// Client wraps the GCS storage client with unified configuration
type Client struct {
	*storage.Client
	config         Config
	logger         *slog.Logger
	createdBuckets sync.Map // map[string]bool to cache bucket creation status
}

// NewClient creates a new GCS client with proper emulator support
func NewClient(ctx context.Context, cfg Config, logger *slog.Logger) (*Client, error) {
	l := configureLogger(logger)
	var client *storage.Client
	var err error

	if cfg.EmulatorHost != "" {
		client, err = storage.NewClient(ctx,
			storage.WithJSONReads(),
			option.WithoutAuthentication())
	} else {
		l.Info("Initializing GCS client with Application Default Credentials")
		client, err = storage.NewClient(ctx)
	}

	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}

	gcsClient := &Client{
		Client: client,
		config: cfg,
		logger: l,
	}

	l.Info("GCS client initialized successfully")
	return gcsClient, nil
}

// EnsureBucketExists creates a bucket if it doesn't exist
// Safe to call multiple times - ignores "already exists" errors
func (c *Client) EnsureBucketExists(ctx context.Context, bucketName string) error {
	bucketName = strings.TrimSpace(bucketName)
	if bucketName == "" {
		return fmt.Errorf("bucket name is empty")
	}
	c.logger.Info("Ensuring bucket exists", "bucket", bucketName)

	// Check cache first
	if _, exists := c.createdBuckets.Load(bucketName); exists {
		c.logger.Debug("Bucket already ensured", "bucket", bucketName)
		return nil
	}

	if !c.config.ManageBuckets {
		c.logger.Info("Bucket management disabled; verifying existence only", "bucket", bucketName)
		if err := c.verifyBucketExists(ctx, bucketName); err != nil {
			return err
		}
		c.createdBuckets.Store(bucketName, true)
		return nil
	}

	var err error
	if c.config.EmulatorHost != "" {
		// For emulator, try to create via HTTP API first (more reliable for fake-gcs-server)
		if err = c.createBucketViaHTTP(ctx, bucketName); err != nil {
			c.logger.Debug("HTTP bucket creation failed, trying Go client", "error", err)
			// Fall back to Go client
			err = c.createBucketViaClient(ctx, bucketName)
		}
	} else {
		// For production GCP
		err = c.createBucketViaClient(ctx, bucketName)
	}

	if err != nil {
		return err
	}

	// Cache successful creation
	c.createdBuckets.Store(bucketName, true)
	return nil
}

func configureLogger(base *slog.Logger) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}

	level := resolveLogLevel()
	handler := base.Handler()
	if handler == nil {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = &levelOverrideHandler{
			inner:    handler,
			minLevel: level,
		}
	}
	return slog.New(handler).With("component", "gcs_client")
}

func resolveLogLevel() slog.Level {
	if lvl := strings.TrimSpace(os.Getenv("GCS_LOG_LEVEL")); lvl != "" {
		if parsed, ok := parseLogLevel(lvl); ok {
			return parsed
		}
	}
	if lvl := strings.TrimSpace(os.Getenv("LOG_LEVEL")); lvl != "" {
		if parsed, ok := parseLogLevel(lvl); ok {
			return parsed
		}
	}
	return slog.LevelInfo
}

func parseLogLevel(value string) (slog.Level, bool) {
	switch strings.ToUpper(value) {
	case "DEBUG":
		return slog.LevelDebug, true
	case "INFO":
		return slog.LevelInfo, true
	case "WARN", "WARNING":
		return slog.LevelWarn, true
	case "ERROR":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

type levelOverrideHandler struct {
	inner    slog.Handler
	minLevel slog.Level
}

func (h *levelOverrideHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.minLevel
}

func (h *levelOverrideHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *levelOverrideHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelOverrideHandler{
		inner:    h.inner.WithAttrs(attrs),
		minLevel: h.minLevel,
	}
}

func (h *levelOverrideHandler) WithGroup(name string) slog.Handler {
	return &levelOverrideHandler{
		inner:    h.inner.WithGroup(name),
		minLevel: h.minLevel,
	}
}

// createBucketViaHTTP creates a bucket using the emulator's HTTP API
func (c *Client) createBucketViaHTTP(ctx context.Context, bucketName string) error {
	// This would require HTTP client implementation
	// For now, we'll use the Go client approach which works for both
	return c.createBucketViaClient(ctx, bucketName)
}

// createBucketViaClient creates a bucket using the Go storage client
func (c *Client) createBucketViaClient(ctx context.Context, bucketName string) error {
	projectID := c.config.ProjectID
	if projectID == "" {
		projectID = "demo-project" // Default for emulator
	}

	start := time.Now()
	err := c.Client.Bucket(bucketName).Create(ctx, projectID, nil)
	duration := time.Since(start)

	if err != nil {
		c.logger.Debug("Bucket creation failed", "bucket", bucketName, "duration", duration, "error", err)
		// Ignore context cancellation (assume bucket exists or operation was interrupted)
		if errors.Is(err, context.Canceled) {
			c.logger.Debug("Bucket creation canceled, assuming it exists or will be created", "bucket", bucketName)
			return nil
		}
		// Ignore common "already exists" errors
		if strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "You already own this bucket") ||
			strings.Contains(err.Error(), "Not Found") { // Some emulators return this
			c.logger.Debug("Bucket already exists or creation not needed", "bucket", bucketName)
			return nil
		}
		return fmt.Errorf("failed to create bucket %s: %w", bucketName, err)
	}

	c.logger.Info("Bucket created successfully", "bucket", bucketName, "duration", duration)
	return nil
}

func (c *Client) verifyBucketExists(ctx context.Context, bucketName string) error {
	_, err := c.Client.Bucket(bucketName).Attrs(ctx)
	if err == nil {
		c.logger.Debug("Bucket verified", "bucket", bucketName)
		return nil
	}
	if errors.Is(err, storage.ErrBucketNotExist) || strings.Contains(err.Error(), "Not Found") {
		return fmt.Errorf("bucket %s does not exist and bucket management is disabled", bucketName)
	}
	return fmt.Errorf("failed to verify bucket %s: %w", bucketName, err)
}

// EnsureAllBucketsExist ensures all configured buckets exist
func (c *Client) EnsureAllBucketsExist(ctx context.Context) error {
	buckets := []string{
		c.config.MediaUploadsBucket,
		c.config.ProcessedMediaBucket,
		c.config.ConvoCacheBucket,
	}

	c.logger.Info("Ensuring all GCS buckets exist", "bucket_count", len(buckets), "buckets", buckets)

	for _, bucket := range buckets {
		if err := c.EnsureBucketExists(ctx, bucket); err != nil {
			return fmt.Errorf("failed to ensure bucket %s exists: %w", bucket, err)
		}
	}

	c.logger.Info("All GCS buckets verified/created successfully", "bucket_count", len(buckets))
	return nil
}

// DownloadBlob downloads a blob from GCS to a local file
func (c *Client) DownloadBlob(ctx context.Context, bucketName, objectName, destinationFile string) error {
	l := c.logger.With("operation", "DownloadBlob", "bucket", bucketName, "object", objectName, "destination", destinationFile)
	l.Debug("Attempting to download blob")

	dlCtx, cancel := context.WithTimeout(ctx, time.Minute*3)
	defer cancel()

	rc, err := c.Client.Bucket(bucketName).Object(objectName).NewReader(dlCtx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			l.Error("GCS object not found for download", "error", err)
			return fmt.Errorf("GCS object not found: gs://%s/%s", bucketName, objectName)
		}
		l.Error("Failed to create GCS reader", "error", err)
		return fmt.Errorf("Object(%q).NewReader: %w", objectName, err)
	}
	defer rc.Close()

	destDir := filepath.Dir(destinationFile)
	if err := os.MkdirAll(destDir, 0750); err != nil {
		l.Error("Failed to create destination directory for download", "dir", destDir, "error", err)
		return fmt.Errorf("os.MkdirAll %s: %w", destDir, err)
	}

	f, err := os.Create(destinationFile)
	if err != nil {
		l.Error("Failed to create destination file", "error", err)
		return fmt.Errorf("os.Create %s: %w", destinationFile, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			l.Error("Failed to close destination file after download", "error", closeErr)
		}
		if err != nil {
			os.Remove(destinationFile)
		}
	}()

	if _, err = io.Copy(f, rc); err != nil {
		l.Error("Failed to copy GCS object to local file", "error", err)
		return fmt.Errorf("io.Copy from GCS to %s: %w", destinationFile, err)
	}
	l.Info("Blob downloaded successfully")
	return nil
}

// UploadBlob uploads a local file to GCS
func (c *Client) UploadBlob(ctx context.Context, sourceFile, bucketName, objectName, contentType string) error {
	l := c.logger.With("operation", "UploadBlob", "bucket", bucketName, "object", objectName, "source", sourceFile)
	l.Debug("Attempting to upload blob")

	ulCtx, cancel := context.WithTimeout(ctx, time.Minute*3)
	defer cancel()

	f, err := os.Open(sourceFile)
	if err != nil {
		l.Error("Failed to open source file for upload", "error", err)
		return fmt.Errorf("os.Open %s: %w", sourceFile, err)
	}
	defer f.Close()

	obj := c.Client.Bucket(bucketName).Object(objectName)
	wc := obj.NewWriter(ulCtx)
	if contentType != "" {
		wc.ContentType = contentType
	}
	wc.CacheControl = "public, max-age=31536000"

	if _, err = io.Copy(wc, f); err != nil {
		l.Error("Failed to copy source file to GCS writer", "error", err)
		_ = wc.CloseWithError(err) //nolint:staticcheck
		return fmt.Errorf("io.Copy to GCS writer for %s: %w", objectName, err)
	}

	if err := wc.Close(); err != nil {
		l.Error("Failed to close GCS writer after successful copy", "error", err)
		return fmt.Errorf("GCS Writer.Close for %s: %w", objectName, err)
	}
	l.Info("Blob uploaded successfully")
	return nil
}

// DownloadToBytes downloads a blob from GCS and returns its content as bytes
func (c *Client) DownloadToBytes(ctx context.Context, bucketName, objectName string) ([]byte, error) {
	l := c.logger.With("operation", "DownloadToBytes", "bucket", bucketName, "object", objectName)
	l.Debug("Attempting to download blob to bytes")

	dlCtx, cancel := context.WithTimeout(ctx, time.Minute*3)
	defer cancel()

	rc, err := c.Client.Bucket(bucketName).Object(objectName).NewReader(dlCtx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			l.Error("GCS object not found for download", "error", err)
			return nil, fmt.Errorf("GCS object not found: gs://%s/%s", bucketName, objectName)
		}
		l.Error("Failed to create GCS reader", "error", err)
		return nil, fmt.Errorf("Object(%q).NewReader: %w", objectName, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		l.Error("Failed to read GCS object to bytes", "error", err)
		return nil, fmt.Errorf("io.ReadAll from GCS: %w", err)
	}
	l.Info("Blob downloaded to bytes successfully")
	return data, nil
}

// DeleteBlob deletes a blob from GCS
func (c *Client) DeleteBlob(ctx context.Context, bucketName, objectName string) error {
	l := c.logger.With("operation", "DeleteBlob", "bucket", bucketName, "object", objectName)
	l.Debug("Attempting to delete blob")

	delCtx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	obj := c.Client.Bucket(bucketName).Object(objectName)
	if err := obj.Delete(delCtx); err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			l.Warn("Attempted to delete non-existent blob. Ignoring.")
			return nil
		}
		l.Error("Failed to delete GCS object", "error", err)
		return fmt.Errorf("Object(%q).Delete: %w", objectName, err)
	}
	l.Info("Blob deleted successfully")
	return nil
}

// CopyBlob copies an object within or across buckets using server-side copy (no download)
func (c *Client) CopyBlob(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string) error {
	l := c.logger.With("operation", "CopyBlob", "src_bucket", srcBucket, "src_object", srcObject, "dst_bucket", dstBucket, "dst_object", dstObject)
	l.Debug("Attempting to copy blob")

	copyCtx, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()

	src := c.Client.Bucket(srcBucket).Object(srcObject)
	dst := c.Client.Bucket(dstBucket).Object(dstObject)

	copier := dst.CopierFrom(src)
	copier.CacheControl = "public, max-age=31536000"

	_, err := copier.Run(copyCtx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			l.Error("Source object not found for copy", "error", err)
			return fmt.Errorf("source object not found: gs://%s/%s", srcBucket, srcObject)
		}
		l.Error("Failed to copy GCS object", "error", err)
		return fmt.Errorf("CopierFrom(%q).Run: %w", srcObject, err)
	}

	l.Info("Blob copied successfully")
	return nil
}

// CopyPrefix copies all objects with a given prefix to a new prefix within the same bucket
func (c *Client) CopyPrefix(ctx context.Context, bucket, srcPrefix, dstPrefix string) error {
	l := c.logger.With("operation", "CopyPrefix", "bucket", bucket, "src_prefix", srcPrefix, "dst_prefix", dstPrefix)
	l.Debug("Attempting to copy all objects with prefix")

	it := c.Client.Bucket(bucket).Objects(ctx, &storage.Query{Prefix: srcPrefix})
	copiedCount := 0

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			l.Error("Failed to iterate objects", "error", err)
			return fmt.Errorf("iterating objects with prefix %s: %w", srcPrefix, err)
		}

		newPath := strings.Replace(attrs.Name, srcPrefix, dstPrefix, 1)
		if err := c.CopyBlob(ctx, bucket, attrs.Name, bucket, newPath); err != nil {
			return fmt.Errorf("copying %s to %s: %w", attrs.Name, newPath, err)
		}
		copiedCount++
	}

	l.Info("Prefix copy completed", "copied_count", copiedCount)
	return nil
}

// DeletePrefix deletes all objects with a given prefix
func (c *Client) DeletePrefix(ctx context.Context, bucket, prefix string) error {
	l := c.logger.With("operation", "DeletePrefix", "bucket", bucket, "prefix", prefix)
	l.Debug("Attempting to delete all objects with prefix")

	it := c.Client.Bucket(bucket).Objects(ctx, &storage.Query{Prefix: prefix})
	deletedCount := 0

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			l.Error("Failed to iterate objects for deletion", "error", err)
			return fmt.Errorf("iterating objects with prefix %s: %w", prefix, err)
		}

		if err := c.DeleteBlob(ctx, bucket, attrs.Name); err != nil {
			l.Warn("Failed to delete object during prefix deletion", "object", attrs.Name, "error", err)
			// Continue deleting other objects
		} else {
			deletedCount++
		}
	}

	l.Info("Prefix deletion completed", "deleted_count", deletedCount)
	return nil
}

// GenerateSignedURL generates a signed URL for the given object
func (c *Client) GenerateSignedURL(ctx context.Context, bucketName, objectName string, opts *storage.SignedURLOptions) (string, error) {
	l := c.logger.With("operation", "GenerateSignedURL", "bucket", bucketName, "object", objectName)
	l.Debug("Generating signed URL")

	// For emulator, return direct URL without signing
	if c.config.EmulatorHost != "" {
		emulatorURL, err := c.generateEmulatorUploadURL(ctx, bucketName, objectName, opts)
		if err != nil {
			l.Error("Failed to generate emulator upload URL", "error", err)
			return "", err
		}
		l.Info("Generated emulator upload URL", "url", emulatorURL)
		return emulatorURL, nil
	}

	// Use bucket.SignedURL() which works with Workload Identity / IAM credentials
	// This is preferred over storage.SignedURL() in Cloud Run environments
	signedURL, err := c.Client.Bucket(bucketName).SignedURL(objectName, opts)
	if err != nil {
		l.Error("Failed to generate signed URL", "error", err)
		return "", fmt.Errorf("bucket.SignedURL: %w", err)
	}

	// If SignedURLHost is configured, replace the host in the signed URL
	if c.config.SignedURLHost != "" {
		signedURL, err = c.replaceURLHost(signedURL, c.config.SignedURLHost)
		if err != nil {
			l.Error("Failed to replace host in signed URL", "error", err)
			return "", fmt.Errorf("failed to replace host in signed URL: %w", err)
		}
	}

	l.Info("Signed URL generated successfully")
	return signedURL, nil
}

// replaceURLHost replaces the host in a URL with the given host
func (c *Client) replaceURLHost(urlStr, newHost string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	u.Host = newHost
	return u.String(), nil
}

// generateEmulatorUploadURL starts a resumable upload session on the emulator and returns its upload URL.
func (c *Client) generateEmulatorUploadURL(ctx context.Context, bucketName, objectName string, opts *storage.SignedURLOptions) (string, error) {
	baseURL := strings.TrimSuffix(c.config.EmulatorHost, "/")
	baseURL = strings.TrimSuffix(baseURL, "/storage/v1")
	baseURL = strings.TrimSuffix(baseURL, "/storage")
	if baseURL == "" {
		return "", fmt.Errorf("emulator host not configured")
	}

	uploadInitURL := fmt.Sprintf("%s/upload/storage/v1/b/%s/o?uploadType=resumable&name=%s", baseURL, bucketName, url.QueryEscape(objectName))
	payload, err := json.Marshal(map[string]string{"name": objectName})
	if err != nil {
		return "", fmt.Errorf("failed to marshal emulator upload payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadInitURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create emulator upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if opts != nil && opts.ContentType != "" {
		req.Header.Set("X-Upload-Content-Type", opts.ContentType)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to initialize emulator upload session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("emulator upload init failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("emulator upload init response missing Location header")
	}

	// Rewrite host for accessibility from the host/mobile network.
	location, err = c.rewriteUploadLocation(location)
	if err != nil {
		return "", fmt.Errorf("failed to rewrite emulator upload URL: %w", err)
	}

	return location, nil
}

// rewriteUploadLocation rewrites the host in the emulator upload URL using (in order):
// 1) Explicit GCS_SIGNED_URL_HOST (config.SignedURLHost)
// 2) HOST_IP env, keeping the port from the emulator URL
func (c *Client) rewriteUploadLocation(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}

	targetHost := strings.TrimSpace(c.config.SignedURLHost)

	if targetHost == "" {
		if host := strings.TrimSpace(os.Getenv("HOST_IP")); host != "" {
			port := u.Port()
			if port == "" {
				port = "80"
			}
			targetHost = net.JoinHostPort(host, port)

		}
	}

	if targetHost != "" {

		u.Host = targetHost
	}

	return u.String(), nil
}

// Close closes the underlying storage client
func (c *Client) Close() error {
	if c.Client != nil {
		c.logger.Info("Closing GCS client")
		return c.Client.Close()
	}
	return nil
}

// ParseGCSURI parses a GCS URI (gs://bucket/path) and returns bucket and path
func ParseGCSURI(uri string) (bucket, path string, err error) {
	if !strings.HasPrefix(uri, "gs://") {
		return "", "", fmt.Errorf("invalid GCS URI format: %s", uri)
	}
	parts := strings.SplitN(strings.TrimPrefix(uri, "gs://"), "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid GCS URI format, missing path: %s", uri)
	}
	return parts[0], parts[1], nil
}
