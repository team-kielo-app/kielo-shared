package gcs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A copy keeps the source's content headers. Setting CacheControl on the
// copier replaced the whole destination metadata, so 2026-10-08's support
// attachment move (and earlier KTV relocations) produced objects served as
// application/octet-stream. Needs the GCS emulator (STORAGE_EMULATOR_HOST).
func TestCopyBlobKeepsContentHeaders(t *testing.T) {
	host := os.Getenv("STORAGE_EMULATOR_HOST")
	if host == "" {
		t.Skip("STORAGE_EMULATOR_HOST not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := NewClient(ctx, Config{ProjectID: "test", EmulatorHost: host}, nil)
	require.NoError(t, err)
	bucket := "copy-headers-" + time.Now().Format("150405.000000")
	require.NoError(t, c.Client.Bucket(bucket).Create(ctx, "test", nil))

	w := c.Client.Bucket(bucket).Object("src/main.webp").NewWriter(ctx)
	w.ContentType = "image/webp"
	w.Metadata = map[string]string{"media_id": "m1"}
	_, err = w.Write([]byte("RIFF....WEBP"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	require.NoError(t, c.CopyBlob(ctx, bucket, "src/main.webp", bucket, "dst/main.webp"))

	attrs, err := c.Client.Bucket(bucket).Object("dst/main.webp").Attrs(ctx)
	require.NoError(t, err)
	require.Equal(t, "image/webp", attrs.ContentType)
	require.Equal(t, "m1", attrs.Metadata["media_id"])
	require.Equal(t, "public, max-age=31536000", attrs.CacheControl)
}
