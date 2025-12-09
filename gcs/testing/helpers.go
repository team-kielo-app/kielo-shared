package testing

import (
	"context"
	"log/slog"

	"github.com/khnhle/kielo-shared/gcs"
)

// SetupTestBuckets ensures all required GCS buckets exist for testing
func SetupTestBuckets(ctx context.Context, client *gcs.Client) error {
	return client.EnsureAllBucketsExist(ctx)
}

// NewTestClient creates a GCS client configured for testing
func NewTestClient(ctx context.Context) (*gcs.Client, error) {
	cfg := gcs.LoadConfig()
	logger := slog.Default().With("test", "gcs")

	client, err := gcs.NewClient(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	// Ensure buckets exist for tests
	if err := SetupTestBuckets(ctx, client); err != nil {
		client.Close()
		return nil, err
	}

	return client, nil
}
