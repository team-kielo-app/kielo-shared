package testing

import (
	"context"
	"log/slog"

	"github.com/team-kielo-app/kielo-shared/gcs"
)

// NewTestClient creates a GCS client configured for testing
func NewTestClient(ctx context.Context) (*gcs.Client, error) {
	cfg := gcs.LoadConfig()
	logger := slog.Default().With("test", "gcs")
	return gcs.NewClient(ctx, cfg, logger)
}
