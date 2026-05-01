package pubsubutil

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/labstack/echo/v4"
)

// PushHandlerMiddleware wraps a push-subscription HTTP handler to:
//  1. Re-establish the publisher's trace context from message attributes.
//  2. Re-establish the publisher's active learning language.
//
// Apply via group middleware or per-route on the Echo router that handles
// Pub/Sub push deliveries. The middleware reads the request body once to
// extract attributes and restores the body for the downstream handler.
func PushHandlerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			body, err := io.ReadAll(c.Request().Body)
			if err != nil {
				return next(c)
			}
			c.Request().Body = io.NopCloser(bytes.NewReader(body))

			var envelope struct {
				Message struct {
					Attributes map[string]string `json:"attributes"`
				} `json:"message"`
			}
			if json.Unmarshal(body, &envelope) == nil && len(envelope.Message.Attributes) > 0 {
				ctx := ConsumerContext(c.Request().Context(), envelope.Message.Attributes)
				ctx = WithLanguageFromAttributes(ctx, envelope.Message.Attributes)
				c.SetRequest(c.Request().WithContext(ctx))
			}
			return next(c)
		}
	}
}
