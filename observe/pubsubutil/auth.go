package pubsubutil

import (
	"context"
	"fmt"

	"google.golang.org/api/idtoken"
)

// VerifyPubSubJWT validates a Google-issued ID token (the kind Pub/Sub
// push subscriptions sign their requests with) for the supplied
// audience. Returns the validated claims map.
//
// All Kielo push-endpoint handlers used to roll their own copy of this
// function with subtly different ctx handling — some passed
// context.Background() to NewValidator, others used a startup-bounded
// timeout. The shared helper takes ctx so callers can pick a sensible
// timeout (the request ctx is the obvious choice for in-flight push
// handlers; a fresh background ctx for offline tools).
//
// The returned claims map is the validated payload's Claims field
// directly — Google's validator already verified the signature and
// audience, so callers can trust the claims as-is.
func VerifyPubSubJWT(ctx context.Context, tokenString, audience string) (map[string]any, error) {
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create ID token validator: %w", err)
	}

	payload, err := validator.Validate(ctx, tokenString, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to validate Google JWT: %w", err)
	}

	return payload.Claims, nil
}
