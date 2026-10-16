package pubsubutil

import (
	"context"
	"fmt"
	"os"
	"strings"

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

	if err := checkPushIdentity(payload.Claims, os.Getenv(PushServiceAccountsEnv)); err != nil {
		return nil, err
	}

	return payload.Claims, nil
}

// PushServiceAccountsEnv lists the service-account emails allowed to push to
// this service (comma-separated). Google signs an ID token for any caller
// that holds a service account, so signature plus audience alone admits a
// stranger who mints a token for this service's URL. When set, the token's
// verified email must be one of these. Unset keeps the audience-only check.
const PushServiceAccountsEnv = "PUBSUB_PUSH_SERVICE_ACCOUNTS"

func checkPushIdentity(claims map[string]any, allowedCSV string) error {
	var allowed []string
	for _, e := range strings.Split(allowedCSV, ",") {
		if e = strings.TrimSpace(e); e != "" {
			allowed = append(allowed, e)
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	email, _ := claims["email"].(string)
	if verified, _ := claims["email_verified"].(bool); !verified || email == "" {
		return fmt.Errorf("push token has no verified service account email")
	}
	for _, a := range allowed {
		if strings.EqualFold(a, email) {
			return nil
		}
	}
	return fmt.Errorf("push token service account %q is not allowed", email)
}
