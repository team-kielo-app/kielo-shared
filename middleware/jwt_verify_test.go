package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func verifyStatus(t *testing.T, key *rsa.PublicKey, token string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	c := e.NewContext(req, httptest.NewRecorder())
	err := JWTAuthWithRSAPublicKey(key, nil)(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c)
	if err == nil {
		return http.StatusOK
	}
	if he, ok := err.(*echo.HTTPError); ok {
		return he.Code
	}
	t.Fatalf("unexpected error type %T: %v", err, err)
	return 0
}

func TestJWTVerifier_AudienceAlgorithmAndExpiry(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(method jwt.SigningMethod, key any, aud []string, exp bool, iss string) string {
		claims := &Claims{
			UserID: uuid.New(),
			Role:   "admin",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   iss,
				Audience: aud,
			},
		}
		if exp {
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		}
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodRS256, priv, []string{"kielo-access"}, true, "kielo.app")); got != http.StatusOK {
		t.Fatalf("access token: want 200, got %d", got)
	}
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodRS256, priv, nil, true, "kielo.app")); got != http.StatusOK {
		t.Fatalf("token without aud (legacy): want 200, got %d", got)
	}
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodRS256, priv, []string{RefreshTokenAudience}, true, "kielo.app")); got != http.StatusUnauthorized {
		t.Fatalf("refresh token used as bearer: want 401, got %d", got)
	}
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodRS256, priv, []string{"kielo-access"}, false, "kielo.app")); got != http.StatusUnauthorized {
		t.Fatalf("token without exp: want 401, got %d", got)
	}
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodRS256, priv, []string{"kielo-access"}, true, "evil")); got != http.StatusUnauthorized {
		t.Fatalf("wrong issuer: want 401, got %d", got)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodRS256, other, []string{"kielo-access"}, true, "kielo.app")); got != http.StatusUnauthorized {
		t.Fatalf("foreign key: want 401, got %d", got)
	}
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, []string{"kielo-access"}, true, "kielo.app")); got != http.StatusUnauthorized {
		t.Fatalf("alg=none: want 401, got %d", got)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if got := verifyStatus(t, &priv.PublicKey, mint(jwt.SigningMethodHS256, pubPEM, []string{"kielo-access"}, true, "kielo.app")); got != http.StatusUnauthorized {
		t.Fatalf("HS256 key confusion: want 401, got %d", got)
	}
}
