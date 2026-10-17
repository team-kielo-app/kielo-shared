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

	"github.com/team-kielo-app/kielo-shared/jwtkeys"
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

func TestJWTVerifier_NextKeyRotation(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&b.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nextPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	mint := func(key *rsa.PrivateKey, kid string, aud []string, exp bool) string {
		claims := &Claims{
			UserID:           uuid.New(),
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "kielo.app", Audience: aud},
		}
		if exp {
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if kid != "" {
			tok.Header["kid"] = kid
		}
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	access := []string{"kielo-access"}

	t.Setenv("JWT_PUBLIC_KEY_PEM_NEXT", "")
	if got := verifyStatus(t, &a.PublicKey, mint(b, "", access, true)); got != http.StatusUnauthorized {
		t.Fatalf("NEXT unset: token from B must be refused, got %d", got)
	}

	t.Setenv("JWT_PUBLIC_KEY_PEM_NEXT", nextPEM)
	for name, tok := range map[string]string{
		"A no kid": mint(a, "", access, true),
		"B no kid": mint(b, "", access, true),
		"B kid":    mint(b, jwtkeys.Fingerprint(&b.PublicKey), access, true),
		"A kid":    mint(a, jwtkeys.Fingerprint(&a.PublicKey), access, true),
	} {
		if got := verifyStatus(t, &a.PublicKey, tok); got != http.StatusOK {
			t.Errorf("%s: want 200, got %d", name, got)
		}
	}
	if got := verifyStatus(t, &a.PublicKey, mint(c, "", access, true)); got != http.StatusUnauthorized {
		t.Errorf("token from C: want 401, got %d", got)
	}
	if got := verifyStatus(t, &a.PublicKey, mint(b, "", []string{"kielo-refresh"}, true)); got != http.StatusUnauthorized {
		t.Errorf("refresh audience signed by NEXT: want 401, got %d", got)
	}
	if got := verifyStatus(t, &a.PublicKey, mint(b, "", access, false)); got != http.StatusUnauthorized {
		t.Errorf("no exp signed by NEXT: want 401, got %d", got)
	}
}

func pubPEM(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func mintRSA(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		UserID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "kielo.app",
			Audience:  []string{"kielo-access"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func serve(t *testing.T, mw echo.MiddlewareFunc, token string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	c := e.NewContext(req, httptest.NewRecorder())
	err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c)
	if err == nil {
		return http.StatusOK
	}
	if he, ok := err.(*echo.HTTPError); ok {
		return he.Code
	}
	t.Fatalf("unexpected error type %T: %v", err, err)
	return 0
}

func TestFlexibleAuth_BuildsKeySetOncePerMiddleware(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_PUBLIC_KEY_PEM_NEXT", "")
	before := keySetBuilds.Load()
	mw := FlexibleAuthSimpleRSA(pubPEM(t, &a.PublicKey))
	token := mintRSA(t, a)
	for i := 0; i < 5; i++ {
		if got := serve(t, mw, token); got != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, got)
		}
	}
	if builds := keySetBuilds.Load() - before; builds != 1 {
		t.Fatalf("key set built %d times for 5 requests, want 1", builds)
	}
}

func TestJWTAuth_MalformedNextFailsAtConstruction(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_PUBLIC_KEY_PEM_NEXT", "not a pem")
	opts := &JWTOptions{PublicKey: &a.PublicKey}

	if _, err := JWTAuthWithOptionsE("", nil, opts); err == nil {
		t.Fatal("JWTAuthWithOptionsE: want an error for a malformed NEXT")
	}
	if _, err := FlexibleAuthWithOptionsE("", nil, opts); err == nil {
		t.Fatal("FlexibleAuthWithOptionsE: want an error for a malformed NEXT")
	}
	for name, build := range map[string]func(){
		"JWTAuthWithOptions":      func() { JWTAuthWithOptions("", nil, opts) },
		"FlexibleAuthWithOptions": func() { FlexibleAuthWithOptions("", nil, opts) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: want a panic at construction for a malformed NEXT", name)
				}
			}()
			build()
		}()
	}

	t.Setenv("JWT_PUBLIC_KEY_PEM_NEXT", "")
	if _, err := JWTAuthWithOptionsE("", nil, opts); err != nil {
		t.Fatalf("unset NEXT: want no error, got %v", err)
	}
}

func TestJWTAuth_BadConfiguredPEMNeverFallsBackToHMAC(t *testing.T) {
	t.Setenv("JWT_PUBLIC_KEY_PEM_NEXT", "")
	secret := "hmac-secret"
	hmacTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "kielo.app",
			Audience:  []string{"kielo-access"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	opts := &JWTOptions{PublicKeyPEM: "garbage"}
	if _, err := JWTAuthWithOptionsE(secret, nil, opts); err == nil {
		t.Fatal("a configured PEM that fails to parse must be an error")
	}
	if got := serve(t, JWTAuthWithOptions(secret, nil, opts), hmacTok); got != http.StatusUnauthorized {
		t.Fatalf("bad PEM with an HMAC secret: want 401, got %d", got)
	}
	if got := serve(t, JWTAuthWithOptions(secret, nil, nil), hmacTok); got != http.StatusOK {
		t.Fatalf("no RSA configured: HMAC must still verify, got %d", got)
	}
}
