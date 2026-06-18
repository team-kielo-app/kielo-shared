// Sweep ZZZZ: regression tests for the auth-code classifier +
// AuthCodedError envelope contract.
package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCodedError_ImplementsCodedHTTPError(t *testing.T) {
	// Compile-time assertion: AuthCodedError must satisfy the
	// CanonicalEchoErrorHandler's CodedHTTPError interface so the
	// canonical envelope lands `code` + `message` in their proper
	// slots instead of JSON-stringifying the struct into `message`.
	var _ CodedHTTPError = AuthCodedError{}
}

func TestClassifyJWTError_DistinctCodesPerFailureMode(t *testing.T) {
	cases := []struct {
		name        string
		jwtErr      error
		wantCode    string
		mustContain string
	}{
		{
			name:        "expired",
			jwtErr:      jwt.ErrTokenExpired,
			wantCode:    AuthCodeTokenExpired,
			mustContain: "expired",
		},
		{
			name:        "signature invalid",
			jwtErr:      jwt.ErrTokenSignatureInvalid,
			wantCode:    AuthCodeTokenSignatureInvalid,
			mustContain: "no longer valid",
		},
		{
			name:        "wrong issuer",
			jwtErr:      jwt.ErrTokenInvalidIssuer,
			wantCode:    AuthCodeTokenIssuerInvalid,
			mustContain: "environment",
		},
		{
			name:        "malformed",
			jwtErr:      jwt.ErrTokenMalformed,
			wantCode:    AuthCodeTokenMalformed,
			mustContain: "corrupted",
		},
		{
			name:        "missing claim",
			jwtErr:      jwt.ErrTokenRequiredClaimMissing,
			wantCode:    AuthCodeTokenClaimsInvalid,
			mustContain: "missing required information",
		},
		{
			name:        "not yet valid (nbf)",
			jwtErr:      jwt.ErrTokenNotValidYet,
			wantCode:    AuthCodeTokenClaimsInvalid,
			mustContain: "not yet valid",
		},
		{
			name:        "unknown jwt error → generic session-invalid",
			jwtErr:      errors.New("some weird jwt thing"),
			wantCode:    AuthCodeSessionInvalid,
			mustContain: "no longer valid",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code, message := classifyJWTError(tt.jwtErr)
			assert.Equal(t, tt.wantCode, code)
			assert.NotEmpty(t, message)
			assert.Contains(t, message, tt.mustContain,
				"message %q should contain %q for user-friendliness",
				message, tt.mustContain)
			// Sweep ZZZZ invariant: no Go internal text in user-facing message
			assert.NotContains(t, message, "Err")
			assert.NotContains(t, message, "jwt:")
			assert.NotContains(t, message, "<nil>")
		})
	}
}

func TestClassifyJWTError_JoinedErrorsResolveCorrectly(t *testing.T) {
	// The jwt library composes errors via errors.Join. Verify our
	// classifier walks the error chain.
	joined := errors.Join(jwt.ErrTokenExpired, errors.New("other context"))
	code, _ := classifyJWTError(joined)
	assert.Equal(t, AuthCodeTokenExpired, code,
		"joined errors should still classify by the jwt sentinel")
}

func TestJWTAuthWithOptions_EmitsTypedCodeOnMissingHeader(t *testing.T) {
	// End-to-end: JWTAuthWithOptions emits the canonical envelope with
	// AuthCodeTokenMissing on an authless request, NOT the default
	// UNAUTHORIZED code.
	e := echo.New()
	e.HTTPErrorHandler = CanonicalEchoErrorHandler
	mw := JWTAuthWithOptions("secret", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// no Authorization header
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := mw(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(c)
	e.HTTPErrorHandler(err, c)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, AuthCodeTokenMissing, body.Error.Code,
		"pre-ZZZZ this was the default UNAUTHORIZED code; post-ZZZZ it's the typed AUTH_TOKEN_MISSING")
	assert.NotEmpty(t, body.Error.Message)
	assert.NotContains(t, body.Error.Message, "Missing authorization header",
		"operator phrasing should not leak; should be user-friendly")
}

func TestJWTAuthWithOptions_EmitsTypedCodeOnBadBearerPrefix(t *testing.T) {
	// Pre-ZZZZ: bad bearer prefix returned 400 + BAD_REQUEST (status
	// drift per RFC 6750). Post-ZZZZ: 401 + AUTH_TOKEN_MALFORMED.
	e := echo.New()
	e.HTTPErrorHandler = CanonicalEchoErrorHandler
	mw := JWTAuthWithOptions("secret", nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // not Bearer
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := mw(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(c)
	e.HTTPErrorHandler(err, c)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"pre-ZZZZ was 400; per RFC 6750 should be 401")
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, AuthCodeTokenMalformed, body.Error.Code)
}

func TestRequireAdminRole_EmitsTypedCodes(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = CanonicalEchoErrorHandler

	t.Run("no claims → AUTH_AUTH_REQUIRED", func(t *testing.T) {
		mw := RequireAdminRole()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := mw(func(c echo.Context) error { return nil })(c)
		e.HTTPErrorHandler(err, c)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, AuthCodeAuthRequired, body.Error.Code)
	})

	t.Run("non-admin claims → AUTH_ADMIN_REQUIRED", func(t *testing.T) {
		mw := RequireAdminRole()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", &Claims{Role: "user"})
		err := mw(func(c echo.Context) error { return nil })(c)
		e.HTTPErrorHandler(err, c)

		require.Equal(t, http.StatusForbidden, rec.Code)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, AuthCodeAdminRequired, body.Error.Code)
	})

	t.Run("admin claims → pass through", func(t *testing.T) {
		mw := RequireAdminRole()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", &Claims{Role: "admin"})
		err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
