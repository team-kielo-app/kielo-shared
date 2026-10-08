package media

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Cloud CDN signed requests are defined as HMAC-SHA1.
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CDNSigner signs Cloud CDN requests with a signed request key (the key
// attached to the CDN backend bucket). Signing is local HMAC — no network —
// so a list of signed URLs costs microseconds.
//
// Format (https://cloud.google.com/cdn/docs/using-signed-urls):
//
//	URL:        <url>?Expires=<unix>&KeyName=<name>&Signature=<b64url(hmac-sha1(key, "<url>?Expires=…&KeyName=…"))>
//	URL prefix: <url>?URLPrefix=<b64url(prefix)>&Expires=<unix>&KeyName=<name>&Signature=<b64url(hmac(…))>
//
// Cloud CDN only checks a signature that is present; enforcement comes from
// the origin being private (the CDN fills a signed request with its own
// service account, an unsigned one anonymously).
type CDNSigner struct {
	keyName string
	key     []byte
}

// ErrCDNSignature is returned by Verify for a missing, malformed, expired or
// wrong signature.
var ErrCDNSignature = errors.New("cdn signature invalid")

// NewCDNSigner builds a signer from the key name and the base64url key value
// (as Terraform's random_id.b64_url and `gcloud compute sign-url` take it).
// Padding is optional.
func NewCDNSigner(keyName, keyB64 string) (*CDNSigner, error) {
	keyName = strings.TrimSpace(keyName)
	keyB64 = strings.TrimRight(strings.TrimSpace(keyB64), "=")
	if keyName == "" || keyB64 == "" {
		return nil, errors.New("cdn signer: key name and key are required")
	}
	key, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("cdn signer: key is not base64url: %w", err)
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("cdn signer: key must be 16 bytes, got %d", len(key))
	}
	return &CDNSigner{keyName: keyName, key: key}, nil
}

// KeyName is the signed request key's name.
func (s *CDNSigner) KeyName() string { return s.keyName }

// SignURL returns rawURL signed until expires.
func (s *CDNSigner) SignURL(rawURL string, expires time.Time) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	toSign := fmt.Sprintf("%s%sExpires=%d&KeyName=%s", rawURL, sep, expires.Unix(), s.keyName)
	return toSign + "&Signature=" + s.sign(toSign)
}

// SignURLPrefix returns the query string that authorizes every URL starting
// with prefix until expires (append it to each URL under the prefix). Used
// for streaming manifests whose segments live under one directory.
func (s *CDNSigner) SignURLPrefix(prefix string, expires time.Time) string {
	toSign := fmt.Sprintf("URLPrefix=%s&Expires=%d&KeyName=%s",
		base64.URLEncoding.EncodeToString([]byte(prefix)), expires.Unix(), s.keyName)
	return toSign + "&Signature=" + s.sign(toSign)
}

// Verify checks a signed URL the way Cloud CDN does. canonicalURL is the URL
// the CDN sees for the request (its own scheme and host plus the request's
// path and query), so a URL reached through another host still verifies.
func (s *CDNSigner) Verify(canonicalURL string, now time.Time) error {
	base, query, ok := strings.Cut(canonicalURL, "?")
	if !ok {
		return ErrCDNSignature
	}
	sigAt := strings.LastIndex(query, "&Signature=")
	if sigAt < 0 {
		return ErrCDNSignature
	}
	signed, sig := query[:sigAt], query[sigAt+len("&Signature="):]
	values, err := url.ParseQuery(signed)
	if err != nil || values.Get("KeyName") != s.keyName {
		return ErrCDNSignature
	}
	expires, err := strconv.ParseInt(values.Get("Expires"), 10, 64)
	if err != nil || now.Unix() > expires {
		return ErrCDNSignature
	}
	var toSign string
	if prefix := values.Get("URLPrefix"); prefix != "" {
		decoded, err := base64.URLEncoding.DecodeString(prefix)
		if err != nil || !strings.HasPrefix(base, string(decoded)) {
			return ErrCDNSignature
		}
		at := strings.Index(signed, "URLPrefix=")
		if at < 0 {
			return ErrCDNSignature
		}
		toSign = signed[at:]
	} else {
		toSign = base + "?" + signed
	}
	if !hmac.Equal([]byte(sig), []byte(s.sign(toSign))) {
		return ErrCDNSignature
	}
	return nil
}

func (s *CDNSigner) sign(input string) string {
	mac := hmac.New(sha1.New, s.key)
	mac.Write([]byte(input))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}
