// Package jwtkeys holds the set of RSA public keys a verifier accepts, so the
// signing key can rotate without a window where live tokens stop verifying.
package jwtkeys

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/team-kielo-app/kielo-shared/cryptoutil"
)

// NextEnv names the optional second verification key. While it is unset a
// verifier behaves exactly as it does with the single JWT_PUBLIC_KEY_PEM.
const NextEnv = "JWT_PUBLIC_KEY_PEM_NEXT"

const fingerprintLen = 16

// Fingerprint is the kid auth-service stamps on tokens: the first 16 hex
// characters of the SHA-256 of the key's PKIX DER encoding.
func Fingerprint(key *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:fingerprintLen]
}

// KeySet verifies a token against every key it holds.
type KeySet struct {
	keys []*rsa.PublicKey
	kids []string
}

// New builds a set from the non-nil keys, in order.
func New(keys ...*rsa.PublicKey) *KeySet {
	set := &KeySet{}
	for _, key := range keys {
		if key == nil {
			continue
		}
		set.keys = append(set.keys, key)
		set.kids = append(set.kids, Fingerprint(key))
	}
	return set
}

// WithNextFromEnv returns a set of primary plus the key in JWT_PUBLIC_KEY_PEM_NEXT.
// An unset variable yields exactly the primary key; an unparsable one is
// logged and ignored so a bad rotation secret cannot take a service down.
func WithNextFromEnv(primary *rsa.PublicKey) *KeySet {
	return New(primary, NextFromEnv())
}

// NextFromEnv parses JWT_PUBLIC_KEY_PEM_NEXT, or returns nil.
func NextFromEnv() *rsa.PublicKey {
	raw := strings.TrimSpace(os.Getenv(NextEnv))
	if raw == "" {
		return nil
	}
	key, err := cryptoutil.ParseRSAPublicKey(raw)
	if err != nil {
		log.Printf("WARN: %s is set but is not a usable RSA public key; ignoring it: %v", NextEnv, err)
		return nil
	}
	return key
}

// FromPEM parses primaryPEM and adds the env NEXT key. The error is the
// primary key's.
func FromPEM(primaryPEM string) (*KeySet, error) {
	primary, err := jwt.ParseRSAPublicKeyFromPEM([]byte(primaryPEM))
	if err != nil {
		return nil, err
	}
	return WithNextFromEnv(primary), nil
}

// Len is the number of keys in the set.
func (s *KeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.keys)
}

// KeyFunc is a jwt.Keyfunc. A kid naming one of the keys selects it; a missing
// or unknown kid (legacy tokens) offers every key, and the token verifies if
// any of them does.
func (s *KeySet) KeyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v, expected RSA", token.Header["alg"])
	}
	if s.Len() == 0 {
		return nil, errors.New("no JWT public key is configured")
	}
	if kid, _ := token.Header["kid"].(string); kid != "" {
		for i, k := range s.kids {
			if k == kid {
				return s.keys[i], nil
			}
		}
	}
	if len(s.keys) == 1 {
		return s.keys[0], nil
	}
	all := jwt.VerificationKeySet{Keys: make([]jwt.VerificationKey, 0, len(s.keys))}
	for _, key := range s.keys {
		all.Keys = append(all.Keys, key)
	}
	return all, nil
}
