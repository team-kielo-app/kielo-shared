// Package cryptoutil provides shared cryptographic helpers for Kielo
// services — currently RSA PEM parsing used by every service that
// validates platform-issued JWTs (auth-service for sign/verify,
// user-service / content-service for verify-only).
package cryptoutil

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ParseRSAPublicKey parses an RSA public key from a PEM-encoded string.
// Tries PKIX (the modern default emitted by openssl genpkey + openssl rsa
// -pubout) first, then falls back to PKCS#1. Also accepts PEM strings
// where literal "\\n" sequences stand in for real newlines — the form
// produced by .env files and Cloud Run secret-as-env-var injection.
//
// dupl: shape parallels ParseRSAPrivateKey but parses different PEM types
// (PKIX/PKCS1 vs PKCS8/PKCS1) with different x509 funcs and return types;
// sharing would require generic-typed asserts that hurt readability.
//
//nolint:dupl // see comment above
func ParseRSAPublicKey(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(pemString, `\n`, "\n")))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not an RSA public key")
		}
		return rsaKey, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse public key: not a valid PKIX or PKCS#1 RSA key")
}

// ParseRSAPrivateKey parses an RSA private key from a PEM-encoded
// string. Tries PKCS#8 (modern default) first, then falls back to
// PKCS#1. Same "\\n" handling as ParseRSAPublicKey.
//
//nolint:dupl // see ParseRSAPublicKey: distinct PEM types and x509 funcs make a shared helper less readable.
func ParseRSAPrivateKey(pemString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(pemString, `\n`, "\n")))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key: not a valid PKCS#1 or PKCS#8 RSA key")
}
