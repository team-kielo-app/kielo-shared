package cryptoutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func mustGenerateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func encodePKIXPublic(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func encodePKCS1Public(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
}

func encodePKCS8Private(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func encodePKCS1Private(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestParseRSAPublicKey_PKIX(t *testing.T) {
	priv := mustGenerateKey(t)
	got, err := ParseRSAPublicKey(encodePKIXPublic(t, &priv.PublicKey))
	if err != nil {
		t.Fatalf("ParseRSAPublicKey: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("public modulus mismatch")
	}
}

func TestParseRSAPublicKey_PKCS1Fallback(t *testing.T) {
	priv := mustGenerateKey(t)
	got, err := ParseRSAPublicKey(encodePKCS1Public(t, &priv.PublicKey))
	if err != nil {
		t.Fatalf("ParseRSAPublicKey PKCS#1: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("PKCS#1 public modulus mismatch")
	}
}

func TestParseRSAPublicKey_EscapedNewlines(t *testing.T) {
	priv := mustGenerateKey(t)
	pem := encodePKIXPublic(t, &priv.PublicKey)
	envForm := strings.ReplaceAll(pem, "\n", `\n`)
	got, err := ParseRSAPublicKey(envForm)
	if err != nil {
		t.Fatalf("ParseRSAPublicKey escaped: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("escaped-newline public modulus mismatch")
	}
}

func TestParseRSAPublicKey_RejectsGarbage(t *testing.T) {
	if _, err := ParseRSAPublicKey("not a pem"); err == nil {
		t.Fatal("expected error on garbage input")
	}
}

func TestParseRSAPublicKey_RejectsEmpty(t *testing.T) {
	if _, err := ParseRSAPublicKey(""); err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestParseRSAPrivateKey_PKCS8(t *testing.T) {
	priv := mustGenerateKey(t)
	got, err := ParseRSAPrivateKey(encodePKCS8Private(t, priv))
	if err != nil {
		t.Fatalf("ParseRSAPrivateKey: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("PKCS#8 private modulus mismatch")
	}
}

func TestParseRSAPrivateKey_PKCS1Fallback(t *testing.T) {
	priv := mustGenerateKey(t)
	got, err := ParseRSAPrivateKey(encodePKCS1Private(t, priv))
	if err != nil {
		t.Fatalf("ParseRSAPrivateKey PKCS#1: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("PKCS#1 private modulus mismatch")
	}
}

func TestParseRSAPrivateKey_EscapedNewlines(t *testing.T) {
	priv := mustGenerateKey(t)
	pem := encodePKCS8Private(t, priv)
	envForm := strings.ReplaceAll(pem, "\n", `\n`)
	got, err := ParseRSAPrivateKey(envForm)
	if err != nil {
		t.Fatalf("ParseRSAPrivateKey escaped: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatalf("escaped-newline private modulus mismatch")
	}
}

func TestParseRSAPrivateKey_RejectsGarbage(t *testing.T) {
	if _, err := ParseRSAPrivateKey("not a pem"); err == nil {
		t.Fatal("expected error on garbage input")
	}
}
