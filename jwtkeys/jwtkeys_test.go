package jwtkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    "kielo.app",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verifies(set *KeySet, token string) bool {
	_, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, set.KeyFunc, jwt.WithExpirationRequired())
	return err == nil
}

func TestKeySetVerification(t *testing.T) {
	a, b, c := genKey(t), genKey(t), genKey(t)
	kidA := Fingerprint(&a.PublicKey)
	for _, withKid := range []bool{true, false} {
		kid := ""
		if withKid {
			kid = kidA
		}
		tokenA := sign(t, a, kid)
		for name, set := range map[string]*KeySet{
			"A":   New(&a.PublicKey),
			"A,B": New(&a.PublicKey, &b.PublicKey),
			"B,A": New(&b.PublicKey, &a.PublicKey),
		} {
			if !verifies(set, tokenA) {
				t.Errorf("kid=%v: token signed by A should verify with {%s}", withKid, name)
			}
		}
		if verifies(New(&b.PublicKey), tokenA) {
			t.Errorf("kid=%v: token signed by A must not verify with {B}", withKid)
		}
	}
	tokenC := sign(t, c, Fingerprint(&c.PublicKey))
	if verifies(New(&a.PublicKey, &b.PublicKey), tokenC) {
		t.Error("token signed by C must fail")
	}
	if verifies(New(&a.PublicKey, &b.PublicKey), sign(t, c, "")) {
		t.Error("token signed by C without kid must fail")
	}
}

func TestKeySetKidSelection(t *testing.T) {
	a, b := genKey(t), genKey(t)
	set := New(&a.PublicKey, &b.PublicKey)
	tok := &jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]any{"kid": Fingerprint(&b.PublicKey)}}
	got, err := set.KeyFunc(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got != &b.PublicKey {
		t.Fatal("kid of B must select exactly B")
	}

	unknown := &jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]any{"kid": "deadbeefdeadbeef"}}
	got, err = set.KeyFunc(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if ks, ok := got.(jwt.VerificationKeySet); !ok || len(ks.Keys) != 2 {
		t.Fatalf("unknown kid must offer every key, got %T", got)
	}

	absent := &jwt.Token{Method: jwt.SigningMethodRS256, Header: map[string]any{}}
	if got, _ = set.KeyFunc(absent); got == nil {
		t.Fatal("absent kid must offer keys")
	}
}

func TestKeySetRejectsNonRSA(t *testing.T) {
	set := New(&genKey(t).PublicKey)
	if _, err := set.KeyFunc(&jwt.Token{Method: jwt.SigningMethodHS256, Header: map[string]any{"alg": "HS256"}}); err == nil {
		t.Fatal("HMAC token must be refused")
	}
}

func pemOf(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestNextFromEnv(t *testing.T) {
	a, b := genKey(t), genKey(t)

	t.Setenv(NextEnv, "")
	got, err := WithNextFromEnv(&a.PublicKey)
	if err != nil || got.Len() != 1 {
		t.Fatalf("unset NEXT must leave one key, got %d, err %v", got.Len(), err)
	}

	t.Setenv(NextEnv, "not a pem")
	if got, err := WithNextFromEnv(&a.PublicKey); err == nil || got != nil {
		t.Fatalf("unparsable NEXT must be an error, got %v, %v", got, err)
	}
	if _, err := FromPEM(pemOf(t, &a.PublicKey)); err == nil {
		t.Fatal("FromPEM with an unparsable NEXT must error")
	}

	t.Setenv(NextEnv, pemOf(t, &b.PublicKey))
	set, err := FromPEM(pemOf(t, &a.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 || !verifies(set, sign(t, b, "")) || !verifies(set, sign(t, a, "")) {
		t.Fatal("PEM and NEXT keys must both verify")
	}

	if _, err := FromPEM("garbage"); err == nil {
		t.Fatal("unparsable primary must error")
	}
}

func TestFingerprintShape(t *testing.T) {
	fp := Fingerprint(&genKey(t).PublicKey)
	if len(fp) != 16 {
		t.Fatalf("fingerprint %q must be 16 hex chars", fp)
	}
}
