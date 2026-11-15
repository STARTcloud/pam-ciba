package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer = "https://provider.example.org"
	testClient = "host-ssh"
)

func signedToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func testKey(t *testing.T) (*rsa.PrivateKey, *KeySet) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, &KeySet{keys: map[string]*rsa.PublicKey{"k1": &key.PublicKey}}
}

func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":                testIssuer,
		"sub":                "user@example.org",
		"aud":                testClient,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"preferred_username": "User@Example.org",
	}
}

func TestVerifyIDTokenAcceptsAValidToken(t *testing.T) {
	key, keys := testKey(t)
	now := time.Now()
	claims, err := VerifyIDToken(signedToken(t, key, "k1", validClaims(now)), keys, testIssuer, testClient, now)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Identifies("USER@example.org") {
		t.Error("claims do not identify the account")
	}
	if claims.Identifies("other@example.org") {
		t.Error("claims identify another account")
	}
}

func TestVerifyIDTokenRefuses(t *testing.T) {
	key, keys := testKey(t)
	otherKey, _ := testKey(t)
	now := time.Now()
	cases := map[string]struct {
		key    *rsa.PrivateKey
		kid    string
		change func(map[string]any)
		want   string
	}{
		"another issuer":       {key, "k1", func(c map[string]any) { c["iss"] = "https://evil.example.org" }, "issuer"},
		"another audience":     {key, "k1", func(c map[string]any) { c["aud"] = "other-client" }, "audience"},
		"another party":        {key, "k1", func(c map[string]any) { c["azp"] = "other-client" }, "authorized party"},
		"several audiences":    {key, "k1", func(c map[string]any) { c["aud"] = []string{testClient, "other"} }, "authorized party"},
		"expired":              {key, "k1", func(c map[string]any) { c["exp"] = now.Add(-10 * time.Minute).Unix() }, "expired"},
		"issued in the future": {key, "k1", func(c map[string]any) { c["iat"] = now.Add(10 * time.Minute).Unix() }, "future"},
		"no subject":           {key, "k1", func(c map[string]any) { delete(c, "sub") }, "subject"},
		"unknown key":          {key, "k2", func(map[string]any) {}, "kid"},
		"another signer":       {otherKey, "k1", func(map[string]any) {}, "signature"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			claims := validClaims(now)
			test.change(claims)
			_, err := VerifyIDToken(signedToken(t, test.key, test.kid, claims), keys, testIssuer, testClient, now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want one naming %q", err, test.want)
			}
		})
	}
}

func TestVerifyIDTokenRefusesAnUnsignedToken(t *testing.T) {
	_, keys := testKey(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(validClaims(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	token := header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	if _, verr := VerifyIDToken(token, keys, testIssuer, testClient, time.Now()); verr == nil {
		t.Fatal("an alg none token is accepted")
	}
}
