package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const clockLeeway = 60 * time.Second

// KeySet is the provider's RSA signing keys by key ID.
type KeySet struct {
	keys map[string]*rsa.PublicKey
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// FetchKeys reads the JSON Web Key Set at jwksURI and answers its RSA signature keys.
func FetchKeys(ctx context.Context, client *http.Client, jwksURI string) (*KeySet, error) {
	body, err := getDocument(ctx, client, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("read provider keys: %w", err)
	}
	document := struct {
		Keys []jsonWebKey `json:"keys"`
	}{}
	if uerr := json.Unmarshal(body, &document); uerr != nil {
		return nil, fmt.Errorf("parse provider keys: %w", uerr)
	}
	set := &KeySet{keys: map[string]*rsa.PublicKey{}}
	for _, key := range document.Keys {
		if key.Kty != "RSA" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		modulus, nerr := base64.RawURLEncoding.DecodeString(key.N)
		exponent, eerr := base64.RawURLEncoding.DecodeString(key.E)
		if nerr != nil || eerr != nil || len(modulus) == 0 || len(exponent) == 0 || len(exponent) > 4 {
			continue
		}
		e := 0
		for _, b := range exponent {
			e = e<<8 | int(b)
		}
		set.keys[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
	}
	if len(set.keys) == 0 {
		return nil, errors.New("provider key set holds no RSA signature key")
	}
	return set, nil
}

func (s *KeySet) find(kid string) (*rsa.PublicKey, error) {
	if key, ok := s.keys[kid]; ok {
		return key, nil
	}
	if kid == "" && len(s.keys) == 1 {
		for _, key := range s.keys {
			return key, nil
		}
	}
	return nil, fmt.Errorf("no provider key with kid %q", kid)
}

type audience []string

func (a *audience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Claims is the verified content of an ID token.
type Claims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          audience `json:"aud"`
	AuthorizedParty   string   `json:"azp"`
	Expiry            int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
}

// Identifies answers whether the token's subject, preferred username or email equals account, compared without case.
func (c *Claims) Identifies(account string) bool {
	for _, value := range []string{c.Subject, c.PreferredUsername, c.Email} {
		if value != "" && strings.EqualFold(value, account) {
			return true
		}
	}
	return false
}

// VerifyIDToken checks an ID token as OpenID Connect Core 3.1.3.7 requires of a client: an RSA signature by one of keys, the issuer, this client in the audience and as authorized party, and the expiry and issue times against now.
func VerifyIDToken(token string, keys *KeySet, issuer, clientID string, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("ID token is not a signed JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("ID token header is not base64url")
	}
	header := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{}
	if uerr := json.Unmarshal(headerBytes, &header); uerr != nil {
		return nil, errors.New("ID token header is not JSON")
	}
	var digest hash.Hash
	var algorithm crypto.Hash
	switch header.Alg {
	case "RS256":
		digest, algorithm = sha256.New(), crypto.SHA256
	case "RS384":
		digest, algorithm = sha512.New384(), crypto.SHA384
	case "RS512":
		digest, algorithm = sha512.New(), crypto.SHA512
	default:
		return nil, fmt.Errorf("ID token algorithm %q is not accepted", header.Alg)
	}
	key, err := keys.find(header.Kid)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("ID token signature is not base64url")
	}
	digest.Write([]byte(parts[0] + "." + parts[1]))
	if verr := rsa.VerifyPKCS1v15(key, algorithm, digest.Sum(nil), signature); verr != nil {
		return nil, errors.New("ID token signature does not verify")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("ID token payload is not base64url")
	}
	claims := &Claims{}
	if uerr := json.Unmarshal(payload, claims); uerr != nil {
		return nil, errors.New("ID token payload is not JSON")
	}
	if strings.TrimRight(claims.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("ID token issuer %q is not the provider", claims.Issuer)
	}
	named := false
	for _, aud := range claims.Audience {
		if aud == clientID {
			named = true
		}
	}
	if !named {
		return nil, errors.New("ID token audience does not name this client")
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID {
		return nil, errors.New("ID token authorized party is another client")
	}
	if len(claims.Audience) > 1 && claims.AuthorizedParty == "" {
		return nil, errors.New("ID token with several audiences names no authorized party")
	}
	if claims.Expiry == 0 || !now.Before(time.Unix(claims.Expiry, 0).Add(clockLeeway)) {
		return nil, errors.New("ID token is expired")
	}
	if claims.IssuedAt != 0 && time.Unix(claims.IssuedAt, 0).After(now.Add(clockLeeway)) {
		return nil, errors.New("ID token is issued in the future")
	}
	if claims.Subject == "" {
		return nil, errors.New("ID token has no subject")
	}
	return claims, nil
}
