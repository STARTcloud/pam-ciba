// Package oidc reads an OpenID Provider's metadata and key set and verifies the ID tokens it issues.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxDocumentBytes = 1 << 20

// Metadata is the part of the provider's OpenID Connect Discovery document a CIBA poll client reads.
type Metadata struct {
	Issuer                                 string   `json:"issuer"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	JWKSURI                                string   `json:"jwks_uri"`
	BackchannelAuthenticationEndpoint      string   `json:"backchannel_authentication_endpoint"`
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported"`
}

// Discover reads the metadata published under the issuer and answers it once the issuer matches, every endpoint is https and poll delivery is offered.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Metadata, error) {
	issuer = strings.TrimRight(issuer, "/")
	body, err := getDocument(ctx, client, issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("read provider metadata: %w", err)
	}
	metadata := &Metadata{}
	if uerr := json.Unmarshal(body, metadata); uerr != nil {
		return nil, fmt.Errorf("parse provider metadata: %w", uerr)
	}
	if strings.TrimRight(metadata.Issuer, "/") != issuer {
		return nil, fmt.Errorf("provider metadata names issuer %q, expected %q", metadata.Issuer, issuer)
	}
	for name, endpoint := range map[string]string{
		"token_endpoint":                      metadata.TokenEndpoint,
		"jwks_uri":                            metadata.JWKSURI,
		"backchannel_authentication_endpoint": metadata.BackchannelAuthenticationEndpoint,
	} {
		if herr := requireHTTPS(name, endpoint); herr != nil {
			return nil, herr
		}
	}
	for _, mode := range metadata.BackchannelTokenDeliveryModesSupported {
		if mode == "poll" {
			return metadata, nil
		}
	}
	return nil, errors.New("provider does not offer the CIBA poll delivery mode")
}

func requireHTTPS(name, endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("provider metadata has no %s", name)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("provider metadata %s is not an https URL", name)
	}
	return nil
}

func getDocument(ctx context.Context, client *http.Client, address string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentBytes))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", address, response.StatusCode)
	}
	return body, nil
}
