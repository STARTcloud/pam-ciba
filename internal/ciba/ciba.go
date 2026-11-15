// Package ciba is a poll-mode client of OpenID Connect Client-Initiated Backchannel Authentication Core 1.0.
package ciba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/STARTcloud/pam-ciba/internal/oidc"
)

// GrantType is the token request grant type of CIBA Core 10.1.
const GrantType = "urn:openid:params:grant-type:ciba"

const (
	defaultInterval   = 5 * time.Second
	slowDownIncrement = 5 * time.Second
	maxInterval       = 60 * time.Second
	maxResponseBytes  = 1 << 20
)

// Token endpoint and authentication endpoint error codes of CIBA Core 11 and 13.
const (
	ErrAuthorizationPending = "authorization_pending"
	ErrSlowDown             = "slow_down"
	ErrExpiredToken         = "expired_token"
	ErrAccessDenied         = "access_denied"
)

// Error is an OAuth error response of the provider.
type Error struct {
	Status      int
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("provider answered %s (HTTP %d)", e.Code, e.Status)
	}
	return fmt.Sprintf("provider answered %s (HTTP %d): %s", e.Code, e.Status, e.Description)
}

// Client sends one client's requests to one provider.
type Client struct {
	HTTP     *http.Client
	Metadata *oidc.Metadata
	ClientID string
}

// Request is an accepted authentication request: its identifier, its lifetime and the minimum wait between token requests.
type Request struct {
	AuthReqID string
	ExpiresIn time.Duration
	Interval  time.Duration
}

// Tokens is a successful token response.
type Tokens struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
}

// Authorize sends the authentication request of CIBA Core 7.1 for the end-user named by loginHint and answers the provider's acknowledgement. bindingMessage, authorizationDetails (the JSON array of RFC 9396) and requestedExpiry are left out when empty and zero.
func (c *Client) Authorize(ctx context.Context, scope, loginHint, bindingMessage, authorizationDetails string, requestedExpiry int) (*Request, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("scope", scope)
	form.Set("login_hint", loginHint)
	if bindingMessage != "" {
		form.Set("binding_message", bindingMessage)
	}
	if authorizationDetails != "" {
		form.Set("authorization_details", authorizationDetails)
	}
	if requestedExpiry > 0 {
		form.Set("requested_expiry", strconv.Itoa(requestedExpiry))
	}
	body, err := c.post(ctx, c.Metadata.BackchannelAuthenticationEndpoint, form)
	if err != nil {
		return nil, err
	}
	acknowledgement := struct {
		AuthReqID string `json:"auth_req_id"`
		ExpiresIn int    `json:"expires_in"`
		Interval  int    `json:"interval"`
	}{}
	if uerr := json.Unmarshal(body, &acknowledgement); uerr != nil {
		return nil, fmt.Errorf("parse authentication acknowledgement: %w", uerr)
	}
	if acknowledgement.AuthReqID == "" || acknowledgement.ExpiresIn <= 0 {
		return nil, errors.New("authentication acknowledgement lacks auth_req_id or expires_in")
	}
	interval := defaultInterval
	if acknowledgement.Interval > 0 {
		interval = time.Duration(acknowledgement.Interval) * time.Second
	}
	return &Request{
		AuthReqID: acknowledgement.AuthReqID,
		ExpiresIn: time.Duration(acknowledgement.ExpiresIn) * time.Second,
		Interval:  interval,
	}, nil
}

// Poll sends the token request of CIBA Core 10.1 until the end-user answers, the request expires or ctx ends. It waits the request's interval before each token request, adds five seconds on slow_down and doubles the wait after a failed connection or a 5xx answer.
func (c *Client) Poll(ctx context.Context, request *Request) (*Tokens, error) {
	deadline := time.Now().Add(request.ExpiresIn)
	interval := request.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	form := url.Values{}
	form.Set("grant_type", GrantType)
	form.Set("auth_req_id", request.AuthReqID)
	form.Set("client_id", c.ClientID)
	for {
		if werr := wait(ctx, interval, deadline); werr != nil {
			return nil, werr
		}
		body, err := c.post(ctx, c.Metadata.TokenEndpoint, form)
		if err == nil {
			tokens := &Tokens{}
			if uerr := json.Unmarshal(body, tokens); uerr != nil {
				return nil, fmt.Errorf("parse token response: %w", uerr)
			}
			return tokens, nil
		}
		var providerError *Error
		if !errors.As(err, &providerError) || providerError.Status >= http.StatusInternalServerError {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			interval = min(interval*2, maxInterval)
			continue
		}
		switch providerError.Code {
		case ErrAuthorizationPending:
		case ErrSlowDown:
			interval += slowDownIncrement
		default:
			return nil, providerError
		}
	}
}

func wait(ctx context.Context, interval time.Duration, deadline time.Time) error {
	if !time.Now().Add(interval).Before(deadline) {
		return &Error{Status: http.StatusBadRequest, Code: ErrExpiredToken, Description: "the authentication request expired before the end-user answered"}
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) post(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		return body, nil
	}
	providerError := &Error{Status: response.StatusCode}
	document := struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
	}{}
	if uerr := json.Unmarshal(body, &document); uerr == nil {
		providerError.Code = document.Code
		providerError.Description = document.Description
	}
	if providerError.Code == "" {
		providerError.Code = "http_" + strconv.Itoa(response.StatusCode)
	}
	return nil, providerError
}
