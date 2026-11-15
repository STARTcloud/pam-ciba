package ciba

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/STARTcloud/pam-ciba/internal/oidc"
)

func provider(t *testing.T, authorize, token http.HandlerFunc) *Client {
	t.Helper()
	mux := http.NewServeMux()
	if authorize != nil {
		mux.HandleFunc("/bc-authorize", authorize)
	}
	if token != nil {
		mux.HandleFunc("/token", token)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &Client{
		HTTP:     server.Client(),
		ClientID: "host-ssh",
		Metadata: &oidc.Metadata{
			TokenEndpoint:                     server.URL + "/token",
			BackchannelAuthenticationEndpoint: server.URL + "/bc-authorize",
		},
	}
}

func answer(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestAuthorizeSendsTheRequestAndReadsTheAcknowledgement(t *testing.T) {
	client := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]string{
			"client_id":             "host-ssh",
			"scope":                 "openid profile",
			"login_hint":            "user@example.org",
			"binding_message":       "sshd sign-in",
			"authorization_details": `[{"type":"pam_sign_in"}]`,
			"requested_expiry":      "120",
		} {
			if got := r.PostForm.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		answer(w, http.StatusOK, map[string]any{"auth_req_id": "abc", "expires_in": 120, "interval": 2})
	}, nil)

	request, err := client.Authorize(context.Background(), "openid profile", "user@example.org", "sshd sign-in", `[{"type":"pam_sign_in"}]`, 120)
	if err != nil {
		t.Fatal(err)
	}
	if request.AuthReqID != "abc" || request.ExpiresIn != 120*time.Second || request.Interval != 2*time.Second {
		t.Errorf("unexpected acknowledgement: %+v", request)
	}
}

func TestAuthorizeDefaultsTheIntervalToFiveSeconds(t *testing.T) {
	client := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusOK, map[string]any{"auth_req_id": "abc", "expires_in": 60})
	}, nil)
	request, err := client.Authorize(context.Background(), "openid", "user@example.org", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if request.Interval != 5*time.Second {
		t.Errorf("interval = %s, want 5s", request.Interval)
	}
}

func TestAuthorizeAnswersTheProviderError(t *testing.T) {
	client := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusBadRequest, map[string]any{"error": "unknown_user_id", "error_description": "no such end-user"})
	}, nil)
	_, err := client.Authorize(context.Background(), "openid", "nobody@example.org", "", "", 0)
	var providerError *Error
	if !errors.As(err, &providerError) || providerError.Code != "unknown_user_id" {
		t.Fatalf("error = %v, want unknown_user_id", err)
	}
}

func TestPollWaitsThroughPendingAndAnswersTheTokens(t *testing.T) {
	calls := 0
	client := provider(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.PostForm.Get("grant_type"); got != GrantType {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("auth_req_id"); got != "abc" {
			t.Errorf("auth_req_id = %q", got)
		}
		calls++
		if calls < 3 {
			answer(w, http.StatusBadRequest, map[string]any{"error": ErrAuthorizationPending})
			return
		}
		answer(w, http.StatusOK, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": "it"})
	})

	tokens, err := client.Poll(context.Background(), &Request{AuthReqID: "abc", ExpiresIn: 5 * time.Second, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.IDToken != "it" || calls != 3 {
		t.Errorf("tokens = %+v after %d calls", tokens, calls)
	}
}

func TestPollStopsOnAccessDenied(t *testing.T) {
	client := provider(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusBadRequest, map[string]any{"error": ErrAccessDenied})
	})
	_, err := client.Poll(context.Background(), &Request{AuthReqID: "abc", ExpiresIn: 5 * time.Second, Interval: 10 * time.Millisecond})
	var providerError *Error
	if !errors.As(err, &providerError) || providerError.Code != ErrAccessDenied {
		t.Fatalf("error = %v, want access_denied", err)
	}
}

func TestPollExpiresWithTheRequest(t *testing.T) {
	client := provider(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusBadRequest, map[string]any{"error": ErrAuthorizationPending})
	})
	_, err := client.Poll(context.Background(), &Request{AuthReqID: "abc", ExpiresIn: 60 * time.Millisecond, Interval: 20 * time.Millisecond})
	var providerError *Error
	if !errors.As(err, &providerError) || providerError.Code != ErrExpiredToken {
		t.Fatalf("error = %v, want expired_token", err)
	}
}

func TestPollEndsWithTheContext(t *testing.T) {
	client := provider(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusBadRequest, map[string]any{"error": ErrAuthorizationPending})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := client.Poll(ctx, &Request{AuthReqID: "abc", ExpiresIn: time.Minute, Interval: 10 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
}
