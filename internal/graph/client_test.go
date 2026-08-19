package graph

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func fixedTokenSource(value string) *TokenSource {
	return &TokenSource{current: &token{value: value, expiry: time.Now().Add(time.Hour)}}
}

func TestRetry429WithRetryAfter(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"throttled"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":[{"id":"a"}]}`))
	}))
	defer srv.Close()

	var slept []time.Duration
	c := &Client{
		baseURL:     srv.URL,
		httpClient:  srv.Client(),
		tokenSource: fixedTokenSource("t"),
		sleep:       func(d time.Duration) { slept = append(slept, d) },
	}

	items, err := c.FetchAll(context.Background(), "/security/alerts_v2", nil, 0)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item after retry, got %d", len(items))
	}
	if calls != 2 {
		t.Fatalf("expected 2 requests (429 then success), got %d", calls)
	}
	if len(slept) != 1 || slept[0] != 2*time.Second {
		t.Fatalf("expected exactly one 2s sleep honoring Retry-After, got %v", slept)
	}
}

func TestPaginationOdataNextLink(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value":           []map[string]any{{"id": "a1"}},
			"@odata.nextLink": srv.URL + "/security/alerts_v2/page2?$skiptoken=abc",
		})
	})
	mux.HandleFunc("/security/alerts_v2/page2", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "$skiptoken=abc" {
			t.Errorf("nextLink query string was rebuilt instead of followed verbatim: got %q", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "a2"}},
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{
		baseURL:     srv.URL,
		httpClient:  srv.Client(),
		tokenSource: fixedTokenSource("t"),
		sleep:       func(time.Duration) {},
	}

	items, err := c.FetchAll(context.Background(), "/security/alerts_v2", nil, 0)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items across both pages, got %d", len(items))
	}
}

func TestTokenRefreshOn401(t *testing.T) {
	var authCalls int
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCalls++
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-token",
			"expires_in":   3600,
		})
	}))
	defer authSrv.Close()

	var apiCalls int
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		auth := r.Header.Get("Authorization")
		if apiCalls == 1 {
			if auth != "Bearer stale-token" {
				t.Errorf("first call: expected stale token, got %q", auth)
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"token expired"}}`))
			return
		}
		if auth != "Bearer fresh-token" {
			t.Errorf("retry: expected fresh token, got %q", auth)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":[{"id":"ok"}]}`))
	}))
	defer apiSrv.Close()

	ts := &TokenSource{
		tenantID:     "tenant",
		clientID:     "client",
		clientSecret: "secret",
		authBaseURL:  authSrv.URL,
		httpClient:   authSrv.Client(),
		current:      &token{value: "stale-token", expiry: time.Now().Add(time.Hour)},
	}
	c := &Client{
		baseURL:     apiSrv.URL,
		httpClient:  apiSrv.Client(),
		tokenSource: ts,
		sleep:       func(time.Duration) {},
	}

	items, err := c.FetchAll(context.Background(), "/security/alerts_v2", nil, 0)
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item after recovering from 401, got %d", len(items))
	}
	if apiCalls != 2 {
		t.Fatalf("expected 2 API calls (401 then retry), got %d", apiCalls)
	}
	if authCalls != 1 {
		t.Fatalf("expected exactly 1 token refresh, got %d", authCalls)
	}
}

func TestLicenseErrorFixture(t *testing.T) {
	body, err := os.ReadFile("../../testdata/error_403_licensing.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseGraphError(http.StatusForbidden, body)
	var le *LicenseError
	if !errors.As(parsed, &le) {
		t.Fatalf("expected *LicenseError from licensing fixture, got %T: %v", parsed, parsed)
	}
}
