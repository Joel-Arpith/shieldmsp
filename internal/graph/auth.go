package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// refreshMargin: re-fetch a token this long before it actually expires, so a
// request never starts with a token that dies mid-flight.
const refreshMargin = 120 * time.Second

type token struct {
	value  string
	expiry time.Time
	roles  []string
}

// TokenSource acquires and caches an app-only (client credentials) Graph
// token. Safe for concurrent use: refresh is mutex-guarded so concurrent
// callers don't stampede login.microsoftonline.com.
type TokenSource struct {
	tenantID     string
	clientID     string
	clientSecret string

	// authBaseURL is overridable in tests to point at an httptest server
	// instead of the real login endpoint.
	authBaseURL string
	httpClient  *http.Client

	mu      sync.Mutex
	current *token
}

func NewTokenSource(tenantID, clientID, clientSecret string) *TokenSource {
	return &TokenSource{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		authBaseURL:  "https://login.microsoftonline.com",
		httpClient:   http.DefaultClient,
	}
}

// Token returns a cached, valid token or fetches a fresh one.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.current != nil && time.Until(ts.current.expiry) > refreshMargin {
		return ts.current.value, nil
	}
	tok, err := ts.fetch(ctx)
	if err != nil {
		return "", err
	}
	ts.current = tok
	return tok.value, nil
}

// Invalidate drops the cached token, forcing the next Token() call to fetch
// a fresh one. Called by the client on a 401 in case the secret rotated.
func (ts *TokenSource) Invalidate() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.current = nil
}

// Roles returns the app roles claim of the current (or freshly fetched)
// token, e.g. ["SecurityAlert.Read.All"]. Used by the graph:verify CLI check;
// the token isn't signature-verified here since nothing security-sensitive
// depends on the result, it's just a readout for the operator.
func (ts *TokenSource) Roles(ctx context.Context) ([]string, error) {
	if _, err := ts.Token(ctx); err != nil {
		return nil, err
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.current.roles, nil
}

func decodeJWTRoles(rawToken string) []string {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims.Roles
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (ts *TokenSource) fetch(ctx context.Context) (*token, error) {
	form := url.Values{
		"client_id":     {ts.clientID},
		"client_secret": {ts.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", ts.authBaseURL, ts.tenantID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("auth: decode token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := tr.ErrorDesc
		if msg == "" {
			msg = string(body)
		}
		return nil, fmt.Errorf("auth: token request denied (%d): %s", resp.StatusCode, msg)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("auth: token response had no access_token")
	}

	return &token{
		value:  tr.AccessToken,
		expiry: time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		roles:  decodeJWTRoles(tr.AccessToken),
	}, nil
}
