package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://graph.microsoft.com/v1.0" // pinned: never beta

const maxTransientRetries = 5

// GraphError is a parsed {"error":{"code","message"}} response body.
type GraphError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *GraphError) Error() string {
	return fmt.Sprintf("graph: %d %s: %s", e.StatusCode, e.Code, e.Message)
}

// LicenseError and ConsentError both wrap a 403 GraphError. Graph returns the
// same status code for "you don't have the right license" and "admin hasn't
// consented" — callers that need to tell them apart use errors.As.
type LicenseError struct{ *GraphError }
type ConsentError struct{ *GraphError }

// Client is the single entry point for Graph HTTP calls. All retry,
// pagination, and error-parsing logic lives here so endpoint wrappers
// (security.go) stay thin.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	tokenSource *TokenSource
	sleep       func(time.Duration) // overridable in tests to skip real waits
}

func NewClient(ts *TokenSource) *Client {
	return &Client{
		baseURL:     defaultBaseURL,
		httpClient:  http.DefaultClient,
		tokenSource: ts,
		sleep:       time.Sleep,
	}
}

// Page is one @odata paginated response with items left as raw JSON so
// callers decode into whatever shape they need.
type page struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// FetchAll GETs path (with query on the first request only) and follows
// @odata.nextLink verbatim until it's absent or limit items are collected.
// limit <= 0 means "all pages".
func (c *Client) FetchAll(ctx context.Context, path string, query url.Values, limit int) ([]json.RawMessage, error) {
	var items []json.RawMessage
	next := c.baseURL + path
	if len(query) > 0 {
		next += "?" + query.Encode()
	}

	for next != "" {
		body, err := c.doURL(ctx, http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		var pg page
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("graph: decode page: %w", err)
		}
		items = append(items, pg.Value...)
		if limit > 0 && len(items) >= limit {
			return items[:limit], nil
		}
		next = pg.NextLink // used exactly as Graph returned it, never rebuilt
	}
	return items, nil
}

func (c *Client) doURL(ctx context.Context, method, fullURL string) ([]byte, error) {
	retriedAuth := false
	backoff := 500 * time.Millisecond

	for attempt := 0; ; attempt++ {
		tok, err := c.tokenSource.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("graph: get token: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
		if err != nil {
			return nil, fmt.Errorf("graph: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("graph: request failed: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("graph: read response: %w", readErr)
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return body, nil

		case resp.StatusCode == http.StatusUnauthorized && !retriedAuth:
			retriedAuth = true
			c.tokenSource.Invalidate()
			continue

		case resp.StatusCode == http.StatusTooManyRequests && attempt < maxTransientRetries:
			c.sleep(parseRetryAfter(resp.Header.Get("Retry-After")))
			continue

		case resp.StatusCode >= 500 && attempt < maxTransientRetries:
			c.sleep(backoff)
			if backoff < 8*time.Second {
				backoff *= 2
			}
			continue

		default:
			return nil, parseGraphError(resp.StatusCode, body)
		}
	}
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return time.Second
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return time.Second
}

func parseGraphError(status int, body []byte) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	gerr := &GraphError{StatusCode: status, Code: envelope.Error.Code, Message: envelope.Error.Message}

	if status == http.StatusForbidden {
		// ponytail: Graph gives no clean licensing-vs-consent discriminator in
		// the error body, so this pattern-matches on the message text. If a
		// real tenant's 403 doesn't fit either bucket it just falls through
		// to the plain GraphError below — revisit if that happens often.
		lower := strings.ToLower(gerr.Message)
		switch {
		case strings.Contains(lower, "license"):
			return &LicenseError{gerr}
		case strings.Contains(lower, "consent") || strings.Contains(envelope.Error.Code, "AuthorizationRequestDenied"):
			return &ConsentError{gerr}
		}
	}
	return gerr
}
