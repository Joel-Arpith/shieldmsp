package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Thin endpoint wrappers: no retry or auth logic here, that all lives in
// Client. Each just builds a path/query and lets FetchAll do the work.

// GetAlerts calls /security/alerts_v2. filter is passed through verbatim as
// an OData $filter (e.g. "severity eq 'high'"); pass "" for none.
func (c *Client) GetAlerts(ctx context.Context, limit int, filter string) ([]json.RawMessage, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("$top", fmt.Sprint(limit))
	}
	if filter != "" {
		q.Set("$filter", filter)
	}
	return c.FetchAll(ctx, "/security/alerts_v2", q, limit)
}

func (c *Client) ListIncidents(ctx context.Context) ([]json.RawMessage, error) {
	return c.FetchAll(ctx, "/security/incidents", nil, 0)
}

func (c *Client) ListUsers(ctx context.Context) ([]json.RawMessage, error) {
	return c.FetchAll(ctx, "/users", nil, 0)
}

// GetSignInLogs calls /auditLogs/signIns. Requires Entra ID P1; a tenant
// without it gets a *LicenseError from the underlying client call.
func (c *Client) GetSignInLogs(ctx context.Context) ([]json.RawMessage, error) {
	return c.FetchAll(ctx, "/auditLogs/signIns", nil, 0)
}

// GetRiskyUsers calls /identityProtection/riskyUsers. Requires Entra ID P2.
func (c *Client) GetRiskyUsers(ctx context.Context) ([]json.RawMessage, error) {
	return c.FetchAll(ctx, "/identityProtection/riskyUsers", nil, 0)
}
