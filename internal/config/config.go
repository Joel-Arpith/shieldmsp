// Package config loads ShieldMSP's environment configuration.
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// OrgID identifies this tenant's data in the ShieldMSP schema. Single-tenant
	// for now (see plan: "Multi-tenant registration" open decision) so it
	// defaults to the Graph tenant ID rather than needing its own mapping table.
	OrgID string
}

func FromEnv() (Config, error) {
	c := Config{
		TenantID:     os.Getenv("MSGRAPH_TENANT_ID"),
		ClientID:     os.Getenv("MSGRAPH_CLIENT_ID"),
		ClientSecret: os.Getenv("MSGRAPH_CLIENT_SECRET"),
	}

	var missing []string
	if c.TenantID == "" {
		missing = append(missing, "MSGRAPH_TENANT_ID")
	}
	if c.ClientID == "" {
		missing = append(missing, "MSGRAPH_CLIENT_ID")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "MSGRAPH_CLIENT_SECRET")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("config: missing env vars: %s", strings.Join(missing, ", "))
	}

	c.OrgID = os.Getenv("SHIELDMSP_ORG_ID")
	if c.OrgID == "" {
		c.OrgID = c.TenantID
	}
	return c, nil
}
