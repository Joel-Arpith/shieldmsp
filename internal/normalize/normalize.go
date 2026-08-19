// Package normalize turns Microsoft Graph security JSON into ShieldMSP's
// internal schema. Deterministic only: no AI, no fuzzy matching, no
// heuristic scoring — same input always produces the same output.
package normalize

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// --- Graph-side shapes (only the fields Layer 1 reads) ---

type GraphAlert struct {
	ID                 string          `json:"id"`
	ProviderAlertID    string          `json:"providerAlertId"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Severity           string          `json:"severity"`
	Status             string          `json:"status"`
	MitreTechniques    []string        `json:"mitreTechniques"`
	Evidence           []GraphEvidence `json:"evidence"`
	CreatedDateTime    string          `json:"createdDateTime"`
	LastUpdateDateTime string          `json:"lastUpdateDateTime"`
}

type GraphEvidence struct {
	ODataType     string            `json:"@odata.type"`
	DeviceDNSName string            `json:"deviceDnsName"`
	MdeDeviceID   string            `json:"mdeDeviceId"`
	OSPlatform    string            `json:"osPlatform"`
	HealthStatus  string            `json:"healthStatus"`
	UserAccount   *GraphUserAccount `json:"userAccount"`
}

type GraphUserAccount struct {
	UserPrincipalName string `json:"userPrincipalName"`
}

// --- ShieldMSP-side schema ---

type ShieldAlert struct {
	ExternalID      string          `json:"external_id"`
	ProviderAlertID string          `json:"provider_alert_id"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	Status          string          `json:"status"`
	MitreTechniques []string        `json:"mitre_techniques"`
	FirstSeen       string          `json:"first_seen"`
	LastSeen        string          `json:"last_seen"`
	OrgID           string          `json:"org_id"`
	AssetTier       int             `json:"asset_tier"`
	Raw             json.RawMessage `json:"raw"`
	IngestedAt      time.Time       `json:"ingested_at"`
}

type ShieldDevice struct {
	ExternalID   string `json:"external_id"`
	Hostname     string `json:"hostname"`
	OSPlatform   string `json:"os_platform"`
	HealthStatus string `json:"health_status"`
	LastSeen     string `json:"last_seen"`
	IsIsolated   bool   `json:"is_isolated"` // always false: Graph can't report this
	AssetTier    int    `json:"asset_tier"`
	OrgID        string `json:"org_id"`
}

// defaultAssetTier applies until a tiering scheme exists.
const defaultAssetTier = 3

// HighIsCritical is an OPEN DECISION, not resolved here (see project plan,
// "Open Decisions #1"): does Graph severity "high" map to ShieldMSP "high"
// or "critical"? Defaults to false (high -> high) as the conservative
// choice — flipping it changes what feeds Layer 2's confidence thresholds,
// so it needs an explicit answer, not a silent pick.
const HighIsCritical = false

// MapSeverity maps a Graph severity value to ShieldMSP's low/medium/high/
// critical scale. Unmapped input is an error, never a silent default — every
// value Graph can send must appear in this table.
func MapSeverity(graphSeverity string) (string, error) {
	switch strings.ToLower(graphSeverity) {
	case "unknown", "informational", "low":
		return "low", nil
	case "medium":
		return "medium", nil
	case "high":
		if HighIsCritical {
			return "critical", nil
		}
		return "high", nil
	default:
		return "", fmt.Errorf("normalize: unmapped graph severity %q", graphSeverity)
	}
}

// NormalizeAlert converts one Graph alert into ShieldMSP's schema. raw is
// the original Graph JSON for the alert, kept verbatim for audit/replay.
func NormalizeAlert(a GraphAlert, raw json.RawMessage, orgID string, ingestedAt time.Time) (ShieldAlert, error) {
	severity, err := MapSeverity(a.Severity)
	if err != nil {
		return ShieldAlert{}, fmt.Errorf("normalize: alert %s: %w", a.ID, err)
	}
	return ShieldAlert{
		ExternalID:      a.ID,
		ProviderAlertID: a.ProviderAlertID,
		Title:           a.Title,
		Description:     a.Description,
		Severity:        severity,
		Status:          a.Status,
		MitreTechniques: a.MitreTechniques,
		FirstSeen:       a.CreatedDateTime,
		LastSeen:        a.LastUpdateDateTime,
		OrgID:           orgID,
		AssetTier:       defaultAssetTier,
		Raw:             raw,
		IngestedAt:      ingestedAt,
	}, nil
}

// ExtractDevices derives ShieldMSP devices from alert evidence, deduped by
// mdeDeviceId. When the same device shows up in multiple alerts, the
// most-recent alert's lastUpdateDateTime wins as last_seen. Output is sorted
// by external_id for deterministic ordering.
func ExtractDevices(alerts []GraphAlert, orgID string) []ShieldDevice {
	byID := make(map[string]ShieldDevice)

	for _, a := range alerts {
		for _, ev := range a.Evidence {
			if ev.MdeDeviceID == "" {
				continue
			}
			existing, seen := byID[ev.MdeDeviceID]
			if seen && !isNewer(a.LastUpdateDateTime, existing.LastSeen) {
				continue
			}
			byID[ev.MdeDeviceID] = ShieldDevice{
				ExternalID:   ev.MdeDeviceID,
				Hostname:     ev.DeviceDNSName,
				OSPlatform:   ev.OSPlatform,
				HealthStatus: ev.HealthStatus,
				LastSeen:     a.LastUpdateDateTime,
				IsIsolated:   false,
				AssetTier:    defaultAssetTier,
				OrgID:        orgID,
			}
		}
	}

	devices := make([]ShieldDevice, 0, len(byID))
	for _, d := range byID {
		devices = append(devices, d)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].ExternalID < devices[j].ExternalID })
	return devices
}

// isNewer reports whether candidate is a later RFC3339 timestamp than
// current. Falls back to string comparison if either fails to parse, so a
// malformed timestamp can't panic — just degrades to "last one wins".
func isNewer(candidate, current string) bool {
	ct, err1 := time.Parse(time.RFC3339, candidate)
	cur, err2 := time.Parse(time.RFC3339, current)
	if err1 == nil && err2 == nil {
		return ct.After(cur)
	}
	return candidate > current
}
