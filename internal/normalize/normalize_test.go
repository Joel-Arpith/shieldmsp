package normalize

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestSeverityMapping(t *testing.T) {
	cases := map[string]string{
		"unknown":       "low",
		"informational": "low",
		"low":           "low",
		"medium":        "medium",
		"high":          "high", // HighIsCritical open decision defaults false
	}
	for in, want := range cases {
		got, err := MapSeverity(in)
		if err != nil {
			t.Fatalf("MapSeverity(%q): unexpected error: %v", in, err)
		}
		if got != want {
			t.Errorf("MapSeverity(%q) = %q, want %q", in, got, want)
		}
	}

	if _, err := MapSeverity("somethingGraphDoesntSendYet"); err == nil {
		t.Error("MapSeverity on an unmapped value should error, not silently default")
	}
}

func TestNormalizeAlertFields(t *testing.T) {
	a := GraphAlert{
		ID:                 "x1",
		ProviderAlertID:    "prov-1",
		Severity:           "high",
		Status:             "new",
		CreatedDateTime:    "2026-01-01T00:00:00Z",
		LastUpdateDateTime: "2026-01-02T00:00:00Z",
	}
	raw := json.RawMessage(`{"id":"x1"}`)
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	sa, err := NormalizeAlert(a, raw, "org-1", now)
	if err != nil {
		t.Fatalf("NormalizeAlert: %v", err)
	}
	if sa.ExternalID != a.ID || sa.ProviderAlertID != a.ProviderAlertID {
		t.Errorf("id mapping wrong: %+v", sa)
	}
	if sa.Severity != "high" {
		t.Errorf("severity = %q, want high", sa.Severity)
	}
	if sa.FirstSeen != a.CreatedDateTime || sa.LastSeen != a.LastUpdateDateTime {
		t.Errorf("first/last seen not mapped from created/lastUpdate: %+v", sa)
	}
	if sa.OrgID != "org-1" || sa.AssetTier != defaultAssetTier {
		t.Errorf("org/tier defaults wrong: %+v", sa)
	}
	if !sa.IngestedAt.Equal(now) {
		t.Errorf("ingested_at = %v, want %v", sa.IngestedAt, now)
	}
	if string(sa.Raw) != string(raw) {
		t.Errorf("raw JSON not preserved verbatim: got %s", sa.Raw)
	}
}

// TestDeviceDedup: the fixture has three alerts that all evidence
// device1-mde-guid, plus one alert on a second device. They must collapse to
// exactly two devices, with device1's last_seen taken from whichever of the
// three alerts has the latest lastUpdateDateTime — not just the last one
// processed.
func TestDeviceDedup(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/alerts_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}

	alerts := make([]GraphAlert, 0, len(envelope.Value))
	for _, r := range envelope.Value {
		var a GraphAlert
		if err := json.Unmarshal(r, &a); err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, a)
	}
	if len(alerts) != 4 {
		t.Fatalf("fixture: expected 4 alerts, got %d", len(alerts))
	}

	var device1Refs int
	for _, a := range alerts {
		for _, ev := range a.Evidence {
			if ev.MdeDeviceID == "device1-mde-guid" {
				device1Refs++
			}
		}
	}
	if device1Refs != 3 {
		t.Fatalf("fixture: expected 3 alerts referencing device1, got %d", device1Refs)
	}

	devices := ExtractDevices(alerts, "test-org")
	if len(devices) != 2 {
		t.Fatalf("expected 3 alerts on device1 + 1 on device2 to dedup to 2 devices, got %d: %+v", len(devices), devices)
	}

	goldenRaw, err := os.ReadFile("../../testdata/devices_evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden []ShieldDevice
	if err := json.Unmarshal(goldenRaw, &golden); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(devices, golden) {
		t.Errorf("device dedup mismatch:\n got:  %+v\n want: %+v", devices, golden)
	}
}
