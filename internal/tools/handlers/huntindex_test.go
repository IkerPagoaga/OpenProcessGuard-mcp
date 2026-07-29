package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleFindings() []Finding {
	return []Finding{
		{Stage: 1, Severity: SeverityMedium, Category: "SUSPICIOUS_PROCESS", Description: "m0"},
		{Stage: 1, Severity: SeverityCritical, Category: "SYSTEM_MASQUERADE", Description: "c0"},
		{Stage: 3, Severity: SeverityInfo, Category: "TOOL_UNAVAILABLE", Description: "i0"},
		{Stage: 4, Severity: SeverityHigh, Category: "BEACON_CANDIDATE", Description: "h0"},
		{Stage: 2, Severity: SeverityMedium, Category: "PERSISTENCE_MECHANISM", Description: "m1"},
	}
}

// TestIndexBySeverityPointsAtMatchingFindings is the correctness half of the
// de-duplication: once the buckets hold positions instead of copies, an off-by-one
// would silently mislabel a finding's severity rather than fail loudly.
func TestIndexBySeverityPointsAtMatchingFindings(t *testing.T) {
	findings := sampleFindings()
	r := HuntReport{Findings: findings}
	r.Critical, r.High, r.Medium, r.Info = indexBySeverity(findings)

	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityInfo} {
		for _, idx := range r.severityIndex(sev) {
			if idx < 0 || idx >= len(findings) {
				t.Fatalf("%s bucket contains out-of-range index %d", sev, idx)
			}
			if got := findings[idx].Severity; got != sev {
				t.Errorf("%s bucket index %d points at a %s finding (%q)", sev, idx, got, findings[idx].Description)
			}
		}
	}
}

// TestIndexBySeverityCoversEveryFindingExactlyOnce guards against a finding being
// dropped from the buckets (invisible in the counts) or double-counted.
func TestIndexBySeverityCoversEveryFindingExactlyOnce(t *testing.T) {
	findings := sampleFindings()
	crit, high, med, info := indexBySeverity(findings)

	seen := make(map[int]int, len(findings))
	for _, bucket := range [][]int{crit, high, med, info} {
		for _, idx := range bucket {
			seen[idx]++
		}
	}
	for i := range findings {
		switch seen[i] {
		case 1: // correct
		case 0:
			t.Errorf("finding %d (%s) appears in no severity bucket", i, findings[i].Description)
		default:
			t.Errorf("finding %d (%s) appears in %d buckets", i, findings[i].Description, seen[i])
		}
	}
}

func TestIndexBySeverityBucketsAreNeverNil(t *testing.T) {
	crit, high, med, info := indexBySeverity(nil)
	for name, b := range map[string][]int{"critical": crit, "high": high, "medium": med, "info": info} {
		if b == nil {
			t.Errorf("%s bucket is nil; it would marshal as JSON null instead of []", name)
		}
	}
}

// TestHuntReportCarriesNoDuplicateFindingText is the point of the change: a finding's
// text must appear ONCE in the payload. Previously each finding was serialised twice
// (once in findings, once in its severity bucket), making half the flagship tool's
// output redundant bytes competing for the model's context.
func TestHuntReportCarriesNoDuplicateFindingText(t *testing.T) {
	findings := sampleFindings()
	r := HuntReport{Findings: findings}
	r.Critical, r.High, r.Medium, r.Info = indexBySeverity(findings)

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload := string(b)
	for _, f := range findings {
		if n := strings.Count(payload, `"description":"`+f.Description+`"`); n != 1 {
			t.Errorf("finding %q appears %d times in the payload, want exactly 1", f.Description, n)
		}
	}
	// And the buckets must serialise as numbers, not objects.
	if !strings.Contains(payload, `"critical":[1]`) {
		t.Errorf("critical bucket did not serialise as an index array; payload: %s", payload)
	}
}
