package handlers

import (
	"strings"
	"testing"
)

// TestSysmonQueryScript locks the culture-safe, DST-exact StartTime construction: the
// query must read the UTC clock directly in-script — [datetime]::UtcNow.AddMinutes(-N)
// — and must NOT round-trip a Go-formatted timestamp through [datetime]::Parse
// (culture-sensitive, mis-parses on non-English Windows) nor touch local time at all
// (local arithmetic is off by the DST offset across a transition; even a
// ToUniversalTime() round-trip is ambiguous during the fall-back hour).
func TestSysmonQueryScript(t *testing.T) {
	s := sysmonQueryScript("Microsoft-Windows-Sysmon/Operational", 1, 30)

	if !strings.Contains(s, "[datetime]::UtcNow.AddMinutes(-30)") {
		t.Errorf("script does not read the UTC clock directly (culture-safe + DST-exact); got:\n%s", s)
	}
	if strings.Contains(s, "[datetime]::Parse") {
		t.Errorf("script still round-trips through culture-sensitive [datetime]::Parse")
	}
	if strings.Contains(s, "Get-Date") {
		t.Errorf("script still touches the local clock (Get-Date)")
	}
	if !strings.Contains(s, "Microsoft-Windows-Sysmon/Operational") {
		t.Errorf("script missing the log name")
	}
	if !strings.Contains(s, "Id        = 1") {
		t.Errorf("script missing the event ID filter")
	}
	// The event ID and sinceMinutes are ints, so the format string can't be
	// injected — a different N produces a different, still-safe window.
	if !strings.Contains(sysmonQueryScript("X", 3, 1440), "[datetime]::UtcNow.AddMinutes(-1440)") {
		t.Errorf("sinceMinutes not interpolated correctly")
	}
}
