package handlers

import (
	"errors"
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

// TestSysmonQueryScriptProbesChannel locks the v2.4.0 silent-clean fix: the
// script must probe the channel FIRST (Get-WinEvent -ListLog, -ErrorAction
// Stop) and emit the distinguishable marker when it is absent — otherwise a
// machine without Sysmon reads as a CLEAN Stage 4, violating the "absence of
// findings is not proof" principle.
func TestSysmonQueryScriptProbesChannel(t *testing.T) {
	s := sysmonQueryScript("Microsoft-Windows-Sysmon/Operational", 1, 30)

	if !strings.Contains(s, "Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop") {
		t.Errorf("script does not probe channel existence before querying; got:\n%s", s)
	}
	if !strings.Contains(s, sysmonChannelMissingMarker) {
		t.Errorf("script cannot signal a missing channel (marker %q absent)", sysmonChannelMissingMarker)
	}
	// The probe must come BEFORE the event query, so a missing channel is
	// reported instead of falling through to the event query.
	if strings.Index(s, "-ListLog") > strings.Index(s, "-FilterHashtable") {
		t.Errorf("channel probe must precede the event query")
	}

	// The event query must fail LOUD: -ErrorAction Stop with the benign
	// zero-events case classified by locale-INVARIANT FullyQualifiedErrorId
	// (message-text matching would re-import the culture-sensitivity class the
	// UtcNow fix eliminated), and every other failure — access denied on a
	// non-elevated host, EventLog service down — emitting the query-failed
	// marker instead of masquerading as an empty result.
	if strings.Contains(s, "SilentlyContinue") {
		t.Errorf("event query still uses -ErrorAction SilentlyContinue (access-denied reads as clean)")
	}
	if !strings.Contains(s, "FullyQualifiedErrorId -like 'NoMatchingEvents*'") {
		t.Errorf("zero-events case not classified by locale-invariant FullyQualifiedErrorId")
	}
	if !strings.Contains(s, sysmonQueryFailedMarker) {
		t.Errorf("script cannot signal a failed query (marker %q absent)", sysmonQueryFailedMarker)
	}
}

// TestDecodeSysmonQueryOutput pins the marker→sentinel mapping and the
// PowerShell single-object-vs-array normalisation — the Go half of the
// silent-clean fix, testable without spawning PowerShell.
func TestDecodeSysmonQueryOutput(t *testing.T) {
	// Markers → sentinels (with the CRLF PowerShell actually appends).
	if _, err := decodeSysmonQueryOutput(sysmonChannelMissingMarker + "\r\n"); !errors.Is(err, ErrSysmonChannelMissing) {
		t.Errorf("channel-missing marker: got %v, want ErrSysmonChannelMissing", err)
	}
	if _, err := decodeSysmonQueryOutput(sysmonQueryFailedMarker + "\r\n"); !errors.Is(err, ErrSysmonQueryFailed) {
		t.Errorf("query-failed marker: got %v, want ErrSysmonQueryFailed", err)
	}

	// Empty forms → zero events, no error.
	for _, empty := range []string{"", "[]", "null", "  [] \r\n"} {
		if xs, err := decodeSysmonQueryOutput(empty); err != nil || len(xs) != 0 {
			t.Errorf("decode(%q) = %v, %v; want empty, nil", empty, xs, err)
		}
	}

	// Multi-event JSON array of strings.
	if xs, err := decodeSysmonQueryOutput(`["<Event>a</Event>","<Event>b</Event>"]`); err != nil || len(xs) != 2 {
		t.Errorf("array decode = %v, %v; want 2 events", xs, err)
	}
	// Single event: ConvertTo-Json emits a bare QUOTED JSON string — this is
	// also why a crafted event can never spoof a marker (markers are unquoted).
	if xs, err := decodeSysmonQueryOutput(`"<Event>solo</Event>"`); err != nil || len(xs) != 1 || xs[0] != "<Event>solo</Event>" {
		t.Errorf("single decode = %v, %v; want the one unwrapped event", xs, err)
	}
	// An event whose CONTENT is a marker string arrives quoted → data, not marker.
	if xs, err := decodeSysmonQueryOutput(`"` + sysmonChannelMissingMarker + `"`); err != nil || len(xs) != 1 {
		t.Errorf("quoted marker must decode as event data, got %v, %v", xs, err)
	}

	// Garbage → error, never silent success.
	if _, err := decodeSysmonQueryOutput("not json at all"); err == nil {
		t.Errorf("garbage output must error")
	}
}
