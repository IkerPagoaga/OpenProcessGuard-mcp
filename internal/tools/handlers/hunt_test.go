package handlers

import (
	"strings"
	"testing"
)

// TestSigningFindings locks the Stage-1 signing-lens calibration that closes the
// "plain unsigned malware = zero hunt findings" gap: tampering (HashMismatch) and
// untrusted issuers (NotTrusted) escalate to HIGH; merely-unsigned is made
// visible as INFO and counted; a Valid signature and an un-evaluated (empty,
// non-elevated) status produce nothing.
func TestSigningFindings(t *testing.T) {
	procs := []procRow{
		{PID: 1, Name: "trusted.exe", ExePath: `C:\Windows\System32\trusted.exe`, Status: "Valid"},
		{PID: 2, Name: "unreadable.exe", ExePath: "", Status: ""}, // non-elevated unknown -> skipped
		{PID: 3, Name: "tampered.exe", ExePath: `C:\x\tampered.exe`, Status: "HashMismatch"},
		{PID: 4, Name: "untrusted.exe", ExePath: `C:\x\untrusted.exe`, Status: "NotTrusted"},
		{PID: 5, Name: "plain.exe", ExePath: `C:\Users\me\plain.exe`, Status: "NotSigned"},
		{PID: 6, Name: "weird.exe", ExePath: `C:\x\weird.exe`, Status: "UnknownError"}, // a verify error is NOT "unsigned"
	}

	high, infoUnsigned, unverified, summary := 0, 0, 0, 0
	for _, f := range signingFindings(procs) {
		switch f.Category {
		case "UNTRUSTED_SIGNATURE":
			if f.Severity != SeverityHigh {
				t.Errorf("UNTRUSTED_SIGNATURE should be HIGH, got %s", f.Severity)
			}
			high++
		case "UNSIGNED_PROCESS":
			if f.Severity != SeverityInfo {
				t.Errorf("UNSIGNED_PROCESS should be INFO, got %s", f.Severity)
			}
			infoUnsigned++
		case "UNVERIFIED_SIGNATURE":
			unverified++
		case "UNSIGNED_SUMMARY":
			summary++
		}
	}
	if high != 2 {
		t.Errorf("want 2 HIGH untrusted findings (HashMismatch + NotTrusted), got %d", high)
	}
	if infoUnsigned != 1 {
		t.Errorf("want 1 INFO unsigned finding (only the NotSigned proc), got %d", infoUnsigned)
	}
	if unverified != 1 {
		t.Errorf("want 1 UNVERIFIED_SIGNATURE finding (UnknownError is not 'unsigned'), got %d", unverified)
	}
	if summary != 1 {
		t.Errorf("want 1 unsigned summary finding, got %d", summary)
	}

	// A clean set (all Valid / unreadable) must produce no findings at all.
	if clean := signingFindings([]procRow{
		{PID: 1, Name: "a.exe", Status: "Valid"},
		{PID: 2, Name: "b.exe", Status: ""},
	}); len(clean) != 0 {
		t.Errorf("clean set should produce no findings, got %d", len(clean))
	}

	// The per-finding listing cap holds and the summary still counts every one.
	many := make([]procRow, 30)
	for i := range many {
		many[i] = procRow{PID: int32(i + 100), Name: "u.exe", ExePath: `C:\x\u.exe`, Status: "NotSigned"}
	}
	listed, summaries := 0, 0
	for _, f := range signingFindings(many) {
		switch f.Category {
		case "UNSIGNED_PROCESS":
			listed++
		case "UNSIGNED_SUMMARY":
			if !strings.Contains(f.Description, "30") {
				t.Errorf("summary should count all 30 unsigned, got %q", f.Description)
			}
			summaries++
		}
	}
	if listed != 20 {
		t.Errorf("listing should be capped at 20, got %d", listed)
	}
	if summaries != 1 {
		t.Errorf("want exactly one summary, got %d", summaries)
	}
}
