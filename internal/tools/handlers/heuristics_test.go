package handlers

import "testing"

// TestNameSpoofMatch locks in the fix for the substring bug that flagged the
// legitimate Windows shell (explorer.exe contains "explore") as NAME_SPOOF on
// every machine. Matching is now exact against the base name.
func TestNameSpoofMatch(t *testing.T) {
	cases := []struct {
		name      string // already lower-cased, as the caller passes it
		wantMatch bool
		wantPat   string
	}{
		// Legitimate processes must NOT be flagged.
		{"explorer.exe", false, ""},
		{"iexplore.exe", false, ""},
		{"svchost.exe", false, ""},
		{"lsass.exe", false, ""},
		{"csrss.exe", false, ""},
		{"lsass5.exe", false, ""}, // "lsas5" is the pattern, not "lsass5"
		{"", false, ""},
		// Known lookalikes must be flagged, exactly.
		{"svch0st.exe", true, "svch0st"},
		{"explrer.exe", true, "explrer"},
		{"lsas5.exe", true, "lsas5"},
		{"explore.exe", true, "explore"}, // no legitimate explore.exe exists
		{"svchost32.exe", true, "svchost32"},
		{"smss32.exe", true, "smss32"},
	}
	for _, c := range cases {
		pat, ok := nameSpoofMatch(c.name)
		if ok != c.wantMatch {
			t.Errorf("nameSpoofMatch(%q) matched=%v, want %v", c.name, ok, c.wantMatch)
		}
		if ok && pat != c.wantPat {
			t.Errorf("nameSpoofMatch(%q) pattern=%q, want %q", c.name, pat, c.wantPat)
		}
	}
}

// TestMasqueradeMatch locks in that FlagMasquerade (the Stage-1 CRITICAL) is now
// reachable AND does not false-fire: a CORE system-process name from a temp/
// user-writable dir is a masquerade; an empty path (SYSTEM process seen without
// elevation) is NOT; a legitimate System32 path is NOT; and dual-use binaries
// (cmd/powershell) from temp are NOT escalated to CRITICAL here.
func TestMasqueradeMatch(t *testing.T) {
	cases := []struct {
		name     string
		exeLower string // caller passes an already-lower-cased path
		want     bool
	}{
		{"svchost.exe", `c:\users\bob\appdata\local\temp\svchost.exe`, true},
		{"lsass.exe", `c:\temp\lsass.exe`, true},
		{"svchost.exe", `c:\windows\system32\svchost.exe`, false}, // legit location
		{"lsass.exe", "", false},                                  // empty path must NOT fire (non-elevated FP)
		{"cmd.exe", `c:\temp\cmd.exe`, false},                     // dual-use — not CRITICAL here
		{"powershell.exe", `c:\users\x\appdata\local\temp\powershell.exe`, false},
		{"notepad.exe", `c:\temp\notepad.exe`, false}, // not a system-process name
		{"explorer.exe", `c:\windows\explorer.exe`, false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := masqueradeMatch(c.name, c.exeLower); got != c.want {
			t.Errorf("masqueradeMatch(%q, %q) = %v, want %v", c.name, c.exeLower, got, c.want)
		}
	}
}
