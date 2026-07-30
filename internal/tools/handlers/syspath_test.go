package handlers

import (
	"strings"
	"testing"
)

// TestDllhostFromSysWOW64IsNotFlagged is the v2.5.1 regression test. The 32-bit COM
// surrogate at C:\Windows\SysWOW64\dllhost.exe is Microsoft-signed and runs routinely,
// yet it produced the ONLY HIGH finding on a clean machine. A false HIGH is worse than
// a missed one: it teaches the operator to discount the severity that exists to demand
// attention.
func TestDllhostFromSysWOW64IsNotFlagged(t *testing.T) {
	if wrongSystemPath("dllhost.exe", `c:\windows\syswow64\dllhost.exe`) {
		t.Error("legitimate 32-bit dllhost.exe in SysWOW64 flagged as WRONG_PATH")
	}
	if wrongSystemPath("dllhost.exe", `c:\windows\system32\dllhost.exe`) {
		t.Error("legitimate 64-bit dllhost.exe in System32 flagged as WRONG_PATH")
	}
	// The check must still catch a genuine impostor.
	if !wrongSystemPath("dllhost.exe", `c:\users\bob\appdata\local\temp\dllhost.exe`) {
		t.Error("dllhost.exe from a temp directory was NOT flagged")
	}
}

// TestWow64ProcessesAcceptSysWOW64 keeps the map honest against its own documented
// expectation, so a future edit cannot quietly drop a `\syswow64\` entry and resurrect
// the dllhost-class false positive for a different binary.
func TestWow64ProcessesAcceptSysWOW64(t *testing.T) {
	for _, name := range wow64SystemProcesses {
		if _, known := systemProcessPaths[name]; !known {
			t.Errorf("%s is listed as WOW64-capable but is absent from systemProcessPaths", name)
			continue
		}
		path := `c:\windows\syswow64\` + name
		if name == "powershell.exe" {
			path = `c:\windows\syswow64\windowspowershell\v1.0\powershell.exe`
		}
		if wrongSystemPath(name, path) {
			t.Errorf("%s at %s flagged as WRONG_PATH, but a signed 32-bit variant ships there", name, path)
		}
	}
}

// TestSystem32OnlyProcessesRejectSysWOW64 is the other half: processes with no genuine
// 32-bit variant must STILL be flagged when found under SysWOW64, or the fix above
// would have blunted a real detection.
func TestSystem32OnlyProcessesRejectSysWOW64(t *testing.T) {
	wow64 := map[string]bool{}
	for _, n := range wow64SystemProcesses {
		wow64[n] = true
	}
	// lsass/csrss/wininit/winlogon/services/smss have no SysWOW64 image on real Windows
	// (verified against a live install), so one appearing there is a genuine red flag.
	for _, name := range []string{"lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "smss.exe"} {
		if wow64[name] {
			t.Fatalf("test premise broken: %s is marked WOW64-capable", name)
		}
		if !wrongSystemPath(name, `c:\windows\syswow64\`+name) {
			t.Errorf("%s under SysWOW64 was NOT flagged, but it has no legitimate 32-bit variant", name)
		}
	}
}

// TestWrongSystemPathIgnoresUnknownAndEmpty pins the two non-suspicious cases: an
// unknown binary, and a SYSTEM process whose path is unreadable to a non-elevated host.
// Flagging either would false-fire on every healthy machine.
func TestWrongSystemPathIgnoresUnknownAndEmpty(t *testing.T) {
	if wrongSystemPath("notepad.exe", `c:\users\bob\appdata\local\temp\notepad.exe`) {
		t.Error("an unknown process name was treated as a known system process")
	}
	if wrongSystemPath("lsass.exe", "") {
		t.Error("an unreadable image path was flagged; this false-fires when running non-elevated")
	}
}

// TestSystemProcessPathFragmentsAreLowercaseAndAnchored guards the matching contract:
// comparison is a lowercase substring test, so an uppercase or unslashed fragment would
// silently never match and disable the check for that process.
func TestSystemProcessPathFragmentsAreLowercaseAndAnchored(t *testing.T) {
	for name, fragments := range systemProcessPaths {
		if name != strings.ToLower(name) {
			t.Errorf("map key %q is not lowercase; lookup uses a lowercased name", name)
		}
		for _, f := range fragments {
			if f != strings.ToLower(f) {
				t.Errorf("%s: fragment %q is not lowercase and can never match", name, f)
			}
			if !strings.HasPrefix(f, `\`) || !strings.HasSuffix(f, `\`) {
				t.Errorf("%s: fragment %q must be slash-delimited so it matches a whole directory", name, f)
			}
		}
	}
}
