package handlers

import "testing"

// TestSigningFromSigner locks in the autorunsc verdict fix: "(Not verified) X"
// must be treated as unverified (it was previously marked verified because the
// check compared for equality against the bare "(Not verified)" string), and a
// "Microsoft" publisher is trusted only when the entry is actually verified.
func TestSigningFromSigner(t *testing.T) {
	cases := []struct {
		signer       string
		wantVerified bool
		wantMS       bool
	}{
		{"(Verified) Microsoft Windows", true, true},
		{"(Verified) Google LLC", true, false},
		{"(Not verified) Acme Malware Inc", false, false},      // the regression case
		{"(Not verified) Microsoft Corporation", false, false}, // spoofed publisher — not trusted
		{"(Not verified)", false, false},
		{"(verified) lower-case prefix", true, false}, // case-insensitive
		{"", false, false},
	}
	for _, c := range cases {
		v, ms := signingFromSigner(c.signer)
		if v != c.wantVerified || ms != c.wantMS {
			t.Errorf("signingFromSigner(%q) = (verified=%v, microsoft=%v), want (%v, %v)",
				c.signer, v, ms, c.wantVerified, c.wantMS)
		}
	}
}

// TestSigningFromStatus locks in that an invalid or self-signed certificate that
// merely names Microsoft does not evade get_unsigned_processes — trust requires a
// Valid Authenticode status.
func TestSigningFromStatus(t *testing.T) {
	cases := []struct {
		status       string
		subject      string
		wantVerified bool
		wantMS       bool
	}{
		{"Valid", "CN=Microsoft Windows, O=Microsoft Corporation", true, true},
		{"Valid", "CN=Google LLC", true, false},
		{"HashMismatch", "CN=Microsoft Corporation", false, false}, // the bypass case
		{"NotSigned", "", false, false},
		{"UnknownError", "CN=microsoft evil", false, false},
	}
	for _, c := range cases {
		v, ms := signingFromStatus(c.status, c.subject)
		if v != c.wantVerified || ms != c.wantMS {
			t.Errorf("signingFromStatus(%q, %q) = (verified=%v, microsoft=%v), want (%v, %v)",
				c.status, c.subject, v, ms, c.wantVerified, c.wantMS)
		}
	}
}

// TestClassifyUnsigned locks in that an un-evaluated signature (empty status —
// an unreadable SYSTEM binary on a non-elevated run) is treated as UNKNOWN and
// excluded from the unsigned list, not mislabeled "no digital signature". A
// definitive negative (NotSigned/HashMismatch/NotTrusted) is still listed.
func TestClassifyUnsigned(t *testing.T) {
	cases := []struct {
		status   string
		wantList bool
	}{
		{"Valid", false},
		{"", false}, // not evaluated — the non-elevated storm case
		{"NotSigned", true},
		{"HashMismatch", true},
		{"NotTrusted", true},
		{"UnknownError", true},
	}
	for _, c := range cases {
		list, reason := classifyUnsigned(c.status)
		if list != c.wantList {
			t.Errorf("classifyUnsigned(%q) list=%v, want %v", c.status, list, c.wantList)
		}
		if list && reason == "" {
			t.Errorf("classifyUnsigned(%q) listed but empty reason", c.status)
		}
		if !list && reason != "" {
			t.Errorf("classifyUnsigned(%q) not listed but non-empty reason %q", c.status, reason)
		}
	}
}
