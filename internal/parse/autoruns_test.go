package parse

import "testing"

func TestAutorunsCSV_QuotingAndColumns(t *testing.T) {
	// Header carries a Signer column; the description field embeds an escaped
	// quote ("") which the old hand-rolled splitter would have mangled.
	const raw = `Time,Entry Location,Entry,Enabled,Category,Description,Signer,Company,Image Path,Version,Launch String,VT detection
,HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,Foo,enabled,Logon,"A ""quoted"" desc",(Verified) Acme Corp,Acme Inc,C:\Program Files\foo.exe,1.0,"C:\Program Files\foo.exe -x",0/72`

	rows, err := AutorunsCSV(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.Description != `A "quoted" desc` {
		t.Errorf("escaped-quote description mangled: %q", r.Description)
	}
	if !r.SignerKnown || r.Signer != "(Verified) Acme Corp" {
		t.Errorf("signer parsed wrong: known=%v signer=%q", r.SignerKnown, r.Signer)
	}
	if r.LaunchString != `C:\Program Files\foo.exe -x` {
		t.Errorf("launch string with embedded comma mishandled: %q", r.LaunchString)
	}
	if !r.VTKnown || r.VTDetections != 0 || r.VTTotal != 72 {
		t.Errorf("VT score parsed wrong: %+v", r)
	}
}

// TestAutorunsCSV_MissingSignerColumn proves an absent Signer column yields
// SignerKnown=false, so callers do NOT flag every entry as UNSIGNED.
func TestAutorunsCSV_MissingSignerColumn(t *testing.T) {
	const raw = `Entry Location,Entry,Image Path
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,Bar,C:\bar.exe`

	rows, err := AutorunsCSV(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].SignerKnown {
		t.Errorf("missing Signer column must yield SignerKnown=false, got true")
	}
}

func TestParseVTScore(t *testing.T) {
	cases := []struct {
		in         string
		det, total int
		ok         bool
	}{
		{"5/72", 5, 72, true},
		{" 0 / 72 ", 0, 72, true},
		{"5-72", 0, 0, false}, // wrong separator must not silently become 0/0
		{"", 0, 0, false},
		{"n/a", 0, 0, false},
	}
	for _, c := range cases {
		det, total, ok := ParseVTScore(c.in)
		if det != c.det || total != c.total || ok != c.ok {
			t.Errorf("ParseVTScore(%q) = (%d,%d,%v), want (%d,%d,%v)", c.in, det, total, ok, c.det, c.total, c.ok)
		}
	}
}
