package parse

import "testing"

// TestSysmonFields proves the XML parser unescapes entities and does NOT truncate
// a value that itself contains markup-like text ("</Data>") — the exact case the
// previous string-scanning extractor mishandled, hiding command-line evidence.
func TestSysmonFields(t *testing.T) {
	const xml = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>` +
		`<System><TimeCreated SystemTime='2026-07-02T10:00:00.000Z'/></System>` +
		`<EventData>` +
		`<Data Name='Image'>C:\Windows\System32\cmd.exe</Data>` +
		`<Data Name='CommandLine'>cmd /c echo &lt;/Data&gt; &amp; whoami</Data>` +
		`<Data Name='ProcessId'>4242</Data>` +
		`</EventData></Event>`

	ts, fields, ok := SysmonFields(xml)
	if !ok {
		t.Fatal("expected ok=true for valid Sysmon XML")
	}
	if ts != "2026-07-02T10:00:00.000Z" {
		t.Errorf("timestamp = %q", ts)
	}
	if fields["Image"] != `C:\Windows\System32\cmd.exe` {
		t.Errorf("Image = %q", fields["Image"])
	}
	// Fully unescaped AND not truncated at the embedded </Data>.
	if want := `cmd /c echo </Data> & whoami`; fields["CommandLine"] != want {
		t.Errorf("CommandLine = %q, want %q", fields["CommandLine"], want)
	}
	if fields["ProcessId"] != "4242" {
		t.Errorf("ProcessId = %q", fields["ProcessId"])
	}
}

func TestSysmonFields_Malformed(t *testing.T) {
	if _, _, ok := SysmonFields("not xml at all"); ok {
		t.Error("expected ok=false for non-XML input")
	}
}
