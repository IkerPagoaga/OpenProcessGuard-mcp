package tools

import (
	"strings"
	"testing"
)

func TestSanitiseString_Caps(t *testing.T) {
	long := strings.Repeat("A", 1000)
	if got := len([]rune(sanitiseString(long, maxFieldLen))); got != maxFieldLen {
		t.Errorf("default cap: got %d runes, want %d", got, maxFieldLen)
	}
	if got := len([]rune(sanitiseString(long, maxForensicFieldLen))); got != 1000 {
		t.Errorf("forensic cap must not truncate 1000 runes, got %d", got)
	}
}

func TestSanitiseString_StripsControl(t *testing.T) {
	// NUL and BEL dropped; tab preserved.
	if got := sanitiseString("a\x00b\x07c\td", maxFieldLen); got != "abc\td" {
		t.Errorf("control-char stripping wrong: %q", got)
	}
}

// TestSanitiseJSON_ForensicCarveOutAndHTML proves the two #12 fixes together:
// a forensic field is not truncated, a normal field is, and HTML is not escaped.
func TestSanitiseJSON_ForensicCarveOutAndHTML(t *testing.T) {
	longCmd := strings.Repeat("A", 1000)
	longName := strings.Repeat("B", 1000)
	raw := `{"command_line":"<script>` + longCmd + `","name":"` + longName + `"}`

	out := sanitiseJSON(raw)

	if !strings.Contains(out, "<script>") {
		t.Errorf("HTML should render literally: %q", out)
	}
	if strings.Contains(out, "\\u003c") {
		t.Errorf("< must not be HTML-escaped to \\u003c: %q", out)
	}
	if !strings.Contains(out, longCmd) {
		t.Error("forensic command_line must not be truncated")
	}
	if strings.Contains(out, longName) {
		t.Error("non-forensic field should be truncated to the default cap")
	}
}
