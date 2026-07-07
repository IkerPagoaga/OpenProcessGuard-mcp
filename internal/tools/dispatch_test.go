package tools

import (
	"encoding/json"
	"testing"
)

// TestDispatchPID locks the PID bounds validation: only a positive PID within
// range reaches the handler; junk or out-of-range input is rejected before any
// OS call is made.
func TestDispatchPID(t *testing.T) {
	var gotPID int
	stub := func(pid int) (string, error) { gotPID = pid; return "ok", nil }

	cases := []struct {
		args    string
		wantErr bool
		wantPID int
	}{
		{`{"pid":1234}`, false, 1234},
		{`{"pid":1}`, false, 1},
		{`{"pid":4194304}`, false, 4194304},
		{`{"pid":0}`, true, 0},
		{`{"pid":-5}`, true, 0},
		{`{"pid":4194305}`, true, 0}, // above the max
		{`{"pid":"notanint"}`, true, 0},
		{`not json`, true, 0},
	}
	for _, c := range cases {
		gotPID = 0
		out, err := dispatchPID(json.RawMessage(c.args), stub)
		if c.wantErr {
			if err == nil {
				t.Errorf("dispatchPID(%s) expected error, got nil (out=%q)", c.args, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("dispatchPID(%s) unexpected error: %v", c.args, err)
		}
		if gotPID != c.wantPID {
			t.Errorf("dispatchPID(%s) handler got pid %d, want %d", c.args, gotPID, c.wantPID)
		}
	}
}

// TestSinceArg locks the clamp behavior shared by get_process_create_events /
// get_network_events (and now query_sysmon_events): out-of-range input degrades
// to a sane window instead of erroring.
func TestSinceArg(t *testing.T) {
	cases := []struct {
		args string
		want int
	}{
		{`{"since_minutes":30}`, 30},
		{`{"since_minutes":1440}`, 1440},
		{`{"since_minutes":0}`, 60},        // zero -> default
		{`{"since_minutes":-10}`, 60},      // negative -> default
		{`{"since_minutes":100000}`, 1440}, // above max -> clamp
		{`{}`, 60},                         // missing -> default
		{`not json`, 60},                   // unparseable -> default
	}
	for _, c := range cases {
		if got := sinceArg(json.RawMessage(c.args)); got != c.want {
			t.Errorf("sinceArg(%s) = %d, want %d", c.args, got, c.want)
		}
	}
}

// TestSafeAuditArgs locks credential redaction in the audit log: any key that
// looks like a credential is replaced with [REDACTED]; other args pass through,
// and nil / empty input returns nil rather than panicking.
func TestSafeAuditArgs(t *testing.T) {
	got := safeAuditArgs("lookup_hash",
		json.RawMessage(`{"vt_api_key":"SEKRET","sha256":"abc","password":"p","normal":"v"}`))
	if got["vt_api_key"] != "[REDACTED]" {
		t.Errorf("vt_api_key should be redacted, got %v", got["vt_api_key"])
	}
	if got["password"] != "[REDACTED]" {
		t.Errorf("password should be redacted, got %v", got["password"])
	}
	if got["sha256"] != "abc" {
		t.Errorf("sha256 should pass through, got %v", got["sha256"])
	}
	if got["normal"] != "v" {
		t.Errorf("normal should pass through, got %v", got["normal"])
	}
	if safeAuditArgs("x", nil) != nil {
		t.Error("nil args should return nil")
	}
	if safeAuditArgs("x", json.RawMessage(`{}`)) != nil {
		t.Error("empty object should return nil")
	}
}
