package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestNegotiateProtocolVersion pins the negotiation rule. Echoing the client's string
// unchecked made the server assert support for revisions it had never implemented —
// observed live returning "2099-01-01" and reflecting arbitrary text.
func TestNegotiateProtocolVersion(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		want      string
	}{
		{"supported newest is echoed", "2025-11-25", "2025-11-25"},
		{"supported older is echoed", "2024-11-05", "2024-11-05"},
		{"supported middle is echoed", "2025-06-18", "2025-06-18"},
		{"absent falls back to newest", "", defaultProtocolVersion},
		{"future/unknown falls back", "2099-01-01", defaultProtocolVersion},
		{"garbage falls back", "NOT-A-VERSION-<script>", defaultProtocolVersion},
		{"near-miss falls back", "2025-11-24", defaultProtocolVersion},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := negotiateProtocolVersion(tc.requested); got != tc.want {
				t.Errorf("negotiateProtocolVersion(%q) = %q, want %q", tc.requested, got, tc.want)
			}
		})
	}
}

// TestDefaultProtocolVersionIsSupported guards against the constant drifting away from
// the list — answering with a version absent from supportedProtocolVersions would
// reintroduce exactly the "claims what it cannot serve" defect.
func TestDefaultProtocolVersionIsSupported(t *testing.T) {
	for _, v := range supportedProtocolVersions {
		if v == defaultProtocolVersion {
			if supportedProtocolVersions[0] != defaultProtocolVersion {
				t.Errorf("defaultProtocolVersion %q is supported but not the newest entry (%q)",
					defaultProtocolVersion, supportedProtocolVersions[0])
			}
			return
		}
	}
	t.Errorf("defaultProtocolVersion %q is not in supportedProtocolVersions %v",
		defaultProtocolVersion, supportedProtocolVersions)
}

// TestResponseIDRoundTrip is the reason Response.ID is json.RawMessage: decoding ids
// through interface{} routes every number via float64, which rewrites values beyond
// 2^53. JSON-RPC requires the response id to EQUAL the request id.
func TestResponseIDRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"small integer", `1`},
		{"beyond 2^53", `9007199254740993`},
		{"very large integer", `123456789012345678901234567890`},
		{"string id", `"req-abc-123"`},
		{"zero", `0`},
		{"negative", `-42`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var in bytes.Buffer
			in.WriteString(`{"jsonrpc":"2.0","id":` + tc.id + `,"method":"ping"}` + "\n")

			var out bytes.Buffer
			if err := serve(nil, &in, &out); err != nil {
				t.Fatalf("serve error: %v", err)
			}

			line := strings.TrimSpace(out.String())
			if line == "" {
				t.Fatal("no response written")
			}
			var resp struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				t.Fatalf("undecodable response %q: %v", line, err)
			}
			if got := string(resp.ID); got != tc.id {
				t.Errorf("response id = %s, want %s (byte-identical)", got, tc.id)
			}
		})
	}
}

// TestParseErrorResponseHasNullID pins the spec behaviour for an unparseable request:
// a nil json.RawMessage must marshal to `null`, not be omitted.
func TestParseErrorResponseHasNullID(t *testing.T) {
	var in bytes.Buffer
	in.WriteString("{not json at all\n")

	var out bytes.Buffer
	if err := serve(nil, &in, &out); err != nil {
		t.Fatalf("serve error: %v", err)
	}
	line := strings.TrimSpace(out.String())
	if !strings.Contains(line, `"id":null`) {
		t.Errorf("parse-error response missing an explicit null id: %s", line)
	}
}
