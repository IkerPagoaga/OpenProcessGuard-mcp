package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"
	"unicode"

	"processguard-mcp/internal/audit"
	"processguard-mcp/internal/config"
	"processguard-mcp/internal/tools/handlers"
)

// ── Output sanitisation ──────────────────────────────────────────────────────
//
// ProcessGuard returns data sourced from the live OS — process names, command
// lines, registry paths, file paths, network addresses. An adversary can craft
// process names or command lines that look like LLM instructions (prompt
// injection). The functions below sanitise every string before it leaves the
// MCP boundary.
//
// Rules:
//   1. Truncate any single string field to maxFieldLen runes.
//   2. Strip ASCII control characters (< 0x20, 0x7F) except tab and newline.
//   3. Normalise Unicode to printable form — replace non-printable runes with '?'.
//
// These transforms are applied to the final JSON blob returned by every tool,
// so no individual handler needs to worry about it.

const (
	maxFieldLen = 512 // default cap: runes per string value in a tool response

	// maxForensicFieldLen is the cap for evidence-bearing fields. The whole
	// point of the tool is to surface these — a full command line, a hash set,
	// a Sysmon XML blob — so truncating them to 512 runes would cut off exactly
	// the data an analyst needs.
	maxForensicFieldLen = 16384
)

// forensicKeys are output field names (lower-cased) that carry forensic evidence
// and therefore get the larger cap instead of the default 512.
var forensicKeys = map[string]bool{
	"command_line": true, "cmdline": true, "hashes": true, "sha256": true,
	"raw_xml": true, "xml": true, "path": true, "exe_path": true,
	"image": true, "image_path": true, "image_loaded": true,
	"launch_string": true, "parent_image": true, "permalink": true,
}

// sanitiseOutput walks every string in a JSON-decoded interface{} tree and
// applies the sanitisation rules above under a per-field length cap. A map value
// under a forensic key (and any nested value beneath it) gets the larger cap.
func sanitiseOutput(v interface{}, maxLen int) interface{} {
	switch t := v.(type) {
	case string:
		return sanitiseString(t, maxLen)
	case []interface{}:
		for i, item := range t {
			t[i] = sanitiseOutput(item, maxLen)
		}
		return t
	case map[string]interface{}:
		for k, val := range t {
			childMax := maxLen
			if forensicKeys[strings.ToLower(k)] {
				childMax = maxForensicFieldLen
			}
			t[k] = sanitiseOutput(val, childMax)
		}
		return t
	}
	return v
}

func sanitiseString(s string, maxLen int) string {
	runes := []rune(s)

	// Truncate
	if maxLen > 0 && len(runes) > maxLen {
		runes = runes[:maxLen]
	}

	// Strip non-printable characters
	var b strings.Builder
	b.Grow(len(runes))
	for _, r := range runes {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7F:
			// ASCII control — drop silently
		case !unicode.IsPrint(r):
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SanitiseText makes an arbitrary string — e.g. an error message assembled
// outside the normal tool-output path — safe to hand to the model: ASCII control
// characters stripped, non-printable runes replaced, length-capped. main.go uses
// it so isError content passes the same boundary as regular tool output.
func SanitiseText(s string) string {
	return sanitiseString(s, maxFieldLen)
}

// sanitiseJSON deserialises a JSON string, sanitises every string value in
// the resulting tree, then re-serialises it. HTML escaping is disabled so that
// forensic values containing <, >, or & render literally instead of as <
// noise. Returns the original string on any parse error (handlers already
// return valid JSON).
func sanitiseJSON(raw string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		// Not JSON — apply plain string sanitisation
		return sanitiseString(raw, maxFieldLen)
	}
	clean := sanitiseOutput(v, maxFieldLen)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(clean); err != nil {
		return sanitiseString(raw, maxFieldLen)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// MaxToolOutputBytes bounds a single tool response. It is a context-window guard, not
// a working limit: every tool with a natural size now defaults to a bounded slice, so
// reaching this means the caller explicitly asked for something very large.
const MaxToolOutputBytes = 256 * 1024

// narrowingHints tell the model HOW to ask a smaller question, per tool. A refusal
// without a lever is just a dead end; naming the specific argument turns the budget
// into guidance the model can act on immediately.
var narrowingHints = map[string]string{
	"list_processes":            "narrow with name_filter or min_memory_mb, or lower limit",
	"get_process_detail":        "this process has an unusually large environment or command line; inspect a different PID",
	"get_loaded_modules":        "this process has an unusually large module list; use get_suspicious_processes first to pick a narrower target",
	"get_network_connections":   "use get_established_connections or get_foreign_connections for a focused view",
	"get_autoruns_entries":      "use flag_autoruns_anomalies, which returns only the high-risk subset",
	"flag_autoruns_anomalies":   "an unusually large number of entries were flagged; review get_autoruns_entries in sections",
	"query_sysmon_events":       "lower since_minutes or max_events",
	"get_process_create_events": "lower since_minutes or max_events",
	"get_network_events":        "lower since_minutes or max_events",
	"run_full_hunt":             "run the individual stage tools instead (get_suspicious_processes, get_unsigned_processes, get_foreign_connections)",
}

// ── Tool registry ─────────────────────────────────────────────────────────────

type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema interface{}     `json:"inputSchema"`
	Annotations ToolAnnotations `json:"annotations"`
}

// ToolAnnotations carries the MCP behaviour hints. This is the MACHINE-READABLE form of
// the read-only guarantee the project asserts in prose across README, SECURITY,
// ARCHITECTURE, LIMITATIONS and CONTRIBUTING: a client can enforce an annotation, but it
// cannot enforce a paragraph.
//
// destructiveHint and idempotentHint are deliberately absent. The MCP spec defines both
// as meaningful only when readOnlyHint is false, and every tool here is read-only —
// emitting them would add noise that says nothing.
type ToolAnnotations struct {
	ReadOnlyHint  bool `json:"readOnlyHint"`
	OpenWorldHint bool `json:"openWorldHint"`
}

// openWorldTools names the tools that reach beyond the local machine. Everything else
// is pure local inspection, which is what openWorldHint:false asserts.
var openWorldTools = map[string]bool{
	"lookup_hash": true, // queries the VirusTotal API over the network
}

// Registry returns all tools Claude can call.
func Registry() []ToolDef {
	tools := []ToolDef{
		// ── Stage 0: Native process enumeration (always available) ──────────
		{
			Name:        "list_processes",
			Description: "List running processes with PID, name, parent PID, CPU% (cumulative average over the process's lifetime, not an instantaneous sample), memory usage, executable path, and current user. Use this as the starting point for any security analysis. Prefer name_filter/min_memory_mb over listing everything — the full table is large.",
			InputSchema: listProcessSchema(),
		},
		{
			Name:        "get_process_detail",
			Description: "Get deep detail on a single process: full command line, working directory, environment variables (all names listed; values shown only for an allowlist of non-sensitive names, everything else [REDACTED]), open kernel-handle count (omitted when unreadable), and thread count.",
			InputSchema: pidSchema(),
		},
		{
			Name:        "get_network_connections",
			Description: "List all active TCP/UDP network connections with remote addresses, ports, and associated process names. Use get_established_connections for a focused view.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_loaded_modules",
			Description: "List DLLs and modules loaded by a specific process, as reported by the Windows loader. Use this to spot unexpected libraries in trusted system processes and modules running from temp paths. NOTE: this reads the loader's module list, so reflectively/manually mapped DLLs do not appear.",
			InputSchema: pidSchema(),
		},
		{
			Name:        "get_suspicious_processes",
			Description: "Run automated heuristic checks across all processes: name spoofing, wrong-path system processes, unsigned binaries in temp folders, unusual parent-child relationships.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_startup_entries",
			Description: "List programs configured to run at startup via registry Run keys and common startup folders. Use get_autoruns_entries for a more comprehensive persistence check.",
			InputSchema: emptySchema(),
		},

		// ── Stage 1: Signing (built-in Authenticode) ─────────────────────────
		{
			Name:        "get_process_tree",
			Description: "Return the full parent-child process tree with Authenticode signing status. Uses Windows Get-AuthenticodeSignature directly — no external Sysinternals tools required.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_unsigned_processes",
			Description: "Return all running processes whose Authenticode signature is absent or untrusted — a primary malware indicator in system paths. No external Sysinternals tools required.",
			InputSchema: emptySchema(),
		},

		// ── Stage 2: Autoruns ─────────────────────────────────────────────────
		{
			Name:        "get_autoruns_entries",
			Description: "Run autorunsc.exe and return ALL persistence entry points: registry Run/RunOnce keys, Scheduled Tasks, Services, Drivers, Browser Helper Objects, Codecs, and more. Requires autoruns_path in config.json.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "flag_autoruns_anomalies",
			Description: "Return only high-risk autorun entries: unsigned binaries, entries in temp/downloads paths, and entries with VirusTotal detections. Requires autoruns_path.",
			InputSchema: emptySchema(),
		},

		// ── Stage 3: Network ──────────────────────────────────────────────────
		{
			Name:        "get_established_connections",
			Description: "Return only ESTABLISHED TCP connections with process names and optional GeoIP context. Filters out LISTENING/TIME_WAIT noise. Critical for detecting active C2 channels.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_foreign_connections",
			Description: "Return ESTABLISHED connections to non-private (internet) IP addresses, with GeoIP country data when geoip_db is configured. These are your primary data-exfiltration and C2 candidates.",
			InputSchema: emptySchema(),
		},

		// ── Stage 4: Sysmon ───────────────────────────────────────────────────
		{
			Name:        "query_sysmon_events",
			Description: "Query the Sysmon Windows Event Log for a specific event ID within the last N minutes. Event IDs: 1=ProcessCreate, 3=NetworkConnect, 7=ImageLoaded, 11=FileCreate. Requires Sysmon service.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"event_id": map[string]interface{}{
						"type":        "integer",
						"description": "Sysmon event ID (1=ProcessCreate, 3=NetworkConnect, 7=ImageLoaded, 11=FileCreate)",
						"minimum":     1,
						"maximum":     255,
					},
					"since_minutes": map[string]interface{}{
						"type":        "integer",
						"description": "How far back to query (default 60, max 1440)",
						"default":     60,
						"minimum":     1,
						"maximum":     1440,
					},
					"max_events": maxEventsSchemaProp(),
				},
				"required": []string{"event_id"},
			},
		},
		{
			Name:        "get_process_create_events",
			Description: "Return Sysmon Event ID 1 (ProcessCreate) records for the last N minutes. Includes command line, parent image, user, and hashes. Use for forensic timeline reconstruction.",
			InputSchema: sinceSchema(),
		},
		{
			Name:        "get_network_events",
			Description: "Return Sysmon Event ID 3 (NetworkConnect) records for the last N minutes. Captures outbound connections at the time they were made — invaluable for detecting C2 beacons.",
			InputSchema: sinceSchema(),
		},

		// ── Stage 5: VirusTotal ───────────────────────────────────────────────
		{
			Name:        "lookup_hash",
			Description: "Look up a SHA256 file hash on VirusTotal and return the detection score (e.g. '5/72'). Results are cached in-memory for 24 hours (cleared on restart). Requires vt_api_key in config.json.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sha256": map[string]interface{}{
						"type":        "string",
						"description": "SHA256 hash of the file to look up (64 hex characters)",
					},
				},
				"required": []string{"sha256"},
			},
		},

		// ── Orchestration ─────────────────────────────────────────────────────
		{
			Name:        "run_full_hunt",
			Description: "Execute the complete 5-stage threat hunt (Process Integrity + Authenticode signing → Persistence → Network → Sysmon → VirusTotal) and return a structured HuntReport with severity-ranked findings and recommended actions. This is the primary entry point for a full security audit.",
			InputSchema: emptySchema(),
		},
	}

	// EVERY ProcessGuard tool is read-only — that is the product's core guarantee, and
	// CONTRIBUTING forbids any PR that adds a tool which modifies the system. Applying
	// the annotation centrally rather than per-literal means a newly added tool cannot
	// forget it, and makes the single open-world exception explicit instead of implied.
	for i := range tools {
		tools[i].Annotations = ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: openWorldTools[tools[i].Name],
		}
	}
	return tools
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

// Call dispatches a tool call by name, sanitises the output, and records an
// audit log entry. The context is the serve-level lifetime context: cancelling
// it aborts the handler's child processes / HTTP calls mid-flight. A handler
// panic is converted to a generic error HERE, at the tool boundary: the full
// panic value + stack go to the operator's stderr log only (never the LLM
// context), and the audit write runs in a defer so the crashing invocation —
// exactly the one a forensics audit trail must not lose — is still recorded.
func Call(ctx context.Context, cfg *config.Config, name string, args json.RawMessage) (result string, err error) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			// Called during unwind, so debug.Stack() still includes the panic site.
			slog.Error("tool panicked", "tool", name, "panic", r, "stack", string(debug.Stack()))
			result, err = "", fmt.Errorf("tool %q failed with an internal error (details in the server log)", name)
		}
		audit.Log(name, safeAuditArgs(name, args), time.Since(start), err)
	}()
	result, err = callInner(ctx, cfg, name, args)
	if err != nil {
		return "", err
	}
	// Sanitise all string values before handing them to the LLM context.
	sanitised := sanitiseJSON(result)

	// Global response budget. The per-field caps (maxFieldLen / maxForensicFieldLen)
	// bound individual STRINGS, which is the wrong axis: a response of ten thousand
	// short fields passes every per-field check and still floods the context window,
	// leaving the model no room to reason about what it just read. Refusing with an
	// actionable hint is better than silently truncating — truncated JSON does not
	// parse, and a silently shortened list reads as a complete one.
	if len(sanitised) > MaxToolOutputBytes {
		hint, ok := narrowingHints[name]
		if !ok {
			hint = "request a narrower slice of this data"
		}
		return "", fmt.Errorf(
			"%s produced %d bytes, over the %d-byte response budget — %s",
			name, len(sanitised), MaxToolOutputBytes, hint)
	}
	return sanitised, nil
}

func callInner(ctx context.Context, cfg *config.Config, name string, args json.RawMessage) (string, error) {
	switch name {
	// Stage 0 — Native
	case "list_processes":
		return handlers.ListProcesses(listProcessQueryArg(args))
	case "get_process_detail":
		return dispatchPID(args, handlers.GetProcessDetail)
	case "get_network_connections":
		return handlers.GetNetworkConnections(ctx)
	case "get_loaded_modules":
		return dispatchPID(args, func(pid int) (string, error) {
			return handlers.GetLoadedModules(ctx, pid)
		})
	case "get_suspicious_processes":
		return handlers.GetSuspiciousProcesses()
	case "get_startup_entries":
		return handlers.GetStartupEntries(ctx)

	// Stage 1 — Signing (built-in Authenticode)
	case "get_process_tree":
		return handlers.GetProcessTree(ctx)
	case "get_unsigned_processes":
		return handlers.GetUnsignedProcesses(ctx)

	// Stage 2 — Autoruns
	case "get_autoruns_entries":
		return handlers.GetAutorunsEntries(ctx, cfg)
	case "flag_autoruns_anomalies":
		return handlers.FlagAutorunsAnomalies(ctx, cfg)

	// Stage 3 — Network
	case "get_established_connections":
		return handlers.GetEstablishedConnections(ctx, cfg)
	case "get_foreign_connections":
		return handlers.GetForeignConnections(ctx, cfg)

	// Stage 4 — Sysmon
	case "query_sysmon_events":
		var p struct {
			EventID      int `json:"event_id"`
			SinceMinutes int `json:"since_minutes"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
		if p.EventID < 1 || p.EventID > 255 {
			return "", fmt.Errorf("event_id must be between 1 and 255")
		}
		// Clamp out-of-range values to a sane window instead of erroring, so this
		// matches get_process_create_events / get_network_events (sinceArg): a
		// forensic query should degrade gracefully, not fail on a loose bound.
		if p.SinceMinutes <= 0 {
			p.SinceMinutes = 60
		} else if p.SinceMinutes > 1440 {
			p.SinceMinutes = 1440
		}
		return handlers.QuerySysmonEvents(ctx, cfg, p.EventID, p.SinceMinutes, maxEventsArg(args))

	case "get_process_create_events":
		return handlers.GetProcessCreateEvents(ctx, cfg, sinceArg(args), maxEventsArg(args))
	case "get_network_events":
		return handlers.GetNetworkEvents(ctx, cfg, sinceArg(args), maxEventsArg(args))

	// Stage 5 — VirusTotal
	case "lookup_hash":
		var p struct {
			SHA256 string `json:"sha256"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
		return handlers.LookupHash(ctx, cfg, p.SHA256)

	// Orchestration
	case "run_full_hunt":
		return handlers.RunFullHunt(ctx, cfg)

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// safeAuditArgs strips any arg field that might be a credential.
func safeAuditArgs(toolName string, args json.RawMessage) map[string]any {
	if len(args) == 0 || string(args) == "null" || string(args) == "{}" {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(args, &raw); err != nil {
		return nil
	}
	safe := make(map[string]any, len(raw))
	for k, v := range raw {
		if containsAnyKey(k, "key", "token", "secret", "password") {
			safe[k] = "[REDACTED]"
		} else {
			safe[k] = v
		}
	}
	return safe
}

func containsAnyKey(s string, subs ...string) bool {
	sl := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(sl, sub) {
			return true
		}
	}
	return false
}

// ── Input helpers ─────────────────────────────────────────────────────────────

func dispatchPID(args json.RawMessage, fn func(int) (string, error)) (string, error) {
	var p struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if p.PID <= 0 || p.PID > 4194304 {
		return "", fmt.Errorf("pid must be a positive integer (got %d)", p.PID)
	}
	return fn(p.PID)
}

func sinceArg(args json.RawMessage) int {
	var p struct {
		SinceMinutes int `json:"since_minutes"`
	}
	json.Unmarshal(args, &p)
	if p.SinceMinutes <= 0 {
		return 60
	}
	if p.SinceMinutes > 1440 {
		return 1440
	}
	return p.SinceMinutes
}

// listProcessQueryArg extracts the optional list_processes filters. Absent or invalid
// fields degrade to zero values, which the handler reads as "no constraint" (and, for
// limit, as "use the default") — same forgiving contract as sinceArg.
func listProcessQueryArg(args json.RawMessage) handlers.ListProcessQuery {
	var p struct {
		NameFilter  string  `json:"name_filter"`
		MinMemoryMB float64 `json:"min_memory_mb"`
		SortBy      string  `json:"sort_by"`
		Limit       int     `json:"limit"`
	}
	json.Unmarshal(args, &p)
	return handlers.ListProcessQuery{
		NameFilter:  p.NameFilter,
		MinMemoryMB: p.MinMemoryMB,
		SortBy:      p.SortBy,
		Limit:       p.Limit,
	}
}

// maxEventsArg extracts the optional max_events cap. Absent or invalid degrades to 0,
// which the handler reads as "use the default" — matching sinceArg's forgiving
// contract, since a forensic query should degrade gracefully rather than fail on a
// loose bound. The handler owns the hard ceiling; this never widens it.
func maxEventsArg(args json.RawMessage) int {
	var p struct {
		MaxEvents int `json:"max_events"`
	}
	json.Unmarshal(args, &p)
	return p.MaxEvents
}

// ── Schema helpers ────────────────────────────────────────────────────────────

// maxEventsSchemaProp is shared by every Sysmon-reading tool so the cap is described
// identically everywhere, and so the advertised bounds cannot drift from the constants
// the handler actually enforces.
func maxEventsSchemaProp() map[string]interface{} {
	return map[string]interface{}{
		"type": "integer",
		"description": fmt.Sprintf(
			"Maximum events to return (default %d, hard cap %d). Results are newest-first; "+
				"the response sets truncated=true when more events matched than were returned.",
			handlers.DefaultSysmonMaxEvents, handlers.MaxSysmonMaxEvents),
		"default": handlers.DefaultSysmonMaxEvents,
		"minimum": 1,
		"maximum": handlers.MaxSysmonMaxEvents,
	}
}

// listProcessSchema advertises the narrowing options for list_processes. Without these
// the model could only ask for everything, then read a ~100 KB table to answer a
// one-process question.
func listProcessSchema() interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name_filter": map[string]interface{}{
				"type":        "string",
				"description": `Case-insensitive substring matched against BOTH the process name and its executable path (e.g. "chrome", "\\temp\\").`,
			},
			"min_memory_mb": map[string]interface{}{
				"type":        "number",
				"description": "Only return processes using at least this much resident memory, in MB.",
				"minimum":     0,
			},
			"sort_by": map[string]interface{}{
				"type":        "string",
				"enum":        []string{"memory", "cpu", "pid", "name"},
				"default":     "memory",
				"description": "Sort order. Default is memory descending, so a truncated listing shows the largest processes first.",
			},
			"limit": map[string]interface{}{
				"type": "integer",
				"description": fmt.Sprintf(
					"Maximum processes to return (default %d, hard cap %d). The response always reports total_matched and truncated.",
					handlers.DefaultProcessLimit, handlers.MaxProcessLimit),
				"default": handlers.DefaultProcessLimit,
				"minimum": 1,
				"maximum": handlers.MaxProcessLimit,
			},
		},
	}
}

func emptySchema() interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

func pidSchema() interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"pid": map[string]interface{}{
				"type":        "integer",
				"description": "Process ID to inspect (must be a positive integer)",
				"minimum":     1,
				"maximum":     4194304,
			},
		},
		"required": []string{"pid"},
	}
}

func sinceSchema() interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"since_minutes": map[string]interface{}{
				"type":        "integer",
				"description": "How many minutes back to query (default: 60, max: 1440)",
				"default":     60,
				"minimum":     1,
				"maximum":     1440,
			},
			"max_events": maxEventsSchemaProp(),
		},
	}
}
