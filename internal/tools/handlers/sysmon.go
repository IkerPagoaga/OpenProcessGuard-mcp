package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"processguard-mcp/internal/config"
	"processguard-mcp/internal/parse"
	"processguard-mcp/internal/run"
)

// SysmonEvent holds a parsed Sysmon Windows Event Log entry.
type SysmonEvent struct {
	EventID      int    `json:"event_id"`
	EventName    string `json:"event_name"`
	Timestamp    string `json:"timestamp"`
	ProcessID    int    `json:"pid,omitempty"`
	ProcessName  string `json:"process_name,omitempty"`
	CommandLine  string `json:"command_line,omitempty"`
	ParentImage  string `json:"parent_image,omitempty"`
	User         string `json:"user,omitempty"`
	Hashes       string `json:"hashes,omitempty"`
	DestIP       string `json:"dest_ip,omitempty"`
	DestPort     int    `json:"dest_port,omitempty"`
	DestHostname string `json:"dest_hostname,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	ImageLoaded  string `json:"image_loaded,omitempty"`
	Signed       string `json:"signed,omitempty"`
	Signature    string `json:"signature,omitempty"`
	// RawXML is only populated when structured field extraction fails entirely.
	RawXML string `json:"raw_xml,omitempty"`
}

var sysmonEventNames = map[int]string{
	1:  "ProcessCreate",
	2:  "FileCreationTimeChanged",
	3:  "NetworkConnect",
	4:  "SysmonServiceStateChanged",
	5:  "ProcessTerminated",
	6:  "DriverLoaded",
	7:  "ImageLoaded",
	8:  "CreateRemoteThread",
	9:  "RawAccessRead",
	10: "ProcessAccess",
	11: "FileCreate",
	12: "RegistryObjectAddedOrDeleted",
	13: "RegistryValueSet",
	15: "FileCreateStreamHash",
	17: "PipeCreated",
	18: "PipeConnected",
	22: "DNSQuery",
	23: "FileDelete",
	25: "ProcessTampering",
}

// sysmonChannelMissingMarker is emitted by the query script (instead of event
// JSON) when the configured log channel does not exist on this machine. It lets
// the Go side distinguish "Sysmon is not installed" from "no matching events" —
// without it, a Sysmon-less machine read as a CLEAN scan (the silent-clean bug:
// -ErrorAction SilentlyContinue swallowed the missing-channel error and Stage 4
// reported nothing, violating the "absence of findings is not proof" principle).
const sysmonChannelMissingMarker = "SYSMON_CHANNEL_MISSING"

// ErrSysmonChannelMissing reports that the configured Sysmon event-log channel
// does not exist (or is not accessible) — i.e. Sysmon is not installed on this
// machine. Callers use errors.Is to distinguish this from a query failure.
var ErrSysmonChannelMissing = errors.New("sysmon event log channel not found — is Sysmon installed?")

// sysmonQueryFailedMarker is emitted when the channel EXISTS (the probe passed)
// but reading events from it failed — typically access-denied on a non-elevated
// host (the Sysmon channel ACL restricts reads to Administrators/SYSTEM) or the
// EventLog service being down. Without it, -ErrorAction SilentlyContinue
// swallowed those failures into '[]' and a non-elevated host read as a CLEAN
// stage — the same silent-clean class as the missing channel.
const sysmonQueryFailedMarker = "SYSMON_QUERY_FAILED"

// ErrSysmonQueryFailed reports a readable-channel query failure (see
// sysmonQueryFailedMarker). Distinct from ErrSysmonChannelMissing so callers
// can say "install Sysmon" vs "run elevated".
var ErrSysmonQueryFailed = errors.New("sysmon channel exists but could not be read (access denied? Event Log service down?) — run the MCP host elevated")

// sysmonQueryScript builds the PowerShell that fetches Sysmon events for one event ID
// in the last sinceMinutes. It probes the channel FIRST (Get-WinEvent -ListLog with
// -ErrorAction Stop) and emits sysmonChannelMissingMarker when the channel is absent,
// so a machine without Sysmon is reported as TOOL_UNAVAILABLE rather than silently
// clean. StartTime is computed in-script — never round-tripped through a Go-formatted
// string and [datetime]::Parse, which is culture-sensitive and mis-parses the
// timestamp on non-English Windows — and it reads the UTC clock DIRECTLY:
// [datetime]::UtcNow does no local-time conversion at all, so the window is exactly
// "N minutes ago" year-round. (Local arithmetic is off by the DST offset across a
// transition, and even (Get-Date).ToUniversalTime() round-trips through the fall-back
// ambiguous hour.) Get-WinEvent converts a Kind=Utc StartTime correctly.
// The event query runs with -ErrorAction Stop and classifies the failure by
// FullyQualifiedErrorId — which is locale-INVARIANT, unlike exception message
// text (matching messages would re-import the exact culture-sensitivity class
// this script already eliminates from timestamps): "no matching events" is the
// benign empty case; every other failure (access denied, service down) emits
// sysmonQueryFailedMarker instead of masquerading as an empty result.
// sinceMinutes/eventID are ints and logName is validated against a strict
// allowlist at startup (no quotes in the charset), so none can inject into the
// script.
// fetchLimit bounds the rows Get-WinEvent returns. It is ALWAYS passed as the caller's
// cap plus one: retrieving one extra row is what turns "exactly cap rows came back"
// from ambiguous into a definite truncation signal (see querySysmonTyped). Without a
// cap, a 24-hour EID 3 query on a busy host returns tens of thousands of events, each
// ToXml()'d to ~2-4 KB and buffered whole — enough to blow the timeout, the server's
// memory, and the model's context in one call.
func sysmonQueryScript(logName string, eventID, sinceMinutes, fetchLimit int) string {
	return fmt.Sprintf(`
try { $null = Get-WinEvent -ListLog '%[1]s' -ErrorAction Stop } catch { '%[4]s'; exit }
$filter = @{
    LogName   = '%[1]s'
    Id        = %[2]d
    StartTime = [datetime]::UtcNow.AddMinutes(-%[3]d)
}
try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents %[6]d -ErrorAction Stop
    if ($null -eq $events) { '[]'; exit }
    # Single event comes back as an object, not an array — wrap it
    $arr = @($events)
    $xmlArr = $arr | ForEach-Object { $_.ToXml() }
    $xmlArr | ConvertTo-Json -Compress -Depth 1
} catch {
    # FullyQualifiedErrorId is locale-invariant; exception message text is not.
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEvents*') { '[]'; exit }
    '%[5]s'
}`, logName, eventID, sinceMinutes, sysmonChannelMissingMarker, sysmonQueryFailedMarker, fetchLimit)
}

// decodeSysmonQueryOutput classifies the query script's stdout. Markers become
// sentinel errors, the empty forms become zero events, and PowerShell's
// single-object-vs-array ConvertTo-Json shapes normalise to []string. Pure —
// the marker→sentinel mapping is unit-tested without spawning PowerShell.
func decodeSysmonQueryOutput(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	switch raw {
	case sysmonChannelMissingMarker:
		return nil, ErrSysmonChannelMissing
	case sysmonQueryFailedMarker:
		return nil, ErrSysmonQueryFailed
	case "", "[]", "null":
		return nil, nil
	}

	// ConvertTo-Json returns either a JSON array of strings (multiple events)
	// or a bare JSON string (single event). Normalise to []string.
	var xmlStrings []string
	if err := json.Unmarshal([]byte(raw), &xmlStrings); err != nil {
		var single string
		if err2 := json.Unmarshal([]byte(raw), &single); err2 == nil {
			return []string{single}, nil
		}
		return nil, fmt.Errorf("unexpected output format from Get-WinEvent: %w", err)
	}
	return xmlStrings, nil
}

// Sysmon result bounds. A Sysmon-instrumented host generates enormous event volume
// (EID 3 alone can exceed 10k/hour under a broad config), so every read is capped.
const (
	DefaultSysmonMaxEvents = 2000
	MaxSysmonMaxEvents     = 10000
)

// clampSysmonMaxEvents normalises a caller-supplied cap: non-positive means "use the
// default", and the hard ceiling is never exceeded regardless of what a client asks for.
func clampSysmonMaxEvents(n int) int {
	switch {
	case n <= 0:
		return DefaultSysmonMaxEvents
	case n > MaxSysmonMaxEvents:
		return MaxSysmonMaxEvents
	default:
		return n
	}
}

// sysmonResult is the tool-facing envelope. It exists so a CAPPED read cannot look
// identical to a complete one: `truncated` plus the explicit counts say outright that
// the window held more evidence than was returned. Reporting a partial timeline as if
// it were the whole one is the same silent-clean class the channel probe eliminates.
type sysmonResult struct {
	EventID      int           `json:"event_id"`
	SinceMinutes int           `json:"since_minutes"`
	Returned     int           `json:"returned"`
	MaxEvents    int           `json:"max_events"`
	Truncated    bool          `json:"truncated"`
	Note         string        `json:"note,omitempty"`
	Events       []SysmonEvent `json:"events"`
}

// querySysmonTyped is the internal query path: it returns parsed events plus whether
// the read was truncated. In-process callers (run_full_hunt) use this rather than
// unmarshalling the tool-facing JSON string, so the envelope's shape is free to change
// without silently breaking the hunt.
func querySysmonTyped(ctx context.Context, cfg *config.Config, eventID, sinceMinutes, maxEvents int) ([]SysmonEvent, bool, error) {
	if cfg.SysmonLog == "" {
		return nil, false, fmt.Errorf("sysmon_log channel not configured")
	}
	maxEvents = clampSysmonMaxEvents(maxEvents)

	// Ask for one MORE than the cap. If the extra row comes back, strictly more than
	// `maxEvents` events matched, which is what makes truncation detectable instead of
	// merely suspected.
	out, err := run.PowerShellCtx(ctx, run.DefaultTimeout,
		sysmonQueryScript(cfg.SysmonLog, eventID, sinceMinutes, maxEvents+1))
	if err != nil {
		return nil, false, fmt.Errorf("Get-WinEvent failed: %w — is Sysmon installed and running?", err)
	}

	xmlStrings, err := decodeSysmonQueryOutput(string(out))
	switch {
	case errors.Is(err, ErrSysmonChannelMissing):
		return nil, false, fmt.Errorf("channel %q not found or not accessible: %w", cfg.SysmonLog, err)
	case errors.Is(err, ErrSysmonQueryFailed):
		return nil, false, fmt.Errorf("channel %q: %w", cfg.SysmonLog, err)
	case err != nil:
		return nil, false, err
	}

	// Get-WinEvent returns newest-first, so the retained slice is the most recent
	// window — the useful end for a forensic timeline.
	truncated := len(xmlStrings) > maxEvents
	if truncated {
		xmlStrings = xmlStrings[:maxEvents]
	}

	events := make([]SysmonEvent, 0, len(xmlStrings))
	for _, xmlStr := range xmlStrings {
		events = append(events, parseSysmonXML(xmlStr, eventID))
	}
	return events, truncated, nil
}

// QuerySysmonEvents queries the Sysmon Windows Event Log for a specific event ID
// within the last N minutes, returning at most maxEvents (0 = default cap) and
// declaring explicitly whether the result was truncated.
func QuerySysmonEvents(ctx context.Context, cfg *config.Config, eventID, sinceMinutes, maxEvents int) (string, error) {
	maxEvents = clampSysmonMaxEvents(maxEvents)

	events, truncated, err := querySysmonTyped(ctx, cfg, eventID, sinceMinutes, maxEvents)
	if err != nil {
		return "", err
	}

	res := sysmonResult{
		EventID:      eventID,
		SinceMinutes: sinceMinutes,
		Returned:     len(events),
		MaxEvents:    maxEvents,
		Truncated:    truncated,
		Events:       events,
	}
	if truncated {
		res.Note = fmt.Sprintf(
			"TRUNCATED: more than %d matching events exist in this window; only the %d most recent are shown. "+
				"Narrow since_minutes, or raise max_events (hard cap %d), to see the rest.",
			maxEvents, len(events), MaxSysmonMaxEvents)
	}

	result, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// GetProcessCreateEvents returns Sysmon Event ID 1 (ProcessCreate) for the
// last N minutes. This is the primary forensic timeline source.
func GetProcessCreateEvents(ctx context.Context, cfg *config.Config, sinceMinutes, maxEvents int) (string, error) {
	return QuerySysmonEvents(ctx, cfg, 1, sinceMinutes, maxEvents)
}

// GetNetworkEvents returns Sysmon Event ID 3 (NetworkConnect) for the
// last N minutes. Use for C2 beacon detection and outbound call history.
func GetNetworkEvents(ctx context.Context, cfg *config.Config, sinceMinutes, maxEvents int) (string, error) {
	return QuerySysmonEvents(ctx, cfg, 3, sinceMinutes, maxEvents)
}

// parseSysmonXML extracts key fields from a Sysmon event XML string using a
// real XML parser (parse.SysmonFields), so entities are unescaped and values
// containing markup-like text (a command line with "</Data>") survive intact.
// RawXML is only kept when parsing fails or no meaningful field was found.
func parseSysmonXML(xmlStr string, eventID int) SysmonEvent {
	e := SysmonEvent{
		EventID:   eventID,
		EventName: sysmonEventNames[eventID],
	}

	ts, fields, ok := parse.SysmonFields(xmlStr)
	if !ok {
		e.RawXML = xmlStr
		return e
	}
	e.Timestamp = ts

	// Fields common to many event types
	e.ProcessName = fields["Image"]
	e.ProcessID, _ = strconv.Atoi(fields["ProcessId"])
	e.CommandLine = fields["CommandLine"]
	e.ParentImage = fields["ParentImage"]
	e.User = fields["User"]
	e.Hashes = fields["Hashes"]

	// Network events (ID 3)
	e.DestIP = fields["DestinationIp"]
	e.DestHostname = fields["DestinationHostname"]
	e.Protocol = fields["Protocol"]
	e.DestPort, _ = strconv.Atoi(fields["DestinationPort"])

	// Image load events (ID 7)
	e.ImageLoaded = fields["ImageLoaded"]
	e.Signed = fields["Signed"]
	e.Signature = fields["Signature"]

	// Only attach raw XML when we couldn't extract any meaningful field.
	if e.ProcessName == "" && e.DestIP == "" && e.ImageLoaded == "" && e.Timestamp == "" {
		e.RawXML = xmlStr
	}

	return e
}
