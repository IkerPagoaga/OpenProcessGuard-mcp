package handlers

import (
	"context"
	"encoding/json"
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

// sysmonQueryScript builds the PowerShell that fetches Sysmon events for one event ID
// in the last sinceMinutes. StartTime is computed in-script — never round-tripped
// through a Go-formatted string and [datetime]::Parse, which is culture-sensitive and
// mis-parses the timestamp on non-English Windows — and it reads the UTC clock
// DIRECTLY: [datetime]::UtcNow does no local-time conversion at all, so the window is
// exactly "N minutes ago" year-round. (Local arithmetic is off by the DST offset
// across a transition, and even (Get-Date).ToUniversalTime() round-trips through the
// fall-back ambiguous hour.) Get-WinEvent converts a Kind=Utc StartTime correctly.
// -ErrorAction SilentlyContinue returns [] instead of throwing when the log exists but
// has no matching events. sinceMinutes/eventID are ints and logName is validated
// against a strict allowlist at startup, so none can inject into the script.
func sysmonQueryScript(logName string, eventID, sinceMinutes int) string {
	return fmt.Sprintf(`
$filter = @{
    LogName   = '%s'
    Id        = %d
    StartTime = [datetime]::UtcNow.AddMinutes(-%d)
}
try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    if ($null -eq $events) { '[]'; exit }
    # Single event comes back as an object, not an array — wrap it
    $arr = @($events)
    $xmlArr = $arr | ForEach-Object { $_.ToXml() }
    $xmlArr | ConvertTo-Json -Compress -Depth 1
} catch {
    '[]'
}`, logName, eventID, sinceMinutes)
}

// QuerySysmonEvents queries the Sysmon Windows Event Log for a specific
// event ID within the last N minutes.
func QuerySysmonEvents(ctx context.Context, cfg *config.Config, eventID, sinceMinutes int) (string, error) {
	if cfg.SysmonLog == "" {
		return "", fmt.Errorf("sysmon_log channel not configured")
	}

	out, err := run.PowerShellCtx(ctx, run.DefaultTimeout, sysmonQueryScript(cfg.SysmonLog, eventID, sinceMinutes))
	if err != nil {
		return "", fmt.Errorf("Get-WinEvent failed: %w — is Sysmon installed and running?", err)
	}

	raw := strings.TrimSpace(string(out))
	if raw == "[]" || raw == "" || raw == "null" {
		result, _ := json.Marshal([]SysmonEvent{})
		return string(result), nil
	}

	// PowerShell ConvertTo-Json returns either a JSON array of strings (multiple
	// events) or a bare JSON string (single event). Normalise to []string.
	var xmlStrings []string
	if err := json.Unmarshal([]byte(raw), &xmlStrings); err != nil {
		// Single event returned as a bare JSON string
		var single string
		if err2 := json.Unmarshal([]byte(raw), &single); err2 == nil {
			xmlStrings = []string{single}
		} else {
			return "", fmt.Errorf("unexpected output format from Get-WinEvent: %w", err)
		}
	}

	var events []SysmonEvent
	for _, xmlStr := range xmlStrings {
		e := parseSysmonXML(xmlStr, eventID)
		events = append(events, e)
	}
	if events == nil {
		events = []SysmonEvent{}
	}

	result, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// GetProcessCreateEvents returns Sysmon Event ID 1 (ProcessCreate) for the
// last N minutes. This is the primary forensic timeline source.
func GetProcessCreateEvents(ctx context.Context, cfg *config.Config, sinceMinutes int) (string, error) {
	return QuerySysmonEvents(ctx, cfg, 1, sinceMinutes)
}

// GetNetworkEvents returns Sysmon Event ID 3 (NetworkConnect) for the
// last N minutes. Use for C2 beacon detection and outbound call history.
func GetNetworkEvents(ctx context.Context, cfg *config.Config, sinceMinutes int) (string, error) {
	return QuerySysmonEvents(ctx, cfg, 3, sinceMinutes)
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
