package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"processguard-mcp/internal/config"
)

// SysmonEvent holds a parsed Sysmon Windows Event Log entry.
type SysmonEvent struct {
	EventID     int    `json:"event_id"`
	EventName   string `json:"event_name"`
	Timestamp   string `json:"timestamp"`
	ProcessID   int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ParentImage string `json:"parent_image,omitempty"`
	User        string `json:"user,omitempty"`
	Hashes      string `json:"hashes,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestPort    int    `json:"dest_port,omitempty"`
	ImageLoaded string `json:"image_loaded,omitempty"`
	RawXML      string `json:"raw_xml,omitempty"`
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

// QuerySysmonEvents queries the Sysmon Windows Event Log for a specific
// event ID within the last N minutes.
func QuerySysmonEvents(cfg *config.Config, eventID, sinceMinutes int) (string, error) {
	if cfg.SysmonLog == "" {
		return "", fmt.Errorf("sysmon_log channel not configured")
	}

	since := time.Now().UTC().Add(-time.Duration(sinceMinutes) * time.Minute)
	sinceStr := since.Format("2006-01-02T15:04:05.000Z")

	// PowerShell query using Get-WinEvent with an XPath filter.
	// The XPath filter is the most reliable approach across all Windows versions.
	psCmd := fmt.Sprintf(`
$filter = @{
    LogName   = '%s'
    Id        = %d
    StartTime = [datetime]'%s'
}
$events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
if ($events) {
    $events | ForEach-Object { $_.ToXml() } | ConvertTo-Json -Compress
} else {
    '[]'
}`, cfg.SysmonLog, eventID, sinceStr)

	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd,
	).Output()
	if err != nil {
		return "", fmt.Errorf("Get-WinEvent failed: %w — is Sysmon installed and running?", err)
	}

	raw := strings.TrimSpace(string(out))
	if raw == "[]" || raw == "" {
		result, _ := json.Marshal([]SysmonEvent{})
		return string(result), nil
	}

	// PowerShell returns either a JSON array of strings or a single string.
	// Each string is an XML event. Parse each one.
	var xmlStrings []string
	if err := json.Unmarshal([]byte(raw), &xmlStrings); err != nil {
		// Single event — wrap in array
		var single string
		if err2 := json.Unmarshal([]byte(raw), &single); err2 == nil {
			xmlStrings = []string{single}
		} else {
			return "", fmt.Errorf("unexpected output format: %w", err)
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
func GetProcessCreateEvents(cfg *config.Config, sinceMinutes int) (string, error) {
	return QuerySysmonEvents(cfg, 1, sinceMinutes)
}

// GetNetworkEvents returns Sysmon Event ID 3 (NetworkConnect) for the
// last N minutes. Use for C2 beacon detection and outbound call history.
func GetNetworkEvents(cfg *config.Config, sinceMinutes int) (string, error) {
	return QuerySysmonEvents(cfg, 3, sinceMinutes)
}

// parseSysmonXML extracts key fields from a Sysmon event XML string.
// This is a lightweight field extractor — not a full XML parser — to avoid
// an xml dependency. We look for known Sysmon data field patterns.
func parseSysmonXML(xmlStr string, eventID int) SysmonEvent {
	e := SysmonEvent{
		EventID:   eventID,
		EventName: sysmonEventNames[eventID],
		RawXML:    xmlStr,
	}

	extract := func(name string) string {
		needle := `<Data Name='` + name + `'>`
		idx := strings.Index(xmlStr, needle)
		if idx == -1 {
			needle = `<Data Name="` + name + `">`
			idx = strings.Index(xmlStr, needle)
			if idx == -1 {
				return ""
			}
		}
		start := idx + len(needle)
		end := strings.Index(xmlStr[start:], "</Data>")
		if end == -1 {
			return ""
		}
		return strings.TrimSpace(xmlStr[start : start+end])
	}

	// Common to many event types
	e.ProcessName = extract("Image")
	e.ProcessID, _ = strconv.Atoi(extract("ProcessId"))
	e.CommandLine = extract("CommandLine")
	e.ParentImage = extract("ParentImage")
	e.User = extract("User")
	e.Hashes = extract("Hashes")

	// Network events (ID 3)
	e.DestIP = extract("DestinationIp")
	destPortStr := extract("DestinationPort")
	e.DestPort, _ = strconv.Atoi(destPortStr)

	// Image load events (ID 7)
	e.ImageLoaded = extract("ImageLoaded")

	// Timestamp from SystemTime attribute
	needle := `SystemTime='`
	if idx := strings.Index(xmlStr, needle); idx >= 0 {
		start := idx + len(needle)
		if end := strings.Index(xmlStr[start:], "'"); end >= 0 {
			e.Timestamp = xmlStr[start : start+end]
		}
	}

	return e
}
