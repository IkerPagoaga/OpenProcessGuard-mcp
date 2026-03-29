package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"processguard-mcp/internal/config"
)

// AutorunEntry represents a single persistence entry returned by autorunsc.exe.
type AutorunEntry struct {
	// Core identity
	EntryLocation string `json:"entry_location"` // e.g. "HKLM\SOFTWARE\...\Run"
	EntryName     string `json:"entry_name"`
	Description   string `json:"description"`
	Publisher     string `json:"publisher"`

	// Binary details
	ImagePath   string `json:"image_path"`
	LaunchStr   string `json:"launch_string"`
	SHA256      string `json:"sha256,omitempty"`
	IsVerified  bool   `json:"is_verified"`  // code-signed by a trusted publisher
	IsMicrosoft bool   `json:"is_microsoft"` // published by Microsoft

	// VirusTotal (populated by autorunsc -v when key is configured)
	VTDetections int `json:"vt_detections,omitempty"` // positive engine count
	VTTotal      int `json:"vt_total,omitempty"`      // total engines checked

	// Risk flags computed locally
	Flags  []string `json:"flags,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// autorunsc CSV column indices (output of: autorunsc.exe -a * -c -h -v -u)
// Columns: Time,Entry Location,Entry,Enabled,Category,Profile,Description,
//          Signer,Company,Image Path,Version,Launch String,VT detection,VT permalink
const (
	colTime          = 0
	colEntryLocation = 1
	colEntry         = 2
	colEnabled       = 3
	colCategory      = 4
	colDescription   = 6
	colSigner        = 7
	colCompany       = 8
	colImagePath     = 9
	colLaunchString  = 11
	colVTDetection   = 12
)

// suspiciousAutorunDirs mirrors the process heuristic — autoruns from these
// paths are almost always malicious or at minimum high-risk.
var suspiciousAutorunDirs = []string{
	`\temp\`, `\tmp\`, `\appdata\local\temp\`,
	`\downloads\`, `\recycle`, `\public\`,
}

// GetAutorunsEntries runs autorunsc.exe and returns all persistence entries.
// Returns an error if autoruns_path is not configured.
func GetAutorunsEntries(cfg *config.Config) (string, error) {
	if cfg.AutorunsPath == "" {
		return "", fmt.Errorf("autoruns_path not configured — add autorunsc.exe path to config.json")
	}

	// -a * : all categories
	// -c   : CSV output
	// -h   : include hash (SHA256)
	// -s   : verify digital signatures
	// -u   : show only unsigned entries  (remove this flag to see all)
	// -nobanner : suppress the Sysinternals banner
	args := []string{"-a", "*", "-c", "-h", "-s", "-nobanner", "-accepteula"}
	if cfg.VTAPIKey != "" {
		// -v queries VirusTotal; only enable if we have a key
		args = append(args, "-v")
	}

	out, err := exec.Command(cfg.AutorunsPath, args...).Output()
	if err != nil {
		return "", fmt.Errorf("autorunsc failed: %w", err)
	}

	entries, err := parseAutorunsCSV(string(out))
	if err != nil {
		return "", fmt.Errorf("CSV parse failed: %w", err)
	}

	// Apply local risk flags
	for i := range entries {
		flagAutorunEntry(&entries[i])
	}

	result, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// FlagAutorunsAnomalies returns only high-risk entries (unsigned, temp path, VT hits).
func FlagAutorunsAnomalies(cfg *config.Config) (string, error) {
	raw, err := GetAutorunsEntries(cfg)
	if err != nil {
		return "", err
	}
	var all []AutorunEntry
	if err := json.Unmarshal([]byte(raw), &all); err != nil {
		return "", err
	}
	var flagged []AutorunEntry
	for _, e := range all {
		if len(e.Flags) > 0 {
			flagged = append(flagged, e)
		}
	}
	if flagged == nil {
		flagged = []AutorunEntry{}
	}
	result, err := json.MarshalIndent(flagged, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// parseAutorunsCSV converts autorunsc CSV output into AutorunEntry structs.
func parseAutorunsCSV(csv string) ([]AutorunEntry, error) {
	var entries []AutorunEntry
	lines := strings.Split(csv, "\n")
	if len(lines) < 2 {
		return entries, nil
	}

	// Skip the header line
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cols := splitCSVLine(line)
		if len(cols) < colLaunchString+1 {
			continue
		}

		e := AutorunEntry{
			EntryLocation: cols[colEntryLocation],
			EntryName:     cols[colEntry],
			Description:   cols[colDescription],
			Publisher:     cols[colCompany],
			ImagePath:     cols[colImagePath],
			LaunchStr:     cols[colLaunchString],
		}

		signer := cols[colSigner]
		e.IsVerified = signer != "" && !strings.EqualFold(signer, "(Not verified)")
		e.IsMicrosoft = strings.Contains(strings.ToLower(signer), "microsoft")

		// VT detection column: "5/72" format
		if len(cols) > colVTDetection {
			vtStr := cols[colVTDetection]
			fmt.Sscanf(vtStr, "%d/%d", &e.VTDetections, &e.VTTotal)
		}

		// SHA256 is extracted from the image path column in newer autorunsc versions
		// Format varies; we store it when present
		if strings.HasPrefix(cols[colImagePath], "SHA") {
			e.SHA256 = cols[colImagePath]
		}

		entries = append(entries, e)
	}
	return entries, nil
}

// flagAutorunEntry applies risk heuristics and populates Flags + Reason.
func flagAutorunEntry(e *AutorunEntry) {
	var flags []string
	var reasons []string

	if !e.IsVerified && !e.IsMicrosoft {
		flags = append(flags, "UNSIGNED")
		reasons = append(reasons, "entry is not digitally signed by a trusted publisher")
	}

	pathLower := strings.ToLower(e.ImagePath)
	for _, dir := range suspiciousAutorunDirs {
		if strings.Contains(pathLower, dir) {
			flags = append(flags, "SUSPICIOUS_PATH")
			reasons = append(reasons, fmt.Sprintf("binary in high-risk directory: %s", e.ImagePath))
			break
		}
	}

	if e.VTDetections > 0 {
		flags = append(flags, "VT_HIT")
		reasons = append(reasons, fmt.Sprintf("VirusTotal: %d/%d engines flagged this binary", e.VTDetections, e.VTTotal))
	}

	if e.ImagePath == "" && e.LaunchStr == "" {
		flags = append(flags, "NO_PATH")
		reasons = append(reasons, "no executable path or launch string — possible fileless persistence")
	}

	e.Flags = flags
	e.Reason = strings.Join(reasons, "; ")
}

// splitCSVLine splits a single CSV line respecting quoted fields.
func splitCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch == ',' && !inQuote {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	fields = append(fields, current.String())
	return fields
}

// sentinel to avoid unused import
var _ = time.Now
