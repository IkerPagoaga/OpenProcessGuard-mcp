package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

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
	ImagePath  string `json:"image_path"`
	LaunchStr  string `json:"launch_string"`
	SHA256     string `json:"sha256,omitempty"`
	IsVerified bool   `json:"is_verified"`  // code-signed by a trusted publisher
	IsMicrosoft bool  `json:"is_microsoft"` // published by Microsoft

	// VirusTotal (populated by autorunsc -v when key is configured)
	VTDetections int `json:"vt_detections,omitempty"` // positive engine count
	VTTotal      int `json:"vt_total,omitempty"`      // total engines checked

	// Risk flags computed locally
	Flags  []string `json:"flags,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// autorunsColNames lists the canonical column header substrings we look for,
// matched case-insensitively against the first CSV row autorunsc prints.
// autorunsc -c header (typical): Time,Entry Location,Entry,Enabled,Category,
//   Profile,Description,Signer,Company,Image Path,Version,Launch String,
//   VT detection,VT permalink
//
// We use Contains matching so minor wording differences across tool versions
// don't break parsing (e.g. "Entry Location" vs "EntryLocation").
const (
	aColEntryLocation = "entry location"
	aColEntry         = "entry"     // matched after "entry location" — order matters
	aColDescription   = "description"
	aColSigner        = "signer"
	aColCompany       = "company"
	aColImagePath     = "image path"
	aColLaunchString  = "launch string"
	aColVTDetection   = "vt detection"
	aColSHA256        = "sha-256" // present in newer autorunsc versions
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

// autorunsColIdx holds resolved column indices derived from the header row.
type autorunsColIdx struct {
	entryLocation int
	entry         int
	description   int
	signer        int
	company       int
	imagePath     int
	launchString  int
	vtDetection   int
	sha256        int
}

const colNotFound = -1

// buildColIdx reads the header row from autorunsc CSV output and builds an
// index map using case-insensitive substring matching.  This is resilient to
// column-order changes across autorunsc versions.
func buildColIdx(header string) autorunsColIdx {
	cols := splitCSVLine(header)
	idx := autorunsColIdx{
		entryLocation: colNotFound,
		entry:         colNotFound,
		description:   colNotFound,
		signer:        colNotFound,
		company:       colNotFound,
		imagePath:     colNotFound,
		launchString:  colNotFound,
		vtDetection:   colNotFound,
		sha256:        colNotFound,
	}
	for i, col := range cols {
		lower := strings.ToLower(strings.TrimSpace(col))
		switch {
		case strings.Contains(lower, aColEntryLocation):
			idx.entryLocation = i
		case lower == aColEntry || strings.HasPrefix(lower, "entry"):
			// "Entry" must be matched after "Entry Location" — set only if not yet set
			// and the column doesn't also contain "location"
			if idx.entry == colNotFound && !strings.Contains(lower, "location") {
				idx.entry = i
			}
		case strings.Contains(lower, aColDescription):
			idx.description = i
		case strings.Contains(lower, aColSigner):
			idx.signer = i
		case strings.Contains(lower, aColCompany):
			idx.company = i
		case strings.Contains(lower, aColImagePath):
			idx.imagePath = i
		case strings.Contains(lower, aColLaunchString):
			idx.launchString = i
		case strings.Contains(lower, aColVTDetection):
			idx.vtDetection = i
		case strings.Contains(lower, aColSHA256) || lower == "sha256":
			idx.sha256 = i
		}
	}
	return idx
}

// safeCol returns cols[i] if i is valid and in-bounds; otherwise "".
func safeCol(cols []string, i int) string {
	if i == colNotFound || i >= len(cols) {
		return ""
	}
	return cols[i]
}

// parseAutorunsCSV converts autorunsc CSV output into AutorunEntry structs.
// The first non-empty line is treated as the header and used to resolve column
// positions dynamically, so parsing is robust across autorunsc version changes.
func parseAutorunsCSV(csv string) ([]AutorunEntry, error) {
	var entries []AutorunEntry
	lines := strings.Split(csv, "\n")

	// Find the header line (first non-empty line)
	headerLine := ""
	dataStart := 0
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			headerLine = trimmed
			dataStart = i + 1
			break
		}
	}
	if headerLine == "" {
		return entries, nil
	}

	idx := buildColIdx(headerLine)

	for _, line := range lines[dataStart:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cols := splitCSVLine(line)

		signer := safeCol(cols, idx.signer)
		e := AutorunEntry{
			EntryLocation: safeCol(cols, idx.entryLocation),
			EntryName:     safeCol(cols, idx.entry),
			Description:   safeCol(cols, idx.description),
			Publisher:     safeCol(cols, idx.company),
			ImagePath:     safeCol(cols, idx.imagePath),
			LaunchStr:     safeCol(cols, idx.launchString),
			SHA256:        safeCol(cols, idx.sha256),
		}

		e.IsVerified = signer != "" && !strings.EqualFold(signer, "(Not verified)")
		e.IsMicrosoft = strings.Contains(strings.ToLower(signer), "microsoft")

		// VT detection column: "5/72" format
		vtStr := safeCol(cols, idx.vtDetection)
		if vtStr != "" {
			fmt.Sscanf(vtStr, "%d/%d", &e.VTDetections, &e.VTTotal)
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
