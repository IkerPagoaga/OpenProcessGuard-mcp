package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"processguard-mcp/internal/config"
	"processguard-mcp/internal/parse"
	"processguard-mcp/internal/run"
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
	// SignerKnown is false when autorunsc emitted no Signer column at all.
	// When false, signing status is UNKNOWN — callers must not infer "unsigned".
	SignerKnown bool `json:"signer_known"`

	// VirusTotal (populated by autorunsc -v when key is configured)
	VTDetections int `json:"vt_detections,omitempty"` // positive engine count
	VTTotal      int `json:"vt_total,omitempty"`      // total engines checked

	// Risk flags computed locally
	Flags  []string `json:"flags,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

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

	// -a * : all categories · -c : CSV · -h : hash (SHA256) · -s : verify
	// signatures · -nobanner : no Sysinternals banner · -accepteula : headless.
	args := []string{"-a", "*", "-c", "-h", "-s", "-nobanner", "-accepteula"}
	if cfg.VTAPIKey != "" {
		args = append(args, "-v") // -v queries VirusTotal; only with a key
	}

	out, err := run.Tool(cfg.AutorunsPath, args...)
	if err != nil {
		return "", fmt.Errorf("autorunsc failed: %w", err)
	}

	rows, err := parse.AutorunsCSV(string(out))
	if err != nil {
		return "", fmt.Errorf("CSV parse failed: %w", err)
	}

	entries := make([]AutorunEntry, 0, len(rows))
	for _, r := range rows {
		e := AutorunEntry{
			EntryLocation: r.EntryLocation,
			EntryName:     r.EntryName,
			Description:   r.Description,
			Publisher:     r.Company,
			ImagePath:     r.ImagePath,
			LaunchStr:     r.LaunchString,
			SHA256:        r.SHA256,
			SignerKnown:   r.SignerKnown,
			VTDetections:  r.VTDetections,
			VTTotal:       r.VTTotal,
		}
		// Only derive signing verdicts when the signer column actually existed.
		if r.SignerKnown {
			e.IsVerified = r.Signer != "" && !strings.EqualFold(r.Signer, "(Not verified)")
			e.IsMicrosoft = strings.Contains(strings.ToLower(r.Signer), "microsoft")
		}
		flagAutorunEntry(&e)
		entries = append(entries, e)
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

// flagAutorunEntry applies risk heuristics and populates Flags + Reason.
func flagAutorunEntry(e *AutorunEntry) {
	var flags []string
	var reasons []string

	// Only assert UNSIGNED when we actually know the signing status. An absent
	// Signer column means "unknown", not "unsigned" — asserting the latter
	// turned every entry into a false positive.
	if e.SignerKnown && !e.IsVerified && !e.IsMicrosoft {
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
