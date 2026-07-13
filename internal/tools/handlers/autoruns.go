package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

// autorunsVTTimeout bounds an autorunsc run that includes per-hash VirusTotal
// lookups (-v). Larger than run.DefaultTimeout because the lookups are serial
// network calls, but still a hard ceiling — a hung scan cannot wedge the server.
const autorunsVTTimeout = 180 * time.Second

// suspiciousAutorunDirs mirrors the process heuristic — autoruns from these
// paths are almost always malicious or at minimum high-risk.
var suspiciousAutorunDirs = []string{
	`\temp\`, `\tmp\`, `\appdata\local\temp\`,
	`\downloads\`, `\recycle`, `\public\`,
}

// signingFromSigner interprets an autorunsc Signer column. autorunsc emits the
// verification status as a PREFIX — "(Verified) <Publisher>" or
// "(Not verified) <Publisher>" — so equality against the bare "(Not verified)"
// (the previous check) treated every real "(Not verified) Foo" as verified.
// "microsoft" is trusted only when the entry is actually verified, so a
// "(Not verified) Microsoft ..." spoof no longer evades the UNSIGNED flag.
func signingFromSigner(signer string) (verified, microsoft bool) {
	s := strings.ToLower(strings.TrimSpace(signer))
	verified = strings.HasPrefix(s, "(verified)")
	microsoft = verified && strings.Contains(s, "microsoft")
	return
}

// GetAutorunsEntries runs autorunsc.exe and returns all persistence entries.
// Returns an error if autoruns_path is not configured.
func GetAutorunsEntries(ctx context.Context, cfg *config.Config) (string, error) {
	if cfg.AutorunsPath == "" {
		return "", fmt.Errorf("autoruns_path not configured — add autorunsc.exe path to config.json")
	}

	// -a * : all categories · -c : CSV · -h : hash (SHA256) · -s : verify
	// signatures · -nobanner : no Sysinternals banner · -accepteula : headless.
	args := []string{"-a", "*", "-c", "-h", "-s", "-nobanner", "-accepteula"}
	timeout := run.DefaultTimeout
	if cfg.VTAPIKey != "" {
		// -v makes autorunsc submit hashes to VirusTotal via its OWN integration:
		// it does NOT consume vt_api_key, and those calls are not counted against
		// this server's per-hunt VT cap. It is enabled here only as a proxy for
		// "the user has opted into VT"; run_full_hunt's Stage 5 performs the
		// key-authenticated, rate-capped lookups.
		//
		// -vt accepts the VirusTotal terms of service. Without it, a box where the
		// ToS was never accepted gets an INTERACTIVE prompt (per Microsoft's autoruns
		// docs) — which in this headless context means a silent stall until the
		// timeout kills the scan. Configuring vt_api_key IS the user's VT opt-in,
		// so pre-accepting here is faithful to their intent.
		//
		// -v blocks on a VirusTotal hash lookup per unique autostart binary, so a
		// cold-cache first run over a few hundred entries can legitimately exceed
		// the 45s default — raise the (still bounded) budget for this path only.
		args = append(args, "-v", "-vt")
		timeout = autorunsVTTimeout
	}

	out, err := run.ToolCtx(ctx, timeout, cfg.AutorunsPath, args...)
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
			e.IsVerified, e.IsMicrosoft = signingFromSigner(r.Signer)
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
func FlagAutorunsAnomalies(ctx context.Context, cfg *config.Config) (string, error) {
	raw, err := GetAutorunsEntries(ctx, cfg)
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
