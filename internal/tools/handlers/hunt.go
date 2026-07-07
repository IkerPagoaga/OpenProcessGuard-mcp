package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"processguard-mcp/internal/config"
)

// Severity levels for HuntReport findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityInfo     = "INFO"
)

// Finding is a single threat indicator surfaced during the hunt.
type Finding struct {
	Stage       int      `json:"stage"`    // 1=ProcessIntegrity, 2=Autoruns, 3=Network, 4=Sysmon, 5=VirusTotal
	Severity    string   `json:"severity"` // CRITICAL/HIGH/MEDIUM/INFO
	Category    string   `json:"category"` // e.g. "PROCESS_HOLLOWING", "C2_BEACON"
	Description string   `json:"description"`
	Entity      string   `json:"entity"` // PID, path, IP, or autorun key
	Flags       []string `json:"flags,omitempty"`
	Confidence  string   `json:"confidence"` // HIGH/MEDIUM/LOW
}

// HuntReport is the structured output of run_full_hunt.
type HuntReport struct {
	ScanTimestamp    string `json:"scan_timestamp"`
	DurationMs       int64  `json:"duration_ms"`
	ExecutiveSummary string `json:"executive_summary"`
	Availability     struct {
		ProcessExplorer bool `json:"process_explorer"`
		Autoruns        bool `json:"autoruns"`
		Sysmon          bool `json:"sysmon"`
		VirusTotal      bool `json:"virus_total"`
		GeoIP           bool `json:"geo_ip"`
	} `json:"tool_availability"`
	Findings           []Finding `json:"findings"`
	Critical           []Finding `json:"critical"`
	High               []Finding `json:"high"`
	Medium             []Finding `json:"medium"`
	Info               []Finding `json:"info"`
	RecommendedActions []string  `json:"recommended_actions"`
}

// RunFullHunt orchestrates all five hunting stages and returns a HuntReport.
func RunFullHunt(cfg *config.Config) (string, error) {
	start := time.Now()
	report := HuntReport{
		ScanTimestamp: start.UTC().Format(time.RFC3339),
	}

	avail := cfg.Availability()
	report.Availability.ProcessExplorer = avail.ProcessExplorer
	report.Availability.Autoruns = avail.Autoruns
	report.Availability.Sysmon = avail.Sysmon
	report.Availability.VirusTotal = avail.VirusTotal
	report.Availability.GeoIP = avail.GeoIP

	var findings []Finding

	// Autoruns is the most expensive probe (autorunsc -a * scans every category,
	// 10-30s). Stages 2 and 5 both consume it, so run it ONCE here and share the
	// parsed entries rather than launching a second identical scan per hunt.
	var autorunEntries []AutorunEntry
	var autorunErr error
	if avail.Autoruns {
		raw, err := GetAutorunsEntries(cfg)
		if err != nil {
			autorunErr = err
		} else if err := json.Unmarshal([]byte(raw), &autorunEntries); err != nil {
			autorunErr = err
		}
	}

	// ── Stage 1: Process Integrity (heuristics + Authenticode signing) ──
	findings = append(findings, runStage1(cfg)...)

	// ── Stage 2: Persistence (Autoruns) ───────────────────────────
	findings = append(findings, runStage2(avail.Autoruns, autorunEntries, autorunErr)...)

	// ── Stage 3: Network Visibility ────────────────────────────────
	findings = append(findings, runStage3(cfg)...)

	// ── Stage 4: Sysmon Forensics (last 60 min) ───────────────────
	findings = append(findings, runStage4(cfg)...)

	// ── Stage 5: VirusTotal Hash Escalation ────────────────────────
	findings = append(findings, runStage5(cfg, avail, autorunEntries)...)

	// Bucket findings by severity
	report.Findings = findings
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			report.Critical = append(report.Critical, f)
		case SeverityHigh:
			report.High = append(report.High, f)
		case SeverityMedium:
			report.Medium = append(report.Medium, f)
		default:
			report.Info = append(report.Info, f)
		}
	}

	// Ensure no nil slices in JSON output
	if report.Critical == nil {
		report.Critical = []Finding{}
	}
	if report.High == nil {
		report.High = []Finding{}
	}
	if report.Medium == nil {
		report.Medium = []Finding{}
	}
	if report.Info == nil {
		report.Info = []Finding{}
	}
	if report.Findings == nil {
		report.Findings = []Finding{}
	}

	// DurationMs must be set BEFORE buildSummary — the summary embeds it, and
	// the struct is passed by value, so setting it afterwards reported 0ms.
	report.DurationMs = time.Since(start).Milliseconds()
	report.RecommendedActions = buildRecommendations(report)
	report.ExecutiveSummary = buildSummary(report)

	result, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}
	return string(result), nil
}

// runStage1 runs the process-integrity checks: the gopsutil heuristic scan
// (get_suspicious_processes) AND the Authenticode signing lens. The two are
// independent — a signing failure does not suppress the heuristic findings and
// vice versa. Adding the signing lens closes a real gap: a plain unsigned or
// untrusted binary that trips no heuristic (not name-spoofing, not in a temp
// dir, not Office-spawned) previously produced zero findings in the full hunt,
// even though the standalone get_unsigned_processes tool would surface it.
func runStage1(cfg *config.Config) []Finding {
	var findings []Finding

	// 1a. Heuristic scan — name spoof / wrong path / temp dir / masquerade / parent.
	raw, err := GetSuspiciousProcesses()
	if err != nil {
		findings = append(findings, scanError(1, "process-integrity", err))
	} else {
		var procs []SuspiciousProcess
		if err := json.Unmarshal([]byte(raw), &procs); err != nil {
			findings = append(findings, scanError(1, "process-integrity", err))
		} else {
			for _, p := range procs {
				severity := SeverityMedium
				for _, flag := range p.Flags {
					switch flag {
					case FlagMasquerade:
						severity = SeverityCritical
					case FlagNameSpoof, FlagWrongPath:
						if severity != SeverityCritical {
							severity = SeverityHigh
						}
					}
				}
				findings = append(findings, Finding{
					Stage:       1,
					Severity:    severity,
					Category:    "SUSPICIOUS_PROCESS",
					Description: p.Reason,
					Entity:      fmt.Sprintf("PID %d (%s) @ %s", p.PID, p.Name, p.ExePath),
					Flags:       p.Flags,
					Confidence:  "MEDIUM",
				})
			}
		}
	}

	// 1b. Authenticode signing lens.
	findings = append(findings, runStage1Signing()...)
	return findings
}

// runStage1Signing surfaces processes whose Authenticode signature is missing or
// untrusted — the lens get_unsigned_processes/get_process_tree expose as
// standalone tools but which the heuristic scan does not cover. It reuses the
// shared collectProcessesWithSigning enumeration (also used by those tools).
//
// Severity is deliberately conservative to keep signal-to-noise sane: tampering
// (hash mismatch) and an untrusted issuer are HIGH; a merely-unsigned binary is
// INFO (unsigned is common for legitimate software, so it is made visible and
// counted, not escalated). A signature that could not be evaluated (an
// unreadable path when ProcessGuard runs non-elevated) is UNKNOWN and skipped,
// mirroring classifyUnsigned — reporting those would bury real findings under a
// wall of legitimate SYSTEM processes.
func runStage1Signing() []Finding {
	// The signing lens gets a tighter budget than the default: a slow whole-system
	// Authenticode pass (cold-cache revocation on a networked box) then degrades to
	// a stage-scoped INFO instead of a SCAN_ERROR that would flip the entire hunt
	// report to PARTIAL — the heuristic half of Stage 1 already ran.
	procs, err := collectProcessesWithSigning(25 * time.Second)
	if err != nil {
		return []Finding{{
			Stage:       1,
			Severity:    SeverityInfo,
			Category:    "SIGNING_LENS_UNAVAILABLE",
			Description: fmt.Sprintf("Authenticode signing lens did not complete (%v) — run get_unsigned_processes / get_process_tree directly to check process signatures.", err),
			Entity:      "process-signing",
			Confidence:  "HIGH",
		}}
	}
	return signingFindings(procs)
}

// signingFindings is the pure classification half of the Stage-1 signing lens —
// []procRow in, []Finding out — so the severity mapping is unit-testable without
// spawning PowerShell (the exact test gap that let the earlier detection bugs
// through).
func signingFindings(procs []procRow) []Finding {
	const maxUnsignedListed = 20
	var findings []Finding
	unsignedCount, listed := 0, 0

	for _, p := range procs {
		list, reason := classifyUnsigned(p.Status)
		if !list {
			continue
		}
		entity := fmt.Sprintf("PID %d (%s) @ %s", p.PID, p.Name, p.ExePath)

		switch strings.ToLower(strings.TrimSpace(p.Status)) {
		case "hashmismatch", "nottrusted":
			// Tampering / untrusted issuer — unambiguous, always escalated.
			findings = append(findings, Finding{
				Stage:       1,
				Severity:    SeverityHigh,
				Category:    "UNTRUSTED_SIGNATURE",
				Description: fmt.Sprintf("Process %q (PID %d) at %s: %s", p.Name, p.PID, p.ExePath, reason),
				Entity:      entity,
				Flags:       []string{"UNTRUSTED_SIGNATURE"},
				Confidence:  "MEDIUM",
			})
		case "notsigned":
			unsignedCount++
			if listed < maxUnsignedListed {
				listed++
				findings = append(findings, Finding{
					Stage:       1,
					Severity:    SeverityInfo,
					Category:    "UNSIGNED_PROCESS",
					Description: fmt.Sprintf("Unsigned process %q (PID %d) at %s — %s. Unsigned is common for legitimate software; triage with lookup_hash.", p.Name, p.PID, p.ExePath, reason),
					Entity:      entity,
					Flags:       []string{"UNSIGNED"},
					Confidence:  "LOW",
				})
			}
		default:
			// A signature is present but could not be verified (UnknownError,
			// unsupported format, …) — reported honestly as UNVERIFIED, not
			// asserted to be "unsigned".
			if listed < maxUnsignedListed {
				listed++
				findings = append(findings, Finding{
					Stage:       1,
					Severity:    SeverityInfo,
					Category:    "UNVERIFIED_SIGNATURE",
					Description: fmt.Sprintf("Process %q (PID %d) at %s — %s.", p.Name, p.PID, p.ExePath, reason),
					Entity:      entity,
					Flags:       []string{"SIGNATURE_UNVERIFIED"},
					Confidence:  "LOW",
				})
			}
		}
	}

	if unsignedCount > 0 {
		extra := ""
		if unsignedCount > maxUnsignedListed {
			extra = fmt.Sprintf(" First %d listed above; run get_unsigned_processes for the full set.", maxUnsignedListed)
		}
		findings = append(findings, Finding{
			Stage:       1,
			Severity:    SeverityInfo,
			Category:    "UNSIGNED_SUMMARY",
			Description: fmt.Sprintf("Authenticode: %d running process(es) without a trusted signature.%s", unsignedCount, extra),
			Entity:      "process-signing",
			Confidence:  "HIGH",
		})
	}
	return findings
}

// runStage2 maps flagged autorun entries to findings. The entries are fetched
// once in RunFullHunt and shared with Stage 5 (previously each stage re-ran
// autorunsc, doubling hunt time). A fetch error is surfaced, not swallowed.
func runStage2(available bool, entries []AutorunEntry, fetchErr error) []Finding {
	var findings []Finding
	if !available {
		findings = append(findings, Finding{
			Stage:       2,
			Severity:    SeverityInfo,
			Category:    "TOOL_UNAVAILABLE",
			Description: "Autoruns (autorunsc.exe) not configured — persistence check skipped. Add autoruns_path to config.json.",
			Entity:      "autoruns",
			Confidence:  "HIGH",
		})
		return findings
	}
	if fetchErr != nil {
		return append(findings, scanError(2, "autoruns", fetchErr))
	}

	for _, e := range entries {
		if len(e.Flags) == 0 {
			continue // only surface anomalous (flagged) entries
		}
		severity := SeverityMedium
		if e.VTDetections > 0 {
			severity = SeverityCritical
		} else if e.SignerKnown && !e.IsVerified {
			// Only escalate on a KNOWN-unsigned entry; an absent signer column
			// means unknown, not unsigned.
			severity = SeverityHigh
		}
		findings = append(findings, Finding{
			Stage:       2,
			Severity:    severity,
			Category:    "PERSISTENCE_MECHANISM",
			Description: e.Reason,
			Entity:      fmt.Sprintf("%s @ %s", e.EntryName, e.EntryLocation),
			Flags:       e.Flags,
			Confidence:  "HIGH",
		})
	}
	return findings
}

// runStage3 runs foreign connection detection.
func runStage3(cfg *config.Config) []Finding {
	var findings []Finding

	raw, err := GetForeignConnections(cfg)
	if err != nil {
		return append(findings, scanError(3, "network", err))
	}
	var conns []EnrichedConnection
	if err := json.Unmarshal([]byte(raw), &conns); err != nil {
		return append(findings, scanError(3, "network", err))
	}

	for _, c := range conns {
		desc := fmt.Sprintf("Process %q (PID %d) has an ESTABLISHED connection to %s", c.ProcessName, c.PID, c.RemoteAddr)
		if c.GeoIP != nil && c.GeoIP.CountryName != "" {
			desc += fmt.Sprintf(" (%s)", c.GeoIP.CountryName)
		}
		findings = append(findings, Finding{
			Stage:       3,
			Severity:    SeverityMedium,
			Category:    "FOREIGN_CONNECTION",
			Description: desc,
			Entity:      fmt.Sprintf("%s → %s", c.LocalAddr, c.RemoteAddr),
			Flags:       c.Flags,
			Confidence:  "MEDIUM",
		})
	}
	return findings
}

// runStage4 queries Sysmon for the last 60 minutes of process creation and
// network connection events, flagging suspicious spawns and beacon-like patterns.
func runStage4(cfg *config.Config) []Finding {
	var findings []Finding
	if !cfg.Availability().Sysmon {
		findings = append(findings, Finding{
			Stage:       4,
			Severity:    SeverityInfo,
			Category:    "TOOL_UNAVAILABLE",
			Description: "Sysmon not configured. Install Sysmon and restart to enable forensic timeline.",
			Entity:      "sysmon",
			Confidence:  "HIGH",
		})
		return findings
	}

	// ── ID 1: ProcessCreate — suspicious parent-child spawns ────────────
	rawCreate, err := GetProcessCreateEvents(cfg, 60)
	if err != nil {
		findings = append(findings, scanError(4, "sysmon-processcreate", err))
	} else {
		var createEvents []SysmonEvent
		if json.Unmarshal([]byte(rawCreate), &createEvents) == nil {
			for _, e := range createEvents {
				if isSuspiciousParentInSysmon(e.ParentImage, e.ProcessName) {
					findings = append(findings, Finding{
						Stage:       4,
						Severity:    SeverityHigh,
						Category:    "SUSPICIOUS_SPAWN",
						Description: fmt.Sprintf("Sysmon: %q spawned by %q at %s", e.ProcessName, e.ParentImage, e.Timestamp),
						Entity:      fmt.Sprintf("PID %d", e.ProcessID),
						Flags:       []string{"SUSPICIOUS_PARENT", "SYSMON_EVIDENCE"},
						Confidence:  "HIGH",
					})
				}
			}
			if len(createEvents) > 0 {
				findings = append(findings, Finding{
					Stage:       4,
					Severity:    SeverityInfo,
					Category:    "SYSMON_SUMMARY",
					Description: fmt.Sprintf("Sysmon recorded %d process creation events in the last 60 minutes.", len(createEvents)),
					Entity:      "sysmon",
					Confidence:  "HIGH",
				})
			}
		}
	}

	// ── ID 3: NetworkConnect — detect unusual outbound connections ───────
	rawNet, err := GetNetworkEvents(cfg, 60)
	if err != nil {
		findings = append(findings, scanError(4, "sysmon-network", err))
	} else {
		var netEvents []SysmonEvent
		if json.Unmarshal([]byte(rawNet), &netEvents) == nil {
			// Beacon indicator: scripting hosts / admin tools making outbound internet connections
			beaconSources := []string{
				"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
				"mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
				"bitsadmin.exe", "msiexec.exe",
			}
			for _, e := range netEvents {
				srcLower := lowerBase(e.ProcessName)
				for _, b := range beaconSources {
					if srcLower == b && e.DestIP != "" {
						desc := fmt.Sprintf("Sysmon: %q made outbound connection to %s", e.ProcessName, e.DestIP)
						if e.DestPort > 0 {
							desc += fmt.Sprintf(":%d", e.DestPort)
						}
						if e.DestHostname != "" {
							desc += fmt.Sprintf(" (%s)", e.DestHostname)
						}
						if e.Timestamp != "" {
							desc += fmt.Sprintf(" at %s", e.Timestamp)
						}
						findings = append(findings, Finding{
							Stage:       4,
							Severity:    SeverityHigh,
							Category:    "BEACON_CANDIDATE",
							Description: desc,
							Entity:      fmt.Sprintf("PID %d -> %s", e.ProcessID, e.DestIP),
							Flags:       []string{"SCRIPTING_HOST_NETWORK", "SYSMON_EVIDENCE"},
							Confidence:  "HIGH",
						})
						break
					}
				}
			}
			if len(netEvents) > 0 {
				findings = append(findings, Finding{
					Stage:       4,
					Severity:    SeverityInfo,
					Category:    "SYSMON_NETWORK_SUMMARY",
					Description: fmt.Sprintf("Sysmon recorded %d network connection events in the last 60 minutes.", len(netEvents)),
					Entity:      "sysmon",
					Confidence:  "HIGH",
				})
			}
		}
	}

	return findings
}

func isSuspiciousParentInSysmon(parent, child string) bool {
	suspParents := []string{"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
		"acrord32.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe"}
	suspChildren := []string{"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
		"mshta.exe", "rundll32.exe", "regsvr32.exe"}

	pLower := lowerBase(parent)
	cLower := lowerBase(child)

	for _, sp := range suspParents {
		if pLower == sp {
			for _, sc := range suspChildren {
				if cLower == sc {
					return true
				}
			}
		}
	}
	return false
}

func lowerBase(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			path = path[i+1:]
			break
		}
	}
	result := make([]byte, len(path))
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

// runStage5 performs VirusTotal hash lookups on autoruns entries that carry
// a SHA256. Any entry with VT detections is escalated to CRITICAL. The entries
// are the ones already fetched once in RunFullHunt (shared with Stage 2).
// Skipped when vt_api_key is not configured.
func runStage5(cfg *config.Config, avail config.ToolAvailability, entries []AutorunEntry) []Finding {
	var findings []Finding
	if !avail.VirusTotal {
		findings = append(findings, Finding{
			Stage:       5,
			Severity:    SeverityInfo,
			Category:    "TOOL_UNAVAILABLE",
			Description: "VirusTotal API key not configured — hash reputation scoring skipped. Add vt_api_key to config.json.",
			Entity:      "virustotal",
			Confidence:  "HIGH",
		})
		return findings
	}
	if !avail.Autoruns {
		return findings // nothing to score without autoruns hashes
	}

	checked := 0
	for _, e := range entries {
		if e.SHA256 == "" || len(e.SHA256) != 64 {
			continue
		}
		if checked >= 10 { // cap VT calls per hunt to stay within free-tier limits
			break
		}
		checked++
		vtRaw, err := LookupHash(cfg, e.SHA256)
		if err != nil {
			continue
		}
		var report VTReport
		if err := json.Unmarshal([]byte(vtRaw), &report); err != nil {
			continue
		}
		if report.Malicious == 0 {
			continue
		}
		severity := SeverityHigh
		if report.Malicious >= 5 {
			severity = SeverityCritical
		}
		findings = append(findings, Finding{
			Stage:       5,
			Severity:    severity,
			Category:    "VT_DETECTION",
			Description: fmt.Sprintf("VirusTotal: autorun entry %q scored %s — %d engine(s) flagged as malicious", e.EntryName, report.Score, report.Malicious),
			Entity:      fmt.Sprintf("%s @ %s", e.EntryName, e.EntryLocation),
			Flags:       []string{"VT_HIT", "PERSISTENCE_MECHANISM"},
			Confidence:  "HIGH",
		})
	}
	return findings
}

// scanError surfaces a stage that failed to complete as a visible finding, so a
// crashed or erroring probe is never silently mistaken for a clean result.
func scanError(stage int, entity string, err error) Finding {
	return Finding{
		Stage:       stage,
		Severity:    SeverityInfo,
		Category:    "SCAN_ERROR",
		Description: fmt.Sprintf("Stage %d (%s) did not complete: %v — findings for this stage may be incomplete.", stage, entity, err),
		Entity:      entity,
		Confidence:  "HIGH",
	}
}

func buildRecommendations(r HuntReport) []string {
	var recs []string
	stageErrors := 0
	for _, f := range r.Findings {
		if f.Category == "SCAN_ERROR" {
			stageErrors++
		}
	}
	if stageErrors > 0 {
		recs = append(recs, fmt.Sprintf("INVESTIGATE: %d hunting stage(s) failed to complete — re-run (elevated if needed); a partial hunt can hide threats in the stages that did not run.", stageErrors))
	}
	if len(r.Critical) > 0 {
		recs = append(recs, fmt.Sprintf("IMMEDIATE: Investigate %d CRITICAL finding(s) — these indicate active or confirmed compromise.", len(r.Critical)))
	}
	if len(r.High) > 0 {
		recs = append(recs, fmt.Sprintf("HIGH PRIORITY: Review %d HIGH severity finding(s) and determine if they represent malicious activity.", len(r.High)))
	}
	if !r.Availability.Autoruns {
		recs = append(recs, "Configure autoruns_path in config.json to enable full persistence check (Stage 2).")
	}
	if !r.Availability.Sysmon {
		recs = append(recs, "Install Sysmon with a configuration file to enable forensic timeline (Stage 4).")
	}
	if !r.Availability.VirusTotal {
		recs = append(recs, "Add a free VirusTotal API key (vt_api_key) to config.json to enable hash reputation scoring.")
	}
	if len(recs) == 0 {
		recs = append(recs, "No immediate actions required. Schedule a monthly hunt using run_full_hunt.")
	}
	return recs
}

func buildSummary(r HuntReport) string {
	stageErrors := 0
	for _, f := range r.Findings {
		if f.Category == "SCAN_ERROR" {
			stageErrors++
		}
	}
	partial := ""
	if stageErrors > 0 {
		partial = fmt.Sprintf(" WARNING: %d stage(s) did not complete — results are PARTIAL; absence of findings is NOT proof of a clean system (re-run elevated).", stageErrors)
	}
	total := len(r.Findings)
	if total == 0 {
		return "Full hunt complete. No suspicious indicators were detected across all configured stages." + partial
	}
	return fmt.Sprintf(
		"Hunt complete in %dms. Found %d indicator(s): %d CRITICAL, %d HIGH, %d MEDIUM, %d INFO. "+
			"Immediate review required for CRITICAL and HIGH findings.%s",
		r.DurationMs, total, len(r.Critical), len(r.High), len(r.Medium), len(r.Info), partial,
	)
}
