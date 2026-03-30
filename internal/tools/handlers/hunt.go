package handlers

import (
	"encoding/json"
	"fmt"
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
	Stage       int      `json:"stage"`         // 1=ProcEx, 2=Autoruns, 3=Network, 4=Sysmon
	Severity    string   `json:"severity"`      // CRITICAL/HIGH/MEDIUM/INFO
	Category    string   `json:"category"`      // e.g. "PROCESS_HOLLOWING", "C2_BEACON"
	Description string   `json:"description"`
	Entity      string   `json:"entity"`        // PID, path, IP, or autorun key
	Flags       []string `json:"flags,omitempty"`
	Confidence  string   `json:"confidence"`    // HIGH/MEDIUM/LOW
}

// HuntReport is the structured output of run_full_hunt.
type HuntReport struct {
	ScanTimestamp    string    `json:"scan_timestamp"`
	DurationMs       int64     `json:"duration_ms"`
	ExecutiveSummary string    `json:"executive_summary"`
	Availability     struct {
		ProcessExplorer bool `json:"process_explorer"`
		Autoruns        bool `json:"autoruns"`
		Sysmon          bool `json:"sysmon"`
		VirusTotal      bool `json:"virus_total"`
		GeoIP           bool `json:"geo_ip"`
	} `json:"tool_availability"`
	Findings          []Finding `json:"findings"`
	Critical          []Finding `json:"critical"`
	High              []Finding `json:"high"`
	Medium            []Finding `json:"medium"`
	Info              []Finding `json:"info"`
	RecommendedActions []string `json:"recommended_actions"`
}

// RunFullHunt orchestrates all four hunting stages and returns a HuntReport.
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

	// ── Stage 1: Process Integrity ─────────────────────────────────
	stage1Findings := runStage1(cfg)
	findings = append(findings, stage1Findings...)

	// ── Stage 2: Persistence (Autoruns) ───────────────────────────
	stage2Findings := runStage2(cfg)
	findings = append(findings, stage2Findings...)

	// ── Stage 3: Network Visibility ────────────────────────────────
	stage3Findings := runStage3(cfg)
	findings = append(findings, stage3Findings...)

	// ── Stage 4: Sysmon Forensics (last 60 min) ───────────────────
	stage4Findings := runStage4(cfg)
	findings = append(findings, stage4Findings...)

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
	if report.Critical == nil { report.Critical = []Finding{} }
	if report.High == nil { report.High = []Finding{} }
	if report.Medium == nil { report.Medium = []Finding{} }
	if report.Info == nil { report.Info = []Finding{} }
	if report.Findings == nil { report.Findings = []Finding{} }

	report.RecommendedActions = buildRecommendations(report)
	report.ExecutiveSummary = buildSummary(report)
	report.DurationMs = time.Since(start).Milliseconds()

	result, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}
	return string(result), nil
}

// runStage1 runs get_suspicious_processes and maps flags to Finding objects.
func runStage1(cfg *config.Config) []Finding {
	var findings []Finding

	raw, err := GetSuspiciousProcesses()
	if err != nil {
		return findings
	}
	var procs []SuspiciousProcess
	if err := json.Unmarshal([]byte(raw), &procs); err != nil {
		return findings
	}

	for _, p := range procs {
		severity := SeverityMedium
		for _, flag := range p.Flags {
			if flag == FlagNameSpoof || flag == FlagWrongPath || flag == FlagNoPath {
				severity = SeverityHigh
				break
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
	return findings
}

// runStage2 runs autorun anomaly detection if Autoruns is configured.
func runStage2(cfg *config.Config) []Finding {
	var findings []Finding
	if !cfg.Availability().Autoruns {
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

	raw, err := FlagAutorunsAnomalies(cfg)
	if err != nil {
		return findings
	}
	var entries []AutorunEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return findings
	}

	for _, e := range entries {
		severity := SeverityMedium
		if e.VTDetections > 0 {
			severity = SeverityCritical
		} else if !e.IsVerified {
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
		return findings
	}
	var conns []EnrichedConnection
	if err := json.Unmarshal([]byte(raw), &conns); err != nil {
		return findings
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
	if err == nil {
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
	if err == nil {
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

func buildRecommendations(r HuntReport) []string {
	var recs []string
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
	total := len(r.Findings)
	if total == 0 {
		return "Full hunt complete. No suspicious indicators were detected across all configured stages."
	}
	return fmt.Sprintf(
		"Hunt complete in %dms. Found %d indicator(s): %d CRITICAL, %d HIGH, %d MEDIUM, %d INFO. "+
			"Immediate review required for CRITICAL and HIGH findings.",
		r.DurationMs, total, len(r.Critical), len(r.High), len(r.Medium), len(r.Info),
	)
}
