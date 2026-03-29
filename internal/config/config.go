package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const configFileName = "config.json"

type Config struct {
	// Stage 0 — existing
	ProcessExplorerPath string `json:"procexp_path"`

	// Stage 1 — Process Explorer headless CSV
	// procexp64.exe /accepteula /t exports to CSV; path validated at startup.
	// Leave empty to skip Process Explorer tools gracefully.

	// Stage 2 — Autoruns
	// autorunsc.exe -a * -c -h -v -u  (headless CSV with hashes + VirusTotal)
	AutorunsPath string `json:"autoruns_path"`

	// Stage 3 — TCPView / network enrichment
	// tcpvcon.exe -c exports CSV; used for richer connection state + process correlation.
	TCPViewPath string `json:"tcpview_path"`

	// Stage 4 — Sysmon forensic layer
	// Windows Event Log channel; default is the standard Sysmon channel.
	SysmonLog string `json:"sysmon_log"`

	// VirusTotal API key (free tier: 4 req/min, 500 req/day)
	// Stored here, NEVER echoed in any tool response.
	VTAPIKey string `json:"vt_api_key"`

	// GeoIP database path — MaxMind GeoLite2-City.mmdb
	GeoIPDB string `json:"geoip_db"`

	// AuditLog enables JSONL audit logging to %APPDATA%\ProcessGuard\audit.log
	AuditLog bool `json:"audit_log"`
}

// Defaults applied when fields are missing from config.json.
var configDefaults = Config{
	SysmonLog: "Microsoft-Windows-Sysmon/Operational",
	AuditLog:  true,
}

// Load resolves config in priority order:
//  1. PROCEXP_PATH env var (legacy compat — populates ProcessExplorerPath only)
//  2. config.json next to the binary
//  3. Interactive prompt for ProcessExplorerPath on first run
func Load() (*Config, error) {
	cfg := configDefaults // copy defaults

	// 1. Legacy env var
	if v := os.Getenv("PROCEXP_PATH"); v != "" {
		cfg.ProcessExplorerPath = v
		return &cfg, nil
	}

	// 2. config.json next to binary
	exeDir, err := execDir()
	if err == nil {
		cfgPath := filepath.Join(exeDir, configFileName)
		if data, err := os.ReadFile(cfgPath); err == nil {
			if err := json.Unmarshal(data, &cfg); err == nil && cfg.ProcessExplorerPath != "" {
				applyDefaults(&cfg)
				return &cfg, nil
			}
		}
	}

	// 3. Interactive first-run prompt
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│  ProcessGuard MCP — First Run Setup                 │")
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────┘")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "ProcessExplorer (procexp64.exe) path not found.")
	fmt.Fprintln(os.Stderr, "Common locations:")
	fmt.Fprintln(os.Stderr, "  C:\\Users\\<you>\\Downloads\\ProcessExplorer\\procexp64.exe")
	fmt.Fprintln(os.Stderr, "  C:\\Tools\\SysinternalsSuite\\procexp64.exe")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprint(os.Stderr, "Enter full path to procexp64.exe: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read path: %w", err)
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("no path provided")
	}

	cfg.ProcessExplorerPath = input
	applyDefaults(&cfg)

	if exeDir != "" {
		save(filepath.Join(exeDir, configFileName), &cfg)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.SysmonLog == "" {
		cfg.SysmonLog = configDefaults.SysmonLog
	}
}

func save(path string, cfg *Config) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0644)
}

func execDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// ToolAvailability reports which hunting stages are available given current config.
type ToolAvailability struct {
	ProcessExplorer bool
	Autoruns        bool
	TCPView         bool
	Sysmon          bool
	VirusTotal      bool
	GeoIP           bool
}

// Availability checks which optional tools are configured and accessible.
func (c *Config) Availability() ToolAvailability {
	return ToolAvailability{
		ProcessExplorer: c.ProcessExplorerPath != "" && fileExists(c.ProcessExplorerPath),
		Autoruns:        c.AutorunsPath != "" && fileExists(c.AutorunsPath),
		TCPView:         c.TCPViewPath != "" && fileExists(c.TCPViewPath),
		Sysmon:          c.SysmonLog != "",
		VirusTotal:      c.VTAPIKey != "",
		GeoIP:           c.GeoIPDB != "" && fileExists(c.GeoIPDB),
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
