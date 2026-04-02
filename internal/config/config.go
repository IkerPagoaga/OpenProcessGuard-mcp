package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const configFileName = "config.json"

// sysmonLogRe whitelists valid Sysmon log channel names.
// Allowed chars: alphanumeric, space, hyphen, slash, underscore, dot.
// This prevents PowerShell injection via a crafted sysmon_log value.
var sysmonLogRe = regexp.MustCompile(`^[A-Za-z0-9 \-/_\.]+$`)

type Config struct {
	ProcessExplorerPath string `json:"procexp_path"`
	AutorunsPath        string `json:"autoruns_path"`
	TCPViewPath         string `json:"tcpview_path"`
	SysmonLog           string `json:"sysmon_log"`
	VTAPIKey            string `json:"vt_api_key"`
	GeoIPDB             string `json:"geoip_db"`
	AuditLog            bool   `json:"audit_log"`
}

var configDefaults = Config{
	SysmonLog: "Microsoft-Windows-Sysmon/Operational",
	AuditLog:  true,
}

// Load resolves config in priority order:
//  1. PROCEXP_PATH env var (legacy compat)
//  2. config.json next to the binary
//  3. Interactive prompt on first run
func Load() (*Config, error) {
	cfg := configDefaults

	if v := os.Getenv("PROCEXP_PATH"); v != "" {
		cfg.ProcessExplorerPath = v
		applyDefaults(&cfg)
		return &cfg, nil
	}

	exeDir, err := execDir()
	if err == nil {
		cfgPath := filepath.Join(exeDir, configFileName)
		if data, err := os.ReadFile(cfgPath); err == nil {
			if err := json.Unmarshal(data, &cfg); err == nil {
				applyDefaults(&cfg)
				if err := cfg.validate(); err != nil {
					return nil, fmt.Errorf("config validation failed: %w", err)
				}
				return &cfg, nil
			}
		}
	}

	// Interactive first-run prompt
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│  ProcessGuard MCP — First Run Setup                  │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "ProcessExplorer (procexp64.exe) path not found.")
	fmt.Fprintln(os.Stderr, "Common locations:")
	fmt.Fprintln(os.Stderr, "  C:\\Users\\<you>\\Downloads\\ProcessExplorer\\procexp64.exe")
	fmt.Fprintln(os.Stderr, "  C:\\Tools\\SysinternalsSuite\\procexp64.exe")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprint(os.Stderr, "Enter full path to procexp64.exe (or press Enter to skip): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read path: %w", err)
	}
	input = strings.TrimSpace(input)
	cfg.ProcessExplorerPath = input
	applyDefaults(&cfg)

	if exeDir != "" {
		save(filepath.Join(exeDir, configFileName), &cfg)
	}

	return &cfg, nil
}

// validate checks that config values are within expected safe bounds.
// This prevents injection attacks via crafted config values.
func (c *Config) validate() error {
	if c.SysmonLog != "" && !sysmonLogRe.MatchString(c.SysmonLog) {
		return fmt.Errorf("sysmon_log contains invalid characters — only alphanumeric, space, hyphen, slash, underscore, and dot are allowed")
	}
	return nil
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
	os.WriteFile(path, data, 0600)
}

func execDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// ToolAvailability reports which hunting stages are available.
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
