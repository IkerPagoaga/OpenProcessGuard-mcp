package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
//  3. Zero-config defaults (native Stage-0 tools only) when no config.json exists
//
// It never reads os.Stdin: under an MCP client stdin carries the JSON-RPC stream,
// so a blocking prompt there would consume the initialize frame and hang the
// handshake. A config.json that exists but is malformed is a fatal error rather
// than a silent fall-through, for the same reason.
func Load() (*Config, error) {
	cfg := configDefaults

	if v := os.Getenv("PROCEXP_PATH"); v != "" {
		cfg.ProcessExplorerPath = v
		applyDefaults(&cfg)
		return &cfg, nil
	}

	exeDir, err := execDir()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve executable directory: %w", err)
	}
	cfgPath := filepath.Join(exeDir, configFileName)

	data, readErr := os.ReadFile(cfgPath)
	switch {
	case readErr == nil:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("config.json at %s is present but not valid JSON: %w — fix or remove it", cfgPath, err)
		}
		applyDefaults(&cfg)
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("config validation failed: %w", err)
		}
		return &cfg, nil

	case os.IsNotExist(readErr):
		// Zero-config first run: native Stage-0 tools work immediately; optional
		// stages (Autoruns / Sysmon / VirusTotal / GeoIP) stay disabled until a
		// config.json is added next to the binary.
		applyDefaults(&cfg)
		fmt.Fprintf(os.Stderr, "ProcessGuard: no config.json at %s — running with native tools only. "+
			"Copy config.example.json to enable the optional stages.\n", cfgPath)
		return &cfg, nil

	default:
		return nil, fmt.Errorf("cannot read config.json at %s: %w", cfgPath, readErr)
	}
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
