package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
	"processguard-mcp/internal/config"
	"processguard-mcp/internal/geoip"
	"processguard-mcp/internal/parse"
	"processguard-mcp/internal/run"
)

// EnrichedConnection is a network connection with process name, state filter,
// and optional GeoIP context.
type EnrichedConnection struct {
	PID         int32           `json:"pid"`
	ProcessName string          `json:"process_name"`
	Protocol    string          `json:"protocol"`
	LocalAddr   string          `json:"local_addr"`
	RemoteAddr  string          `json:"remote_addr"`
	Status      string          `json:"status"`
	GeoIP       *geoip.Location `json:"geoip,omitempty"`
	Flags       []string        `json:"flags,omitempty"`
}

// GetEstablishedConnections returns only ESTABLISHED TCP connections,
// enriched with process names and optional GeoIP data.
func GetEstablishedConnections(ctx context.Context, cfg *config.Config) (string, error) {
	all, err := collectConnections(ctx, cfg)
	if err != nil {
		return "", err
	}
	var est []EnrichedConnection
	for _, c := range all {
		if strings.EqualFold(c.Status, "ESTABLISHED") {
			est = append(est, c)
		}
	}
	if est == nil {
		est = []EnrichedConnection{}
	}
	result, err := json.MarshalIndent(est, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// GetForeignConnections returns ESTABLISHED connections to non-private IPs,
// which is the primary C2 / data-exfiltration indicator.
//
// Private-IP filtering is always applied regardless of whether geoip_db is
// configured.  GeoIP country/city enrichment only happens when geoip_db points
// to a valid MaxMind mmdb file.
func GetForeignConnections(ctx context.Context, cfg *config.Config) (string, error) {
	all, err := collectConnections(ctx, cfg)
	if err != nil {
		return "", err
	}

	// Always open a DB so Lookup() can detect private ranges.
	// When geoip_db is empty, Open("") returns a no-op DB that only
	// classifies private vs public — no country data, no file required.
	var db *geoip.DB
	var geoEnabled bool
	if cfg.GeoIPDB != "" {
		if opened, err := geoip.Open(cfg.GeoIPDB); err == nil {
			db = opened
			geoEnabled = true
			defer db.Close()
		}
	}
	if db == nil {
		db, _ = geoip.Open("") // no-op: private-range detection only
	}

	var foreign []EnrichedConnection
	for _, c := range all {
		if !strings.EqualFold(c.Status, "ESTABLISHED") {
			continue
		}
		remoteIP := parse.RemoteIP(c.RemoteAddr)
		if remoteIP == "" || remoteIP == "*" || remoteIP == "0.0.0.0" {
			continue
		}
		if db != nil {
			loc := db.Lookup(remoteIP)
			if loc.IsPrivate {
				continue
			}
			if geoEnabled {
				locCopy := loc
				c.GeoIP = &locCopy
			}
		}
		c.Flags = append(c.Flags, "FOREIGN_CONNECTION")
		foreign = append(foreign, c)
	}
	if foreign == nil {
		foreign = []EnrichedConnection{}
	}
	result, err := json.MarshalIndent(foreign, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// collectConnections runs netstat and returns all connections enriched with
// process names. Uses tcpvcon.exe if configured, falls back to netstat.
func collectConnections(ctx context.Context, cfg *config.Config) ([]EnrichedConnection, error) {
	pidNames := map[int32]string{}
	procs, _ := process.Processes()
	for _, p := range procs {
		if name, err := p.Name(); err == nil {
			pidNames[p.Pid] = name
		}
	}

	if cfg.TCPViewPath != "" {
		// TODO(P3): tcpvcon.exe -c -a outputs a CSV with richer state info.
		// Fall through to netstat for now.
	}

	return netstatConnections(ctx, pidNames)
}

// netstatConnections runs `netstat -ano` (under a bounded timeout) and maps the
// parsed rows onto enriched connections with process names.
func netstatConnections(ctx context.Context, pidNames map[int32]string) ([]EnrichedConnection, error) {
	out, err := run.ToolCtx(ctx, run.DefaultTimeout, "netstat", "-ano")
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var conns []EnrichedConnection
	for _, c := range parse.Netstat(string(out)) {
		conn := EnrichedConnection{
			Protocol:   c.Protocol,
			LocalAddr:  c.LocalAddr,
			RemoteAddr: c.RemoteAddr,
			Status:     c.Status,
		}
		if c.HasPID {
			conn.PID = c.PID
			conn.ProcessName = pidNames[c.PID]
		}
		conns = append(conns, conn)
	}
	return conns, nil
}
