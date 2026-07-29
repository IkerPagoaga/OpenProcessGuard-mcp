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
	scan, err := foreignConnections(ctx, cfg)
	if err != nil {
		return "", err
	}

	out := struct {
		GeoIPEnabled bool                 `json:"geoip_enabled"`
		GeoIPError   string               `json:"geoip_error,omitempty"`
		Count        int                  `json:"count"`
		Connections  []EnrichedConnection `json:"connections"`
	}{
		GeoIPEnabled: scan.GeoEnabled,
		Count:        len(scan.Connections),
		Connections:  scan.Connections,
	}
	if scan.GeoErr != nil {
		out.GeoIPError = fmt.Sprintf(
			"geoip_db is configured but could not be opened (%v) — country attribution is DISABLED for this result. "+
				"Private-range filtering still applied.", scan.GeoErr)
	}

	result, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// foreignScan carries the foreign-connection rows plus the GeoIP enrichment STATUS.
// That status is load-bearing: a geoip_db pointing at a corrupt or unreadable mmdb was
// previously swallowed here, while config.Availability() had already reported
// geoip:true from a bare fileExists check — so the hunt report claimed country
// enrichment it never performed and every row simply came back without one.
type foreignScan struct {
	Connections []EnrichedConnection
	GeoEnabled  bool
	GeoErr      error
}

// foreignConnections is the internal scan path. In-process callers (run_full_hunt) use
// it instead of unmarshalling the tool-facing JSON, so they receive the GeoIP status as
// typed data rather than losing it.
func foreignConnections(ctx context.Context, cfg *config.Config) (foreignScan, error) {
	all, err := collectConnections(ctx, cfg)
	if err != nil {
		return foreignScan{}, err
	}

	var scan foreignScan

	// Always open a DB so Lookup() can detect private ranges.
	// When geoip_db is empty, Open("") returns a no-op DB that only
	// classifies private vs public — no country data, no file required.
	var db *geoip.DB
	if cfg.GeoIPDB != "" {
		opened, openErr := geoip.Open(cfg.GeoIPDB)
		if openErr != nil {
			// Configured but unusable. Record it and fall through to the no-op DB so
			// private-range filtering still works — but never continue as though
			// enrichment were active.
			scan.GeoErr = openErr
		} else {
			db = opened
			scan.GeoEnabled = true
			defer db.Close()
		}
	}
	if db == nil {
		db, _ = geoip.Open("") // no-op: private-range detection only
	}
	geoEnabled := scan.GeoEnabled

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
	scan.Connections = foreign
	return scan, nil
}

// collectConnections runs netstat and returns all connections enriched with
// process names.
func collectConnections(ctx context.Context, cfg *config.Config) ([]EnrichedConnection, error) {
	pidNames := map[int32]string{}
	procs, _ := process.Processes()
	for _, p := range procs {
		if name, err := p.Name(); err == nil {
			pidNames[p.Pid] = name
		}
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
