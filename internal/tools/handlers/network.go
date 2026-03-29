package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"processguard-mcp/internal/config"
	"processguard-mcp/internal/geoip"
	"github.com/shirou/gopsutil/v3/process"
)

// EnrichedConnection is a network connection with process name, state filter,
// and optional GeoIP context.
type EnrichedConnection struct {
	PID         int32          `json:"pid"`
	ProcessName string         `json:"process_name"`
	Protocol    string         `json:"protocol"`
	LocalAddr   string         `json:"local_addr"`
	RemoteAddr  string         `json:"remote_addr"`
	Status      string         `json:"status"`
	GeoIP       *geoip.Location `json:"geoip,omitempty"`
	Flags       []string       `json:"flags,omitempty"`
}

// GetEstablishedConnections returns only ESTABLISHED TCP connections,
// enriched with process names and optional GeoIP data.
func GetEstablishedConnections(cfg *config.Config) (string, error) {
	all, err := collectConnections(cfg)
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
func GetForeignConnections(cfg *config.Config) (string, error) {
	all, err := collectConnections(cfg)
	if err != nil {
		return "", err
	}

	var db *geoip.DB
	if cfg.GeoIPDB != "" {
		db, _ = geoip.Open(cfg.GeoIPDB)
		if db != nil {
			defer db.Close()
		}
	}

	var foreign []EnrichedConnection
	for _, c := range all {
		if !strings.EqualFold(c.Status, "ESTABLISHED") {
			continue
		}
		// Extract IP from "1.2.3.4:port" format
		remoteIP := remoteIPFromAddr(c.RemoteAddr)
		if remoteIP == "" || remoteIP == "*" || remoteIP == "0.0.0.0" {
			continue
		}
		if db != nil {
			loc := db.Lookup(remoteIP)
			if loc.IsPrivate {
				continue
			}
			c.GeoIP = &loc
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
func collectConnections(cfg *config.Config) ([]EnrichedConnection, error) {
	// Build PID -> name map
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

	return netstatConnections(pidNames)
}

// netstatConnections parses netstat -ano output.
func netstatConnections(pidNames map[int32]string) ([]EnrichedConnection, error) {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var conns []EnrichedConnection
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" {
			continue
		}
		conn := EnrichedConnection{
			Protocol:  proto,
			LocalAddr: fields[1],
		}
		if proto == "TCP" && len(fields) >= 5 {
			conn.RemoteAddr = fields[2]
			conn.Status = fields[3]
			if pid, err := strconv.ParseInt(fields[4], 10, 32); err == nil {
				conn.PID = int32(pid)
				conn.ProcessName = pidNames[int32(pid)]
			}
		} else if proto == "UDP" && len(fields) >= 4 {
			conn.RemoteAddr = "*"
			conn.Status = "LISTENING"
			if pid, err := strconv.ParseInt(fields[3], 10, 32); err == nil {
				conn.PID = int32(pid)
				conn.ProcessName = pidNames[int32(pid)]
			}
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func remoteIPFromAddr(addr string) string {
	if addr == "" || addr == "*" {
		return ""
	}
	// Handle IPv6: [::1]:80
	if strings.HasPrefix(addr, "[") {
		if i := strings.LastIndex(addr, "]"); i >= 0 {
			return addr[1:i]
		}
	}
	// IPv4: 1.2.3.4:80
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}
