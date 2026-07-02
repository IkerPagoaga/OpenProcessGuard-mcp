// Package parse holds the pure output parsers for the external tools
// ProcessGuard shells out to. They take raw command output as a string and
// return structured data with no I/O, which makes every one of them unit
// testable against fixture strings — the property the handlers lacked before.
package parse

import (
	"strconv"
	"strings"
)

// NetConn is one parsed row of `netstat -ano` output.
type NetConn struct {
	Protocol   string
	LocalAddr  string
	RemoteAddr string
	Status     string
	PID        int32
	HasPID     bool
}

// Netstat parses `netstat -ano` output into connection rows.
//
// The protocol names TCP/UDP are not localised by Windows, so filtering on them
// is locale-robust; the PID is always the final whitespace-delimited field on a
// row (4 fields for UDP: proto/local/foreign/pid; 5 for TCP:
// proto/local/foreign/state/pid). The PID is parsed with a checked conversion,
// so a malformed row is dropped from PID attribution instead of silently
// becoming PID 0 (which previously polluted results by mapping to System).
func Netstat(raw string) []NetConn {
	var conns []NetConn
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" {
			continue // header, "Active Connections", or a non-IP row
		}

		c := NetConn{Protocol: proto, LocalAddr: fields[1]}
		if len(fields) >= 3 {
			c.RemoteAddr = fields[2] // "*:*" for UDP / listeners; a real addr for TCP
		}
		// Only TCP carries a connection-state column (fields[3]); UDP is stateless,
		// so we do not fabricate a status for it.
		if proto == "TCP" && len(fields) >= 5 {
			c.Status = fields[3]
		}

		if pid, err := strconv.ParseInt(fields[len(fields)-1], 10, 32); err == nil {
			c.PID = int32(pid)
			c.HasPID = true
		}
		conns = append(conns, c)
	}
	return conns
}

// RemoteIP extracts the host portion from a netstat address, handling IPv4
// (`1.2.3.4:80`), bracketed IPv6 (`[::1]:80`), a bare IPv6 with no port, and a
// malformed bracket — without ever mis-slicing an IPv6 address as if the last
// colon were a port separator.
func RemoteIP(addr string) string {
	if addr == "" || addr == "*" {
		return ""
	}
	// [IPv6]:port
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i >= 0 {
			return addr[1:i]
		}
		return strings.TrimPrefix(addr, "[") // malformed — best effort
	}
	// Bare IPv6 (two or more colons, no brackets) carries no :port suffix.
	if strings.Count(addr, ":") > 1 {
		return addr
	}
	// IPv4:port
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}
