package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
	"processguard-mcp/internal/parse"
	"processguard-mcp/internal/run"
)

// secretPatterns are env var NAME substrings that indicate a sensitive value.
// Matched case-insensitively; a matching var's value is replaced with "[REDACTED]".
var secretPatterns = []string{
	"token", "secret", "password", "passwd", "pwd",
	"key", "apikey", "api_key", "credential", "auth",
	"private", "cert", "jwt", "bearer",
	// Connection strings and DSNs routinely embed credentials even when the name
	// contains no "password"/"secret" token.
	"connection", "database_url", "dsn",
}

// secretValuePrefixes are well-known high-entropy secret formats. A value with
// one of these prefixes is redacted regardless of its variable NAME — this
// catches a real credential stashed in a benignly-named var (e.g. FOO=ghp_…)
// that name-based matching alone would leak.
var secretValuePrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "github_pat_", // GitHub tokens / PATs
	"glpat-",       // GitLab PATs
	"shpat_",       // Shopify access tokens
	"AKIA", "ASIA", // AWS access key IDs
	"xox",                  // Slack tokens (xoxb-/xoxp-/xoxa-…)
	"xai-",                 // xAI keys
	"sk-",                  // OpenAI / Anthropic / Stripe secret keys
	"rk_live_", "rk_test_", // Stripe restricted keys
	"AIza",       // Google API keys
	"1//",        // Google OAuth refresh tokens
	"SG.",        // SendGrid API keys
	"npm_",       // npm tokens
	"dop_v1_",    // DigitalOcean tokens
	"dckr_pat_",  // Docker Hub PATs
	"-----BEGIN", // PEM private keys / certificates
	"eyJ",        // JWT (base64 of '{"…')
}

// isSensitiveEnvVar returns true if the env var NAME looks like a secret.
func isSensitiveEnvVar(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range secretPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// looksLikeSecretValue returns true if the VALUE carries a well-known secret
// prefix, so a credential in a benignly-named variable is still redacted.
func looksLikeSecretValue(v string) bool {
	t := strings.TrimSpace(v)
	for _, p := range secretValuePrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// envValueAllowlist is the curated set of environment-variable NAMES whose VALUES
// are non-sensitive and safe to surface. get_process_detail uses a default-DENY
// (allowlist) model: a variable's value is shown ONLY if its name is in this set, so a
// credential in an unrecognised, benignly-named variable can never leak into the
// model's context regardless of the value's format. The variable NAME is always
// listed either way — a suspicious name is itself forensic signal; only the VALUE is
// gated. Names are matched case-insensitively.
var envValueAllowlist = map[string]bool{
	// OS / hardware identity
	"os": true, "systemroot": true, "systemdrive": true, "windir": true,
	"comspec": true, "pathext": true, "driverdata": true,
	"number_of_processors": true, "processor_architecture": true,
	"processor_architew6432": true, "processor_identifier": true,
	"processor_level": true, "processor_revision": true, "computername": true,
	// Well-known program / data locations (paths, not secrets)
	"path": true, "programfiles": true, "programfiles(x86)": true,
	"programw6432": true, "programdata": true, "commonprogramfiles": true,
	"commonprogramfiles(x86)": true, "commonprogramw6432": true,
	"public": true, "allusersprofile": true,
	// Per-user locations (embed the username, not a secret — forensically useful)
	"userprofile": true, "homedrive": true, "homepath": true,
	"appdata": true, "localappdata": true, "temp": true, "tmp": true,
	"username": true,
	// Session / locale / shell (low-sensitivity)
	"sessionname": true,
	"lang":        true, "lc_all": true, "tz": true, "term": true,
	// Deliberately NOT allowlisted: LOGONSERVER (domain-controller UNC),
	// USERDOMAIN / USERDOMAIN_ROAMINGPROFILE (AD domain) — surfacing these values
	// hands an LLM transcript a ready-made lateral-movement recon set. PROMPT is
	// arbitrary, freely-writable, zero-triage-value. Their NAMES still appear; only
	// the values are withheld.
}

// isAllowlistedEnvVar reports whether an env var's VALUE is safe to surface.
func isAllowlistedEnvVar(name string) bool {
	return envValueAllowlist[strings.ToLower(strings.TrimSpace(name))]
}

// redactedEnvValue applies the default-deny allowlist model: it returns the real
// value only for an allowlisted variable that ALSO clears the secret-name and
// secret-value checks (defense in depth against a sensitive value placed in an
// otherwise-safe name), and "[REDACTED]" for everything else.
func redactedEnvValue(name, value string) string {
	if isAllowlistedEnvVar(name) && !isSensitiveEnvVar(name) && !looksLikeSecretValue(value) {
		return value
	}
	return "[REDACTED]"
}

type ProcessInfo struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	PPID       int32   `json:"ppid"`
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   float32 `json:"memory_mb"`
	ExePath    string  `json:"exe_path"`
	Username   string  `json:"username"`
	Status     string  `json:"status"`
}

func ListProcesses() (string, error) {
	procs, err := process.Processes()
	if err != nil {
		return "", fmt.Errorf("failed to list processes: %w", err)
	}

	var list []ProcessInfo
	for _, p := range procs {
		info := ProcessInfo{PID: p.Pid}

		if name, err := p.Name(); err == nil {
			info.Name = name
		}
		if ppid, err := p.Ppid(); err == nil {
			info.PPID = ppid
		}
		// CPUPercent from a single call is the process's cumulative average since it
		// started (total CPU time ÷ wall-clock age), NOT an instantaneous load
		// sample — surfaced as such in the list_processes schema so the model does
		// not read it as "current" CPU. An instantaneous figure would need two
		// samples spaced by an interval per process, too costly for a full listing.
		if cpu, err := p.CPUPercent(); err == nil {
			info.CPUPercent = cpu
		}
		if mem, err := p.MemoryInfo(); err == nil && mem != nil {
			info.MemoryMB = float32(mem.RSS) / 1024 / 1024
		}
		if exe, err := p.Exe(); err == nil {
			info.ExePath = exe
		}
		if user, err := p.Username(); err == nil {
			info.Username = user
		}
		if statuses, err := p.Status(); err == nil && len(statuses) > 0 {
			info.Status = statuses[0]
		}

		list = append(list, info)
	}

	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ProcessDetail is the rich view of a single process returned by get_process_detail.
// Environment variable names are all listed, but values are surfaced under a
// default-deny allowlist — only curated non-sensitive names reveal their value.
type ProcessDetail struct {
	PID         int32             `json:"pid"`
	Name        string            `json:"name"`
	ExePath     string            `json:"exe_path"`
	Cmdline     []string          `json:"cmdline"`
	Cwd         string            `json:"cwd"`
	Username    string            `json:"username"`
	ThreadCount int32             `json:"thread_count"`
	NumFDs      int32             `json:"open_handles"`
	CreateTime  int64             `json:"create_time_unix"`
	Environ     map[string]string `json:"environ,omitempty"` // non-allowlisted values replaced with [REDACTED]
}

func GetProcessDetail(pid int) (string, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return "", fmt.Errorf("process %d not found: %w", pid, err)
	}

	detail := ProcessDetail{PID: int32(pid)}

	if name, err := p.Name(); err == nil {
		detail.Name = name
	}
	if exe, err := p.Exe(); err == nil {
		detail.ExePath = exe
	}
	if cmd, err := p.CmdlineSlice(); err == nil {
		detail.Cmdline = cmd
	}
	if cwd, err := p.Cwd(); err == nil {
		detail.Cwd = cwd
	}
	if user, err := p.Username(); err == nil {
		detail.Username = user
	}
	if threads, err := p.NumThreads(); err == nil {
		detail.ThreadCount = threads
	}
	if fds, err := p.NumFDs(); err == nil {
		detail.NumFDs = fds
	}
	if ct, err := p.CreateTime(); err == nil {
		detail.CreateTime = ct
	}

	// Collect env vars. Values are surfaced under a default-deny allowlist
	// (redactedEnvValue): every variable NAME is listed, but only allowlisted-safe
	// names reveal their VALUE — so an unknown-format secret in an unrecognised
	// variable cannot leak into the model's context.
	if envs, err := p.Environ(); err == nil && len(envs) > 0 {
		detail.Environ = make(map[string]string, len(envs))
		for _, kv := range envs {
			idx := strings.IndexByte(kv, '=')
			if idx < 0 {
				continue
			}
			k, v := kv[:idx], kv[idx+1:]
			detail.Environ[k] = redactedEnvValue(k, v)
		}
	}

	out, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// NetworkConn is the raw connection view returned by get_network_connections.
type NetworkConn struct {
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name"`
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	Status      string `json:"status"`
}

// GetNetworkConnections returns all active TCP/UDP connections with PID and process name.
func GetNetworkConnections(ctx context.Context) (string, error) {
	// Build PID → name map
	pidNames := map[int32]string{}
	procs, _ := process.Processes()
	for _, p := range procs {
		if name, err := p.Name(); err == nil {
			pidNames[p.Pid] = name
		}
	}

	out, err := run.ToolCtx(ctx, run.DefaultTimeout, "netstat", "-ano")
	if err != nil {
		return "", fmt.Errorf("netstat failed: %w", err)
	}

	var conns []NetworkConn
	for _, c := range parse.Netstat(string(out)) {
		conn := NetworkConn{
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
	if conns == nil {
		conns = []NetworkConn{}
	}

	result, err := json.MarshalIndent(conns, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}
