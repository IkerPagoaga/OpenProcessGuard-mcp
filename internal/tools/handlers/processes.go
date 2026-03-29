package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// secretPatterns are env var name substrings that indicate sensitive values.
// Matched case-insensitively. Matching vars are replaced with "[REDACTED]".
var secretPatterns = []string{
	"token", "secret", "password", "passwd", "pwd",
	"key", "apikey", "api_key", "credential", "auth",
	"private", "cert", "jwt", "bearer",
}

// isSensitiveEnvVar returns true if the env var name looks like a secret.
func isSensitiveEnvVar(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range secretPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
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
// Environment variables are included but sensitive values are redacted.
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
	Environ     map[string]string `json:"environ,omitempty"` // sensitive values replaced with [REDACTED]
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

	// Collect env vars with sensitive values redacted
	if envs, err := p.Environ(); err == nil && len(envs) > 0 {
		detail.Environ = make(map[string]string, len(envs))
		for _, kv := range envs {
			idx := strings.IndexByte(kv, '=')
			if idx < 0 {
				continue
			}
			k, v := kv[:idx], kv[idx+1:]
			if isSensitiveEnvVar(k) {
				detail.Environ[k] = "[REDACTED]"
			} else {
				detail.Environ[k] = v
			}
		}
	}

	out, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type NetworkConn struct {
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name"`
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	Status      string `json:"status"`
}

func GetNetworkConnections() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("network connection listing requires Windows")
	}

	// Use netstat to get connections with PID
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return "", fmt.Errorf("netstat failed: %w", err)
	}

	// Build a PID -> name map
	pidNames := map[string]string{}
	procs, _ := process.Processes()
	for _, p := range procs {
		if name, err := p.Name(); err == nil {
			pidNames[fmt.Sprintf("%d", p.Pid)] = name
		}
	}

	var conns []NetworkConn
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		if proto != "TCP" && proto != "UDP" {
			continue
		}
		conn := NetworkConn{
			Protocol:  proto,
			LocalAddr: fields[1],
		}
		if proto == "TCP" && len(fields) >= 5 {
			conn.RemoteAddr = fields[2]
			conn.Status = fields[3]
			pid := fields[4]
			conn.ProcessName = pidNames[pid]
		} else if proto == "UDP" && len(fields) >= 4 {
			conn.RemoteAddr = "*"
			pid := fields[3]
			conn.ProcessName = pidNames[pid]
		}
		conns = append(conns, conn)
	}

	result, err := json.MarshalIndent(conns, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}
