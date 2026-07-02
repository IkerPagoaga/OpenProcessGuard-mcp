package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"processguard-mcp/internal/config"
	"processguard-mcp/internal/run"
)

// ProcessNode represents a single process in the full process tree.
type ProcessNode struct {
	PID         int32          `json:"pid"`
	Name        string         `json:"name"`
	ExePath     string         `json:"exe_path"`
	Company     string         `json:"company,omitempty"`
	Description string         `json:"description,omitempty"`
	Signer      string         `json:"signer"`
	IsVerified  bool           `json:"is_verified"`
	IsMicrosoft bool           `json:"is_microsoft"`
	CPUPercent  float64        `json:"cpu_percent,omitempty"`
	MemoryMB    float64        `json:"memory_mb,omitempty"`
	Children    []*ProcessNode `json:"children,omitempty"`
}

// UnsignedProcess is a simplified view for get_unsigned_processes.
type UnsignedProcess struct {
	PID     int32  `json:"pid"`
	Name    string `json:"name"`
	ExePath string `json:"exe_path"`
	Signer  string `json:"signer"`
	Reason  string `json:"reason"`
}

// GetProcessTree returns the full parent-child process tree with Authenticode
// signing status.
//
// Process Explorer has no headless CSV-export switch (its `/t` = start minimised
// to tray, `/p` = set its own priority), so the previous approach launched the
// GUI and stalled for the full timeout on every call before falling back. We now
// derive signing status directly from Windows via Get-AuthenticodeSignature,
// which is headless, reliable, and needs no external Sysinternals binary.
func GetProcessTree(cfg *config.Config) (string, error) {
	procs, err := collectProcessesWithSigning()
	if err != nil {
		return "", err
	}

	tree := buildTree(procs)
	result, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// GetUnsignedProcesses returns processes whose Authenticode signature is absent
// or untrusted — a primary malware indicator when found in system paths.
func GetUnsignedProcesses(cfg *config.Config) (string, error) {
	procs, err := collectProcessesWithSigning()
	if err != nil {
		return "", err
	}

	var unsigned []UnsignedProcess
	for _, p := range procs {
		if p.IsVerified || p.IsMicrosoft {
			continue
		}
		reason := "no digital signature"
		if p.Signer != "" {
			reason = "signature present but not trusted by the system"
		}
		unsigned = append(unsigned, UnsignedProcess{
			PID:     p.PID,
			Name:    p.Name,
			ExePath: p.ExePath,
			Signer:  p.Signer,
			Reason:  reason,
		})
	}
	if unsigned == nil {
		unsigned = []UnsignedProcess{}
	}

	result, err := json.MarshalIndent(unsigned, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// procRow is the internal representation of one enumerated process.
type procRow struct {
	PID         int32
	PPID        int32
	Name        string
	ExePath     string
	Company     string
	Description string
	Signer      string
	IsVerified  bool
	IsMicrosoft bool
	CPUPercent  float64
	MemoryMB    float64
}

// collectProcessesWithSigning enumerates processes via Win32_Process and resolves
// each executable's Authenticode signature (cached per unique path to avoid
// re-verifying the same binary). Runs under the central runner's timeout.
func collectProcessesWithSigning() ([]procRow, error) {
	const psCmd = `
$ErrorActionPreference = 'SilentlyContinue'
$sigCache = @{}
Get-CimInstance Win32_Process | ForEach-Object {
    $path = $_.ExecutablePath
    $status = ''
    $subject = ''
    if ($path) {
        if (-not $sigCache.ContainsKey($path)) {
            $sigCache[$path] = Get-AuthenticodeSignature -LiteralPath $path
        }
        $s = $sigCache[$path]
        if ($s) {
            $status = [string]$s.Status
            if ($s.SignerCertificate) { $subject = $s.SignerCertificate.Subject }
        }
    }
    [PSCustomObject]@{
        ProcId  = [int]$_.ProcessId
        PPID    = [int]$_.ParentProcessId
        Name    = $_.Name
        Path    = $path
        Status  = $status
        Subject = $subject
    }
} | ConvertTo-Json -Depth 2 -Compress`

	out, err := run.PowerShell(psCmd)
	if err != nil {
		return nil, fmt.Errorf("process signing enumeration failed: %w", err)
	}

	type psProc struct {
		ProcID  int32  `json:"ProcId"`
		PPID    int32  `json:"PPID"`
		Name    string `json:"Name"`
		Path    string `json:"Path"`
		Status  string `json:"Status"`
		Subject string `json:"Subject"`
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" || raw == "null" {
		return nil, nil
	}

	var procs []psProc
	if err := json.Unmarshal([]byte(raw), &procs); err != nil {
		// ConvertTo-Json emits a bare object when only one process matches.
		var single psProc
		if err2 := json.Unmarshal([]byte(raw), &single); err2 != nil {
			return nil, fmt.Errorf("process JSON parse failed: %w", err)
		}
		procs = append(procs, single)
	}

	rows := make([]procRow, 0, len(procs))
	for _, p := range procs {
		rows = append(rows, procRow{
			PID:         p.ProcID,
			PPID:        p.PPID,
			Name:        p.Name,
			ExePath:     p.Path,
			Signer:      signerCN(p.Subject),
			IsVerified:  strings.EqualFold(p.Status, "Valid"),
			IsMicrosoft: strings.Contains(strings.ToLower(p.Subject), "microsoft"),
		})
	}
	return rows, nil
}

// signerCN extracts the Common Name from an X.500 subject string, falling back
// to the full subject when no CN is present.
func signerCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 3 && strings.EqualFold(part[:3], "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return subject
}

// buildTree constructs the parent-child tree from a flat list of processes.
func buildTree(procs []procRow) []*ProcessNode {
	nodeMap := make(map[int32]*ProcessNode, len(procs))
	for i := range procs {
		p := &procs[i]
		nodeMap[p.PID] = &ProcessNode{
			PID:         p.PID,
			Name:        p.Name,
			ExePath:     p.ExePath,
			Company:     p.Company,
			Description: p.Description,
			Signer:      p.Signer,
			IsVerified:  p.IsVerified,
			IsMicrosoft: p.IsMicrosoft,
			CPUPercent:  p.CPUPercent,
			MemoryMB:    p.MemoryMB,
		}
	}

	var roots []*ProcessNode
	for i := range procs {
		p := &procs[i]
		node := nodeMap[p.PID]
		if parent, ok := nodeMap[p.PPID]; ok && p.PPID != 0 && p.PPID != p.PID {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}
	return roots
}
