package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"processguard-mcp/internal/config"
	"processguard-mcp/internal/run"
)

// ProcessNode represents a single process in the full process tree.
type ProcessNode struct {
	PID         int32          `json:"pid"`
	Name        string         `json:"name"`
	ExePath     string         `json:"exe_path"`
	Signer      string         `json:"signer"`
	IsVerified  bool           `json:"is_verified"`
	IsMicrosoft bool           `json:"is_microsoft"`
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
func GetProcessTree(ctx context.Context, cfg *config.Config) (string, error) {
	procs, err := collectProcessesWithSigning(ctx, run.DefaultTimeout)
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
func GetUnsignedProcesses(ctx context.Context, cfg *config.Config) (string, error) {
	procs, err := collectProcessesWithSigning(ctx, run.DefaultTimeout)
	if err != nil {
		return "", err
	}

	var unsigned []UnsignedProcess
	for _, p := range procs {
		list, reason := classifyUnsigned(p.Status)
		if !list {
			continue
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
	Signer      string
	Status      string // raw Authenticode SignatureStatus ("" when not evaluated)
	IsVerified  bool
	IsMicrosoft bool
}

// signingFromStatus interprets an Authenticode result. A signature is trusted
// only when its Status is "Valid"; "microsoft" in the subject is trusted only
// when the signature itself is Valid, so an invalid or self-signed certificate
// merely NAMING Microsoft does not evade get_unsigned_processes.
func signingFromStatus(status, subject string) (verified, microsoft bool) {
	verified = strings.EqualFold(status, "Valid")
	microsoft = verified && strings.Contains(strings.ToLower(subject), "microsoft")
	return
}

// classifyUnsigned decides whether a process belongs in the unsigned/untrusted
// list, and why. A signature that could NOT be evaluated (empty status — e.g. an
// unreadable SYSTEM binary when ProcessGuard runs non-elevated) is UNKNOWN, not
// unsigned: reporting it as unsigned would bury real findings under a wall of
// legitimate system processes. This mirrors the autoruns SignerKnown discipline.
func classifyUnsigned(status string) (list bool, reason string) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "valid":
		return false, "" // trusted
	case "":
		return false, "" // signature not evaluated (path unreadable) — unknown, not unsigned
	case "notsigned":
		return true, "no digital signature"
	case "hashmismatch":
		return true, "signature invalid (hash mismatch) — possible tampering"
	case "nottrusted":
		return true, "signature present but the issuer is not trusted by the system"
	default:
		return true, fmt.Sprintf("signature could not be verified (status: %s)", status)
	}
}

// collectProcessesWithSigning enumerates processes via Win32_Process and resolves
// each executable's Authenticode signature (cached per unique path to avoid
// re-verifying the same binary). Runs under the central runner's timeout and the
// caller's context, so a dead client cancels the enumeration child too.
func collectProcessesWithSigning(ctx context.Context, timeout time.Duration) ([]procRow, error) {
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

	out, err := run.PowerShellCtx(ctx, timeout, psCmd)
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
		verified, microsoft := signingFromStatus(p.Status, p.Subject)
		rows = append(rows, procRow{
			PID:         p.ProcID,
			PPID:        p.PPID,
			Name:        p.Name,
			ExePath:     p.Path,
			Signer:      signerCN(p.Subject),
			Status:      p.Status,
			IsVerified:  verified,
			IsMicrosoft: microsoft,
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
		if _, dup := nodeMap[p.PID]; dup {
			// Defensive: Win32_Process yields one row per PID, but a duplicate
			// row here would let a later link pass bypass createsCycle's
			// acyclicity invariant (it assumes unique PIDs). Keep the first.
			continue
		}
		nodeMap[p.PID] = &ProcessNode{
			PID:         p.PID,
			Name:        p.Name,
			ExePath:     p.ExePath,
			Signer:      p.Signer,
			IsVerified:  p.IsVerified,
			IsMicrosoft: p.IsMicrosoft,
		}
	}

	// parentOf records only the links actually made, so createsCycle can walk
	// ancestry over an always-acyclic map (the walk is guaranteed to terminate).
	parentOf := make(map[int32]int32, len(procs))
	linked := make(map[int32]bool, len(procs))
	var roots []*ProcessNode
	for i := range procs {
		p := &procs[i]
		if linked[p.PID] {
			continue // duplicate PID row — its node was placed by the first row
		}
		linked[p.PID] = true
		node := nodeMap[p.PID]
		parent, ok := nodeMap[p.PPID]
		if !ok || p.PPID == 0 || p.PPID == p.PID || createsCycle(parentOf, p.PID, p.PPID) {
			roots = append(roots, node)
			continue
		}
		parent.Children = append(parent.Children, node)
		parentOf[p.PID] = p.PPID
	}
	return roots
}

// createsCycle reports whether linking child under parent would close a PPID
// loop. Windows reuses PIDs, so a snapshot can legitimately claim A's parent is
// B while B's recorded parent PID was reused by A — linking both would build a
// cyclic node graph, and json.Marshal fails on cycles, killing the whole
// get_process_tree response. The offending link is broken by rooting the child.
func createsCycle(parentOf map[int32]int32, child, parent int32) bool {
	for cur := parent; ; {
		if cur == child {
			return true
		}
		next, ok := parentOf[cur]
		if !ok {
			return false
		}
		cur = next
	}
}
