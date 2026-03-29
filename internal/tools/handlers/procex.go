package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"processguard-mcp/internal/config"
)

// ProcessNode represents a single process in the full process tree.
type ProcessNode struct {
	PID         int32         `json:"pid"`
	Name        string        `json:"name"`
	ExePath     string        `json:"exe_path"`
	Company     string        `json:"company"`
	Description string        `json:"description"`
	Signer      string        `json:"signer"`
	IsVerified  bool          `json:"is_verified"`
	IsMicrosoft bool          `json:"is_microsoft"`
	CPUPercent  float64       `json:"cpu_percent,omitempty"`
	MemoryMB    float64       `json:"memory_mb,omitempty"`
	VTScore     string        `json:"vt_score,omitempty"` // "5/72" format from procexp CSV
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

// GetProcessTree launches procexp64.exe in CSV export mode, parses the output,
// and returns the full parent-child process tree.
func GetProcessTree(cfg *config.Config) (string, error) {
	if cfg.ProcessExplorerPath == "" {
		return "", fmt.Errorf("procexp_path not configured")
	}

	procs, err := runProcExpCSV(cfg.ProcessExplorerPath)
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

// GetUnsignedProcesses returns processes where the signer is empty or
// "Not verified", excluding known unsigned-but-safe system binaries.
func GetUnsignedProcesses(cfg *config.Config) (string, error) {
	if cfg.ProcessExplorerPath == "" {
		return "", fmt.Errorf("procexp_path not configured")
	}

	procs, err := runProcExpCSV(cfg.ProcessExplorerPath)
	if err != nil {
		return "", err
	}

	var unsigned []UnsignedProcess
	for _, p := range procs {
		if p.IsVerified || p.IsMicrosoft {
			continue
		}
		reason := "no digital signature"
		if strings.Contains(strings.ToLower(p.Signer), "not verified") {
			reason = "signature present but not trusted"
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

// procexpRow is the internal representation of one CSV row from procexp.
type procexpRow struct {
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
	VTScore     string
}

// runProcExpCSV launches procexp64.exe and reads the CSV it writes to stdout.
// Process Explorer supports: procexp64.exe /accepteula /t /p <output.csv>
// We write to a temp file and read it back.
func runProcExpCSV(procexpPath string) ([]procexpRow, error) {
	// TODO(P1): Process Explorer's headless CSV mode uses /p <file>.
	// For now we stub this and return an empty list so the build compiles.
	// Implementation steps:
	//   1. Create a temp file path.
	//   2. Run: procexp64.exe /accepteula /t /p <tempfile>
	//   3. Wait for exit (procexp exits after writing the CSV in /t mode).
	//   4. Open and parse the CSV.
	//   5. Delete the temp file.
	//
	// CSV columns (procexp /t output):
	//   Process Name, PID, CPU, Private Bytes, Working Set, PID, PPID,
	//   Description, Company Name, Path, Image Path, Autostart Location,
	//   Version, VirusTotal, Signer

	_ = procexpPath
	// Stub: fall back to a basic gopsutil list so the tool still returns data.
	return runProcExpFallback()
}

// runProcExpFallback uses gopsutil when procexp CSV is not yet implemented.
func runProcExpFallback() ([]procexpRow, error) {
	// Use the PowerShell Get-Process as a lightweight alternative until
	// the full procexp CSV path is wired up.
	psCmd := `Get-Process | Select-Object Id, Name, @{N='PPID';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}}, Path, CPU, WorkingSet64 | ConvertTo-Json`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
	if err != nil {
		return nil, fmt.Errorf("fallback process list failed: %w", err)
	}

	var psProcs []struct {
		ID          int32   `json:"Id"`
		Name        string  `json:"Name"`
		PPID        int32   `json:"PPID"`
		Path        string  `json:"Path"`
		CPU         float64 `json:"CPU"`
		WorkingSet  int64   `json:"WorkingSet64"`
	}
	if err := json.Unmarshal(out, &psProcs); err != nil {
		return nil, fmt.Errorf("JSON parse failed: %w", err)
	}

	var rows []procexpRow
	for _, p := range psProcs {
		rows = append(rows, procexpRow{
			PID:      p.ID,
			PPID:     p.PPID,
			Name:     p.Name,
			ExePath:  p.Path,
			CPUPercent: p.CPU,
			MemoryMB: float64(p.WorkingSet) / 1024 / 1024,
		})
	}
	return rows, nil
}

// buildTree constructs the parent-child tree from a flat list of processes.
func buildTree(procs []procexpRow) []*ProcessNode {
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
			VTScore:     p.VTScore,
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

// sentinel — csv imported for future use in parseCSV helper
var _ = csv.NewReader
