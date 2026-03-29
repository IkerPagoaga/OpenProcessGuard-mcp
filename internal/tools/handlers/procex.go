package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"processguard-mcp/internal/config"
)

// ProcessNode represents a single process in the full process tree.
type ProcessNode struct {
	PID         int32          `json:"pid"`
	Name        string         `json:"name"`
	ExePath     string         `json:"exe_path"`
	Company     string         `json:"company"`
	Description string         `json:"description"`
	Signer      string         `json:"signer"`
	IsVerified  bool           `json:"is_verified"`
	IsMicrosoft bool           `json:"is_microsoft"`
	CPUPercent  float64        `json:"cpu_percent,omitempty"`
	MemoryMB    float64        `json:"memory_mb,omitempty"`
	VTScore     string         `json:"vt_score,omitempty"` // "5/72" format from procexp CSV
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

// runProcExpCSV launches procexp64.exe /accepteula /t /p <tempfile>,
// waits for it to exit, then parses the CSV it writes.
//
// Process Explorer /t mode writes a CSV and exits immediately.
// Columns (order may vary by version — we detect them by header row):
//
//	Process Name, PID, CPU, Private Bytes, Working Set,
//	PID (duplicate), PPID, Description, Company Name,
//	Path, Image Path, Autostart Location, Version,
//	VirusTotal, Signer
func runProcExpCSV(procexpPath string) ([]procexpRow, error) {
	// Create a temp file that Process Explorer will write the CSV into.
	// procexp requires the file to NOT exist before it writes, so we make
	// a temp name but remove it first.
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("pg_procexp_%d.csv", time.Now().UnixNano()))

	// Remove any stale file (procexp refuses to overwrite)
	os.Remove(tmpFile)
	defer os.Remove(tmpFile)

	// Launch procexp64.exe /accepteula /t /p <output.csv>
	// /t = export tree to CSV and exit; /p <file> = output path
	cmd := exec.Command(procexpPath, "/accepteula", "/t", "/p", tmpFile)
	// procexp pops a GUI briefly even in /t mode on some versions.
	// We give it up to 30 seconds to write the file and exit.
	if err := cmd.Start(); err != nil {
		// procexp failed to launch — fall back to PowerShell list
		return runProcExpFallback()
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Process exited (success or failure — check for CSV file below)
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return nil, fmt.Errorf("procexp64 timed out after 30s — consider using procexp_path fallback")
	}

	// Try to read the CSV file
	f, err := os.Open(tmpFile)
	if err != nil {
		// procexp may not support headless /t on this version; fall back gracefully
		return runProcExpFallback()
	}
	defer f.Close()

	return parseProcExpCSV(f)
}

// parseProcExpCSV reads the CSV written by procexp64.exe /t /p <file>.
func parseProcExpCSV(f *os.File) ([]procexpRow, error) {
	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1 // variable-length rows OK

	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("procexp CSV parse error: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("procexp CSV has no data rows")
	}

	// Build a header→index map from the first row
	header := records[0]
	idx := make(map[string]int, len(header))
	for i, h := range header {
		idx[strings.TrimSpace(strings.ToLower(h))] = i
	}

	// Helper: safe field access by column name
	get := func(row []string, name string) string {
		i, ok := idx[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	var rows []procexpRow
	for _, rec := range records[1:] {
		if len(rec) < 2 {
			continue
		}

		name := get(rec, "process name")
		if name == "" {
			continue
		}

		pid, _ := strconv.ParseInt(get(rec, "pid"), 10, 32)
		ppid, _ := strconv.ParseInt(get(rec, "ppid"), 10, 32)
		cpu, _ := strconv.ParseFloat(strings.TrimSuffix(get(rec, "cpu"), "%"), 64)

		// Private Bytes field is in bytes with possible commas
		pbStr := strings.ReplaceAll(get(rec, "private bytes"), ",", "")
		pb, _ := strconv.ParseInt(pbStr, 10, 64)

		signer := get(rec, "signer")
		company := get(rec, "company name")
		if company == "" {
			company = get(rec, "company")
		}

		isVerified := signer != "" &&
			!strings.Contains(strings.ToLower(signer), "not verified") &&
			!strings.Contains(strings.ToLower(signer), "unsigned")
		isMicrosoft := strings.Contains(strings.ToLower(company), "microsoft") ||
			strings.Contains(strings.ToLower(signer), "microsoft")

		exePath := get(rec, "image path")
		if exePath == "" {
			exePath = get(rec, "path")
		}

		rows = append(rows, procexpRow{
			PID:         int32(pid),
			PPID:        int32(ppid),
			Name:        name,
			ExePath:     exePath,
			Company:     company,
			Description: get(rec, "description"),
			Signer:      signer,
			IsVerified:  isVerified,
			IsMicrosoft: isMicrosoft,
			CPUPercent:  cpu,
			MemoryMB:    float64(pb) / 1024 / 1024,
			VTScore:     get(rec, "virustotal"),
		})
	}
	return rows, nil
}

// runProcExpFallback uses PowerShell Get-Process when procexp CSV is unavailable.
func runProcExpFallback() ([]procexpRow, error) {
	psCmd := `Get-Process | Select-Object Id, Name, @{N='PPID';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}}, Path, CPU, WorkingSet64 | ConvertTo-Json -Depth 2`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
	if err != nil {
		return nil, fmt.Errorf("fallback process list failed: %w", err)
	}

	var psProcs []struct {
		ID         int32   `json:"Id"`
		Name       string  `json:"Name"`
		PPID       int32   `json:"PPID"`
		Path       string  `json:"Path"`
		CPU        float64 `json:"CPU"`
		WorkingSet int64   `json:"WorkingSet64"`
	}
	if err := json.Unmarshal(out, &psProcs); err != nil {
		// ConvertTo-Json may return a single object if only one process matches
		var single struct {
			ID         int32   `json:"Id"`
			Name       string  `json:"Name"`
			PPID       int32   `json:"PPID"`
			Path       string  `json:"Path"`
			CPU        float64 `json:"CPU"`
			WorkingSet int64   `json:"WorkingSet64"`
		}
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("JSON parse failed: %w", err)
		}
		psProcs = append(psProcs, single)
	}

	var rows []procexpRow
	for _, p := range psProcs {
		rows = append(rows, procexpRow{
			PID:        p.ID,
			PPID:       p.PPID,
			Name:       p.Name,
			ExePath:    p.Path,
			CPUPercent: p.CPU,
			MemoryMB:   float64(p.WorkingSet) / 1024 / 1024,
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
