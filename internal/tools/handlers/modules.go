package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"processguard-mcp/internal/run"
)

// ModuleInfo holds information about a single DLL or module loaded by a process.
type ModuleInfo struct {
	Name        string  `json:"name"`
	Path        string  `json:"path,omitempty"`
	BaseAddr    string  `json:"base_address,omitempty"`
	SizeMB      float64 `json:"size_mb,omitempty"`
	FileVersion string  `json:"file_version,omitempty"`
	Company     string  `json:"company,omitempty"`
	// Flags set by local heuristics
	Flags  []string `json:"flags,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// GetLoadedModules returns all DLLs and modules loaded by the given process.
// Primary: PowerShell Get-Process .Modules (richest data).
// Fallback: tasklist /m (names only, no paths).
func GetLoadedModules(pid int) (string, error) {
	modules, err := modulesViaPowerShell(pid)
	if err != nil || len(modules) == 0 {
		// PowerShell failed (e.g. access denied on system process) — fall back
		fallback, fbErr := modulesViaTasklist(pid)
		if fbErr != nil {
			if err != nil {
				return "", fmt.Errorf("PowerShell modules failed: %w; tasklist fallback also failed: %v", err, fbErr)
			}
			return "", fbErr
		}
		modules = fallback
	}

	// Apply simple heuristics: modules loaded from suspicious paths
	for i := range modules {
		flagModule(&modules[i])
	}

	result, err := json.MarshalIndent(modules, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// modulesViaPowerShell uses Get-Process .Modules to get full module details.
func modulesViaPowerShell(pid int) ([]ModuleInfo, error) {
	// Get-Process.Modules gives us ModuleName, FileName, BaseAddress, ModuleMemorySize, FileVersionInfo
	psCmd := fmt.Sprintf(`
$p = Get-Process -Id %d -ErrorAction SilentlyContinue
if ($null -eq $p) { '[]'; exit }
$mods = @($p.Modules)
if ($mods.Count -eq 0) { '[]'; exit }
$mods | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.ModuleName
        Path        = $_.FileName
        BaseAddress = '0x{0:X}' -f $_.BaseAddress.ToInt64()
        SizeBytes   = $_.ModuleMemorySize
        Version     = if ($_.FileVersionInfo) { $_.FileVersionInfo.FileVersion } else { '' }
        Company     = if ($_.FileVersionInfo) { $_.FileVersionInfo.CompanyName } else { '' }
    }
} | ConvertTo-Json -Compress -Depth 2`, pid)

	out, err := run.PowerShell(psCmd)
	if err != nil {
		return nil, fmt.Errorf("Get-Process modules failed: %w", err)
	}

	raw := strings.TrimSpace(string(out))
	if raw == "[]" || raw == "" || raw == "null" {
		return nil, nil
	}

	// Normalise: single module → object, multiple → array
	var psModules []struct {
		Name      string `json:"Name"`
		Path      string `json:"Path"`
		BaseAddr  string `json:"BaseAddress"`
		SizeBytes int64  `json:"SizeBytes"`
		Version   string `json:"Version"`
		Company   string `json:"Company"`
	}
	if err := json.Unmarshal([]byte(raw), &psModules); err != nil {
		// Single-module object fallback
		var single struct {
			Name      string `json:"Name"`
			Path      string `json:"Path"`
			BaseAddr  string `json:"BaseAddress"`
			SizeBytes int64  `json:"SizeBytes"`
			Version   string `json:"Version"`
			Company   string `json:"Company"`
		}
		if err2 := json.Unmarshal([]byte(raw), &single); err2 != nil {
			return nil, fmt.Errorf("module JSON parse failed: %w", err)
		}
		psModules = append(psModules, single)
	}

	modules := make([]ModuleInfo, 0, len(psModules))
	for _, m := range psModules {
		mod := ModuleInfo{
			Name:        m.Name,
			Path:        m.Path,
			BaseAddr:    m.BaseAddr,
			FileVersion: strings.TrimSpace(m.Version),
			Company:     strings.TrimSpace(m.Company),
		}
		if m.SizeBytes > 0 {
			mod.SizeMB = float64(m.SizeBytes) / 1024 / 1024
		}
		modules = append(modules, mod)
	}
	return modules, nil
}

// modulesViaTasklist uses tasklist /m /fi "PID eq N" as a no-path fallback.
// Returns ModuleInfo with Name only; Path will be empty.
func modulesViaTasklist(pid int) ([]ModuleInfo, error) {
	out, err := run.Tool("tasklist", "/m", "/fi", fmt.Sprintf("PID eq %d", pid))
	if err != nil {
		return nil, fmt.Errorf("tasklist /m failed: %w", err)
	}

	// Output format:
	//   Image Name     PID  Modules
	//   ============  ===  ============================
	//   notepad.exe   1234 ntdll.dll, KERNEL32.DLL, ...
	// Module names continue on subsequent lines indented with spaces.
	var modules []ModuleInfo
	lines := strings.Split(string(out), "\n")
	collecting := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "===") || strings.HasPrefix(line, "---") {
			collecting = true
			continue
		}
		if !collecting {
			continue
		}
		// After the separator, module names may span multiple lines.
		// Trim leading spaces and split by comma.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// The first data line starts with "imageName PID modlist..."
		// Subsequent continuation lines are purely module names.
		// Strip leading image name + PID field if present (no leading space).
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// First data line — skip image name and PID prefix before modules
			parts := strings.Fields(trimmed)
			if len(parts) < 3 {
				continue
			}
			// Rejoin from field index 2 onwards as the module list
			trimmed = strings.Join(parts[2:], " ")
		}
		for _, name := range strings.Split(trimmed, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				modules = append(modules, ModuleInfo{Name: name})
			}
		}
	}
	return modules, nil
}

// suspiciousModuleDirs mirrors the process heuristic — modules from these
// paths should be treated as high-risk injection candidates.
var suspiciousModuleDirs = []string{
	`\temp\`, `\tmp\`, `\appdata\local\temp\`,
	`\downloads\`, `\recycle`, `\public\`,
	`\programdata\temp\`,
}

// flagModule applies path-based risk heuristics.
func flagModule(m *ModuleInfo) {
	if m.Path == "" {
		return
	}
	pathLower := strings.ToLower(m.Path)
	for _, dir := range suspiciousModuleDirs {
		if strings.Contains(pathLower, dir) {
			m.Flags = append(m.Flags, "SUSPICIOUS_PATH")
			m.Reason = fmt.Sprintf("module loaded from high-risk directory: %s", m.Path)
			return
		}
	}
}
