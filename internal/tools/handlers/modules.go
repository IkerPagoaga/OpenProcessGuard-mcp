package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type ModuleInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func GetLoadedModules(pid int) (string, error) {
	// Use tasklist /m to get modules for a specific PID
	out, err := exec.Command("tasklist", "/m", "/fi", fmt.Sprintf("PID eq %d", pid)).Output()
	if err != nil {
		return "", fmt.Errorf("tasklist failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	var modules []ModuleInfo

	// tasklist /m output format:
	// Image Name     PID  Modules
	// ─────────────  ───  ────────────────────────────────────────────────
	// notepad.exe    1234 ntdll.dll, KERNEL32.DLL, ...
	inData := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "===") || strings.HasPrefix(line, "---") {
			inData = true
			continue
		}
		if !inData || line == "" {
			continue
		}
		// Split by comma to get individual module names
		// The line starts with the image name and PID, then modules
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 3 {
			mods := strings.Split(parts[2], ",")
			for _, m := range mods {
				m = strings.TrimSpace(m)
				if m != "" {
					modules = append(modules, ModuleInfo{Name: m})
				}
			}
		}
	}

	if len(modules) == 0 {
		// Fallback: use PowerShell for richer module info
		psCmd := fmt.Sprintf(`Get-Process -Id %d | Select-Object -ExpandProperty Modules | Select-Object ModuleName, FileName | ConvertTo-Json`, pid)
		psOut, psErr := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
		if psErr == nil {
			var psModules []struct {
				ModuleName string `json:"ModuleName"`
				FileName   string `json:"FileName"`
			}
			if err := json.Unmarshal(psOut, &psModules); err == nil {
				for _, m := range psModules {
					modules = append(modules, ModuleInfo{Name: m.ModuleName, Path: m.FileName})
				}
			}
		}
	}

	result, err := json.MarshalIndent(modules, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}
