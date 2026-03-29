package handlers

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type StartupEntry struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"`
}

func GetStartupEntries() (string, error) {
	var entries []StartupEntry

	// Query common registry Run keys
	regPaths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	}

	for _, regPath := range regPaths {
		out, err := exec.Command("reg", "query", regPath).Output()
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "HKEY") {
				continue
			}
			// Format: "    name    REG_SZ    value"
			parts := strings.SplitN(line, "REG_SZ", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				cmd := strings.TrimSpace(parts[1])
				entries = append(entries, StartupEntry{
					Name:     name,
					Command:  cmd,
					Location: regPath,
				})
			}
		}
	}

	// Also check startup folders via PowerShell
	psCmd := `Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName | ConvertTo-Json`
	psOut, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
	if err == nil {
		var items []struct {
			Name     string `json:"Name"`
			FullName string `json:"FullName"`
		}
		if err := json.Unmarshal(psOut, &items); err == nil {
			for _, item := range items {
				entries = append(entries, StartupEntry{
					Name:     item.Name,
					Command:  item.FullName,
					Location: "Startup Folder (User)",
				})
			}
		}
	}

	result, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}
	return string(result), nil
}
