package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"processguard-mcp/internal/run"
)

// StartupEntry represents a single program configured to run at startup.
type StartupEntry struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"`
	Type     string `json:"type"` // "registry", "startup_folder"
}

// GetStartupEntries returns programs configured to run at startup via
// registry Run/RunOnce keys and common startup folders (user + all-users).
func GetStartupEntries(ctx context.Context) (string, error) {
	var entries []StartupEntry

	// ── Registry Run / RunOnce keys ──────────────────────────────────────
	regPaths := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		// WOW64 (32-bit apps on 64-bit Windows)
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		// Policies (often used by malware and GPO)
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	}

	for _, regPath := range regPaths {
		out, err := run.ToolCtx(ctx, run.DefaultTimeout, "reg", "query", regPath)
		if err != nil {
			// Key doesn't exist — not an error
			continue
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimRight(line, "\r")
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "HKEY") {
				continue
			}
			// Format: "    Name    REG_SZ    Value"
			//         "    Name    REG_EXPAND_SZ    Value"
			for _, regType := range []string{"REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ"} {
				if idx := strings.Index(line, regType); idx >= 0 {
					name := strings.TrimSpace(line[:idx])
					cmd := strings.TrimSpace(line[idx+len(regType):])
					entries = append(entries, StartupEntry{
						Name:     name,
						Command:  cmd,
						Location: regPath,
						Type:     "registry",
					})
					break
				}
			}
		}
	}

	// ── Startup folders (User + All Users) ───────────────────────────────
	// Use PowerShell to resolve both %APPDATA% and %ALLUSERSPROFILE% paths.
	psCmd := `
$folders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
$results = @()
foreach ($folder in $folders) {
    $items = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
    if ($null -eq $items) { continue }
    foreach ($item in @($items)) {
        $results += [PSCustomObject]@{
            Name     = $item.Name
            FullName = $item.FullName
            Folder   = $folder
        }
    }
}
if ($results.Count -eq 0) { '[]'; exit }
$results | ConvertTo-Json -Compress -Depth 2`

	psOut, err := run.PowerShellCtx(ctx, run.DefaultTimeout, psCmd)
	if err == nil {
		raw := strings.TrimSpace(string(psOut))
		if raw != "" && raw != "[]" && raw != "null" {
			var items []struct {
				Name     string `json:"Name"`
				FullName string `json:"FullName"`
				Folder   string `json:"Folder"`
			}
			if jsonErr := json.Unmarshal([]byte(raw), &items); jsonErr != nil {
				// Single item — ConvertTo-Json returns object not array
				var single struct {
					Name     string `json:"Name"`
					FullName string `json:"FullName"`
					Folder   string `json:"Folder"`
				}
				if jsonErr2 := json.Unmarshal([]byte(raw), &single); jsonErr2 == nil {
					items = append(items, single)
				}
			}
			for _, item := range items {
				location := "Startup Folder (User)"
				if strings.Contains(strings.ToLower(item.Folder), "programdata") {
					location = "Startup Folder (All Users)"
				}
				entries = append(entries, StartupEntry{
					Name:     item.Name,
					Command:  item.FullName,
					Location: location,
					Type:     "startup_folder",
				})
			}
		}
	}

	if entries == nil {
		entries = []StartupEntry{}
	}

	result, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}
	return string(result), nil
}
