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

	var unreadable []string
	for _, regPath := range regPaths {
		out, err := run.ToolCtx(ctx, run.DefaultTimeout, "reg", "query", regPath)
		if err != nil {
			// `reg query` exits non-zero for BOTH "key does not exist" (benign — several
			// of these locations are optional) and "access denied" (NOT benign — a Run
			// key we cannot read is exactly where persistence hides). reg.exe does not
			// separate them by exit code, and its stderr text is localised, so we do not
			// guess: the location is recorded as unreadable and reported to the caller
			// rather than silently vanishing from the results.
			unreadable = append(unreadable, regPath)
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
	// -ErrorAction Stop + per-folder catch, NOT SilentlyContinue: a startup folder that
	// cannot be listed (access denied) must be reported, not folded into "empty". The
	// [ordered]@{} + -InputObject + @() form is deliberate — it serialises 0-, 1- and
	// n-element collections all as JSON arrays, avoiding PowerShell's
	// single-object-vs-array collapse that the Sysmon decoder has to work around.
	psCmd := `
$folders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
$results = @()
$failed  = @()
foreach ($folder in $folders) {
    try {
        $items = Get-ChildItem -Path $folder -ErrorAction Stop
    } catch {
        $failed += $folder
        continue
    }
    if ($null -eq $items) { continue }
    foreach ($item in @($items)) {
        $results += [PSCustomObject]@{
            Name     = $item.Name
            FullName = $item.FullName
            Folder   = $folder
        }
    }
}
$out = [ordered]@{ items = @($results); failed = @($failed) }
ConvertTo-Json -InputObject $out -Compress -Depth 3`

	var warnings []string
	psOut, err := run.PowerShellCtx(ctx, run.DefaultTimeout, psCmd)
	if err != nil {
		// Previously an `if err == nil` guard dropped BOTH startup folders with no
		// signal whatsoever, so a failed enumeration was indistinguishable from two
		// genuinely empty folders.
		warnings = append(warnings, fmt.Sprintf("startup folders could not be enumerated: %v", err))
	} else {
		var payload struct {
			Items []struct {
				Name     string `json:"Name"`
				FullName string `json:"FullName"`
				Folder   string `json:"Folder"`
			} `json:"items"`
			Failed []string `json:"failed"`
		}
		raw := strings.TrimSpace(string(psOut))
		if jsonErr := json.Unmarshal([]byte(raw), &payload); jsonErr != nil {
			warnings = append(warnings, fmt.Sprintf("startup folder output could not be parsed: %v", jsonErr))
		} else {
			for _, f := range payload.Failed {
				warnings = append(warnings, fmt.Sprintf("startup folder %q could not be read (access denied, or the path does not exist)", f))
			}
			for _, item := range payload.Items {
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

	if len(unreadable) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d registry location(s) could not be read and are NOT represented below (either absent, which is normal for optional keys, or access denied, which is not): %s",
			len(unreadable), strings.Join(unreadable, ", ")))
	}

	if entries == nil {
		entries = []StartupEntry{}
	}
	if warnings == nil {
		warnings = []string{}
	}

	// Envelope rather than a bare array: `partial` states outright that this listing is
	// not a complete picture of startup persistence. A silently short list is the
	// dangerous outcome for a persistence check.
	out := struct {
		Count    int            `json:"count"`
		Partial  bool           `json:"partial"`
		Warnings []string       `json:"warnings"`
		Entries  []StartupEntry `json:"entries"`
	}{
		Count:    len(entries),
		Partial:  len(warnings) > 0,
		Warnings: warnings,
		Entries:  entries,
	}

	result, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}
	return string(result), nil
}
