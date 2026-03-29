package handlers

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// Heuristic flags
const (
	FlagNameSpoof       = "NAME_SPOOF"          // name mimics a known system process but has chars swapped
	FlagWrongPath       = "WRONG_PATH"           // known system process running outside System32/SysWOW64
	FlagTempPath        = "SUSPICIOUS_PATH"      // binary in Temp, AppData, Downloads, or Recycle Bin
	FlagNoPath          = "NO_EXE_PATH"          // could not resolve executable path (common in hollow processes)
	FlagSuspiciousChild = "SUSPICIOUS_PARENT"    // unusual parent (e.g. Office spawning cmd/powershell)
)

// systemProcessPaths: legitimate system processes and their expected path fragments
var systemProcessPaths = map[string][]string{
	"svchost.exe":      {`\system32\`, `\syswow64\`},
	"lsass.exe":        {`\system32\`},
	"csrss.exe":        {`\system32\`},
	"wininit.exe":      {`\system32\`},
	"winlogon.exe":     {`\system32\`},
	"services.exe":     {`\system32\`},
	"smss.exe":         {`\system32\`},
	"spoolsv.exe":      {`\system32\`},
	"taskhost.exe":     {`\system32\`},
	"taskhostw.exe":    {`\system32\`},
	"explorer.exe":     {`\windows\`},
	"conhost.exe":      {`\system32\`},
	"dllhost.exe":      {`\system32\`},
	"rundll32.exe":     {`\system32\`, `\syswow64\`},
	"powershell.exe":   {`\system32\`, `\syswow64\`},
	"cmd.exe":          {`\system32\`, `\syswow64\`},
}

// knownSpoof: common leet-speak or lookalike swaps attackers use
var knownSpoofPatterns = []string{
	"svch0st", "lsas5", "crss", "svchost32", "svchosts",
	"lsasss", "csrrs", "wininit32", "explore", "explrer",
	"taskhost32", "spoolsvc", "smss32",
}

// suspiciousDirs: paths that should never contain executables running as system processes
var suspiciousDirs = []string{
	`\temp\`, `\tmp\`, `\appdata\roaming\`, `\appdata\local\temp\`,
	`\downloads\`, `\recycle`, `\public\`, `\programdata\temp\`,
}

// Suspicious parent-child combos: parent -> bad child
var suspiciousParentChild = map[string][]string{
	"winword.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
	"excel.exe":     {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
	"outlook.exe":   {"cmd.exe", "powershell.exe", "mshta.exe"},
	"powerpnt.exe":  {"cmd.exe", "powershell.exe"},
	"acrord32.exe":  {"cmd.exe", "powershell.exe"},
	"chrome.exe":    {"cmd.exe", "powershell.exe"},
	"firefox.exe":   {"cmd.exe", "powershell.exe"},
	"iexplore.exe":  {"cmd.exe", "powershell.exe", "wscript.exe"},
}

type SuspiciousProcess struct {
	PID     int32    `json:"pid"`
	Name    string   `json:"name"`
	ExePath string   `json:"exe_path"`
	Flags   []string `json:"flags"`
	Reason  string   `json:"reason"`
}

func GetSuspiciousProcesses() (string, error) {
	procs, err := process.Processes()
	if err != nil {
		return "", fmt.Errorf("failed to list processes: %w", err)
	}

	// Build PID -> name map for parent-child checks
	pidToName := map[int32]string{}
	for _, p := range procs {
		if name, err := p.Name(); err == nil {
			pidToName[p.Pid] = strings.ToLower(name)
		}
	}

	var suspicious []SuspiciousProcess

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		nameLower := strings.ToLower(name)
		exe, _ := p.Exe()
		exeLower := strings.ToLower(exe)

		var flags []string
		var reasons []string

		// 1. Name spoofing
		for _, spoof := range knownSpoofPatterns {
			if strings.Contains(nameLower, spoof) {
				flags = append(flags, FlagNameSpoof)
				reasons = append(reasons, fmt.Sprintf("name %q matches known spoof pattern %q", name, spoof))
				break
			}
		}

		// 2. Wrong path for known system process
		if expectedPaths, ok := systemProcessPaths[nameLower]; ok && exe != "" {
			matched := false
			for _, ep := range expectedPaths {
				if strings.Contains(exeLower, ep) {
					matched = true
					break
				}
			}
			if !matched {
				flags = append(flags, FlagWrongPath)
				reasons = append(reasons, fmt.Sprintf("system process %q running from unexpected path: %q", name, exe))
			}
		}

		// 3. Binary in suspicious directory
		if exe != "" {
			for _, sd := range suspiciousDirs {
				if strings.Contains(exeLower, sd) {
					flags = append(flags, FlagTempPath)
					reasons = append(reasons, fmt.Sprintf("executable in suspicious directory: %q", filepath.Dir(exe)))
					break
				}
			}
		}

		// 4. No exe path (possible hollow process)
		if exe == "" {
			flags = append(flags, FlagNoPath)
			reasons = append(reasons, "could not resolve executable path")
		}

		// 5. Suspicious parent-child
		if ppid, err := p.Ppid(); err == nil {
			parentName := pidToName[ppid]
			if badChildren, ok := suspiciousParentChild[parentName]; ok {
				for _, bad := range badChildren {
					if nameLower == bad {
						flags = append(flags, FlagSuspiciousChild)
						reasons = append(reasons, fmt.Sprintf("process %q spawned by %q (PPID %d)", name, parentName, ppid))
						break
					}
				}
			}
		}

		if len(flags) > 0 {
			suspicious = append(suspicious, SuspiciousProcess{
				PID:     p.Pid,
				Name:    name,
				ExePath: exe,
				Flags:   flags,
				Reason:  strings.Join(reasons, "; "),
			})
		}
	}

	if suspicious == nil {
		suspicious = []SuspiciousProcess{}
	}

	result, err := json.MarshalIndent(suspicious, "", "  ")
	if err != nil {
		return "", err
	}
	return string(result), nil
}
