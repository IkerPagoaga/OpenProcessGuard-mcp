package tools

import (
	"encoding/json"
	"fmt"
	"processguard-mcp/internal/config"
	"processguard-mcp/internal/tools/handlers"
)

type ToolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// Registry returns all tools Claude can call.
func Registry() []ToolDef {
	return []ToolDef{
		{
			Name:        "list_processes",
			Description: "List all running processes with PID, name, parent PID, CPU%, memory usage, executable path, and current user. Use this as the starting point for any security analysis.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_process_detail",
			Description: "Get deep detail on a single process: full command line, working directory, environment variables (filtered), open file handles count, and thread count.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pid": map[string]interface{}{
						"type":        "integer",
						"description": "Process ID to inspect",
					},
				},
				"required": []string{"pid"},
			},
		},
		{
			Name:        "get_network_connections",
			Description: "List all active TCP/UDP network connections with remote addresses, ports, and associated process. Critical for detecting C2 beacons, data exfiltration, or unexpected outbound connections.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_loaded_modules",
			Description: "List DLLs and modules loaded by a specific process. Use this to detect DLL injection, sideloading, or unexpected libraries in trusted system processes.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pid": map[string]interface{}{
						"type":        "integer",
						"description": "Process ID to inspect",
					},
				},
				"required": []string{"pid"},
			},
		},
		{
			Name:        "get_suspicious_processes",
			Description: "Run automated heuristic checks across all processes: name spoofing (e.g. 'svch0st'), wrong-path system processes, unsigned binaries in temp folders, unusual parent-child relationships, and processes with suspicious keywords in their path.",
			InputSchema: emptySchema(),
		},
		{
			Name:        "get_startup_entries",
			Description: "List programs configured to run at startup via registry Run keys and common startup folders. Persistence mechanisms are a primary indicator of malware.",
			InputSchema: emptySchema(),
		},
	}
}

// Call dispatches a tool call by name.
func Call(cfg *config.Config, name string, args json.RawMessage) (string, error) {
	switch name {
	case "list_processes":
		return handlers.ListProcesses()
	case "get_process_detail":
		var p struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
		return handlers.GetProcessDetail(p.PID)
	case "get_network_connections":
		return handlers.GetNetworkConnections()
	case "get_loaded_modules":
		var p struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
		return handlers.GetLoadedModules(p.PID)
	case "get_suspicious_processes":
		return handlers.GetSuspiciousProcesses()
	case "get_startup_entries":
		return handlers.GetStartupEntries()
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func emptySchema() interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}
