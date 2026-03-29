# ProcessGuard MCP

A local MCP server that exposes your Windows machine's process data to Claude for AI-powered security analysis.

## Tools exposed to Claude

| Tool | Description |
|---|---|
| `list_processes` | All running processes with PID, name, CPU, memory, path, user |
| `get_process_detail` | Deep detail on a single PID: cmdline, cwd, threads, handles |
| `get_network_connections` | All active TCP/UDP connections with owning process |
| `get_loaded_modules` | DLLs loaded by a process (injection detection) |
| `get_suspicious_processes` | Automated heuristic scan across all processes |
| `get_startup_entries` | Registry Run keys + startup folder entries |

## Build

```powershell
cd C:\Users\get_h\Documents\VSCode\ProcessGuard\processGuard-mcp
go mod tidy
go build -o processguard-mcp.exe .
```

## Config

The server resolves the ProcessExplorer path in this order:
1. `PROCEXP_PATH` environment variable
2. `config.json` next to the binary
3. Interactive prompt on first run (saves to config.json)

Your current config: `config.json` already points to `C:\Users\get_h\Downloads\ProcessExplorer\procexp64.exe`

## Claude Desktop integration

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "processguard": {
      "command": "C:\\Users\\get_h\\Documents\\VSCode\\ProcessGuard\\processGuard-mcp\\processguard-mcp.exe"
    }
  }
}
```

> **Important:** Run Claude Desktop as Administrator so the MCP server can access all process details.

## Prompt for analysis

Once connected, paste this into Claude:

```
Using the processguard tools, perform a full security analysis of my machine:
1. Call list_processes and get_suspicious_processes
2. Call get_network_connections and flag any unusual outbound connections
3. Call get_startup_entries and flag anything unexpected
4. Produce a structured threat report with: Executive Summary, Suspicious Processes, Network Anomalies, Persistence Mechanisms, and Recommended Actions
```
