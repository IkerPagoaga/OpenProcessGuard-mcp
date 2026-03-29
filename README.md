# ProcessGuard MCP v2.0

A Windows security monitoring MCP server for Claude Desktop. Exposes live process telemetry, persistence checks, network analysis, and Sysmon forensics through 21 tools organised across 5 hunting stages.

---

## Quick Start

1. Download [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) and [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) from Sysinternals.
2. Edit `config.json` next to the binary with your tool paths.
3. Register the server in `claude_desktop_config.json` (see below).
4. Restart Claude Desktop.

### `claude_desktop_config.json` snippet

```json
{
  "mcpServers": {
    "processguard": {
      "command": "C:\\path\\to\\processguard-mcp.exe"
    }
  }
}
```

---

## Configuration (`config.json`)

```json
{
  "procexp_path":    "C:\\Tools\\SysinternalsSuite\\procexp64.exe",
  "autoruns_path":   "C:\\Tools\\SysinternalsSuite\\autorunsc.exe",
  "tcpview_path":    "",
  "sysmon_log":      "Microsoft-Windows-Sysmon/Operational",
  "vt_api_key":      "",
  "geoip_db":        "",
  "audit_log":       true
}
```

| Field | Required | Description |
|---|---|---|
| `procexp_path` | Yes | Path to `procexp64.exe`. Stage 1 falls back to PowerShell if missing. |
| `autoruns_path` | No | Path to `autorunsc.exe`. Stage 2 skipped if absent. |
| `tcpview_path` | No | Reserved for Stage 3 TCPView CSV enrichment (Phase 3). |
| `sysmon_log` | Auto | Windows Event Log channel. Defaults to the standard Sysmon channel. |
| `vt_api_key` | No | Free VirusTotal API key (4 req/min, 500 req/day). |
| `geoip_db` | No | Path to MaxMind `GeoLite2-City.mmdb` for GeoIP enrichment. |
| `audit_log` | Auto | Enables JSONL audit log to `%APPDATA%\ProcessGuard\audit.log`. |

---

## Tools Reference

### Stage 0 — Native (always available)

| Tool | Description |
|---|---|
| `list_processes` | All running processes: PID, name, PPID, CPU%, memory, exe path, user, status. |
| `get_process_detail` | Deep single-process view: cmdline, CWD, env vars (sensitive values redacted), thread count, open handle count, create time. |
| `get_network_connections` | All TCP/UDP connections via `netstat -ano`, correlated with process names. |
| `get_loaded_modules` | DLLs/modules loaded by a specific PID. Detects injection and sideloading. |
| `get_suspicious_processes` | Heuristic scan: name spoofing (`svch0st`), wrong-path system processes, unsigned binaries in temp dirs, unusual parent-child chains. |
| `get_startup_entries` | Registry Run keys and startup folder entries (lightweight). |

### Stage 1 — Process Explorer (`procexp_path` required)

| Tool | Description |
|---|---|
| `get_process_tree` | Full parent-child tree with signing status, company, VirusTotal score. Falls back to PowerShell if procexp unavailable. |
| `get_unsigned_processes` | Processes without a trusted digital signature. |

### Stage 2 — Autoruns (`autoruns_path` required)

| Tool | Description |
|---|---|
| `get_autoruns_entries` | All persistence points: Run/RunOnce, Scheduled Tasks, Services, Drivers, BHOs, Codecs, and more. Runs `autorunsc.exe -a * -c -h -s -nobanner`. |
| `flag_autoruns_anomalies` | Filtered high-risk entries only: unsigned, suspicious path, VirusTotal hits. |

### Stage 3 — Network

| Tool | Description |
|---|---|
| `get_established_connections` | ESTABLISHED TCP connections only (filters LISTENING/TIME_WAIT noise). |
| `get_foreign_connections` | Connections to non-private IPs with optional GeoIP country/ASN enrichment. Primary C2 and data-exfil candidates. |

### Stage 4 — Sysmon (Sysmon service required)

| Tool | Description |
|---|---|
| `query_sysmon_events` | Query any Sysmon Event ID within the last N minutes. IDs: 1=ProcessCreate, 3=NetworkConnect, 7=ImageLoaded, 11=FileCreate. |
| `get_process_create_events` | Sysmon Event 1 records: cmdline, parent image, user, hashes. Forensic timeline. |
| `get_network_events` | Sysmon Event 3 records: outbound connections at creation time. C2 beacon detection. |

### Stage 5 — VirusTotal (`vt_api_key` required)

| Tool | Description |
|---|---|
| `lookup_hash` | SHA256 hash reputation check. Returns detection score (e.g. `5/72`). Results cached 24 h. Rate-limited to 4 req/min to match free tier. |

### Orchestration

| Tool | Description |
|---|---|
| `run_full_hunt` | Executes all four stages sequentially. Returns a `HuntReport` with `CRITICAL/HIGH/MEDIUM/INFO` severity buckets, executive summary, and recommended actions. This is the primary entry point for a full security audit. |

---

## Recommended Claude Prompts

### Full system audit
```
Run run_full_hunt and walk me through the findings, starting with CRITICAL and HIGH severity. 
For any unsigned process or suspicious autorun, use lookup_hash to check its reputation.
```

### Investigate a suspicious PID
```
I think PID 4821 is behaving oddly. Run get_process_detail and get_loaded_modules on it, 
then check its network activity with get_established_connections filtered to that process.
```

### Persistence check after suspected infection
```
Run flag_autoruns_anomalies and list anything that's unsigned or has a VirusTotal hit.
For each flagged entry, try to correlate with get_process_create_events for the last 120 minutes.
```

### C2 beacon hunt
```
Use get_foreign_connections to list all outbound internet connections, grouped by country.
Then use get_network_events (last 60 min) to see which processes opened those connections.
Flag anything that beacons at a regular interval.
```

### Post-incident forensics
```
Pull get_process_create_events and get_network_events for the last 240 minutes.
Build a timeline of new processes and their outbound connections.
Cross-reference any unsigned spawned process with lookup_hash.
```

---

## Security Notes

- **Env var redaction**: `get_process_detail` strips any env var whose name contains `token`, `secret`, `password`, `key`, `credential`, `auth`, `private`, `cert`, `jwt`, or `bearer`. The value is replaced with `[REDACTED]`.
- **VT API key**: Never echoed in any tool response or audit log.
- **Audit log**: Every tool call is written to `%APPDATA%\ProcessGuard\audit.log` as JSONL with tool name, safe args, duration, and any error. Audit failures are silent and never crash the server.
- **Admin rights**: Run Claude Desktop as Administrator to ensure Sysmon Event Log access and full process enumeration.

---

## Architecture

```
processguard-mcp.exe  (stdio JSON-RPC 2.0)
├── internal/config        Config load + tool availability matrix
├── internal/audit         Append-only JSONL audit log
├── internal/geoip         MaxMind GeoLite2 wrapper + private-IP CIDR detection
├── internal/procex        Process Explorer path verification
└── internal/tools
    ├── tools.go           Tool registry + Call() dispatcher (with audit hook)
    └── handlers/
        ├── processes.go   list_processes, get_process_detail (env redaction), get_network_connections
        ├── modules.go     get_loaded_modules
        ├── heuristics.go  get_suspicious_processes
        ├── startup.go     get_startup_entries
        ├── procex.go      get_process_tree, get_unsigned_processes (procexp CSV + PS fallback)
        ├── autoruns.go    get_autoruns_entries, flag_autoruns_anomalies
        ├── network.go     get_established_connections, get_foreign_connections
        ├── sysmon.go      query_sysmon_events, get_process_create_events, get_network_events
        ├── virustotal.go  lookup_hash (cache + rate limiter)
        └── hunt.go        run_full_hunt orchestrator
```

---

## Open Blockers

| # | Item | Status |
|---|---|---|
| P1 | procexp64 headless CSV mode | Implemented — verify your version supports `/t /p <file>` |
| P2 | Autoruns column layout | Run `autorunsc.exe -a * -c -nobanner` manually and inspect header row |
| P3 | MaxMind GeoLite2-City.mmdb | Download free from [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data), set `geoip_db` |
| P4 | Sysmon install | Install with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config), verify `Get-WinEvent` returns events |
| VT | VirusTotal API key | Register free at [virustotal.com](https://www.virustotal.com), set `vt_api_key` |
