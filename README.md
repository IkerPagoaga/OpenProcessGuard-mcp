# ProcessGuard MCP v2.0

A Windows security monitoring MCP server for Claude Desktop. Exposes live process telemetry, persistence checks, network analysis, and Sysmon forensics through 21 tools organised across 5 hunting stages.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone the Repository](#2-clone-the-repository)
3. [Build the Binary](#3-build-the-binary)
4. [Create config.json](#4-create-configjson)
5. [Register with Claude Desktop](#5-register-with-claude-desktop)
6. [Run Claude Desktop as Administrator](#6-run-claude-desktop-as-administrator)
7. [Verify the Installation](#7-verify-the-installation)
8. [Optional Tools](#8-optional-tools)
9. [Troubleshooting](#9-troubleshooting)
10. [Tools Reference](#10-tools-reference)
11. [Recommended Prompts](#11-recommended-prompts)
12. [Security Notes](#12-security-notes)
13. [Architecture](#13-architecture)

---

## 1. Prerequisites

Before you start, make sure the following are installed on your Windows machine.

### Required

| Software | Version | Download |
|---|---|---|
| Windows | 10 or 11 (64-bit) | — |
| Go | 1.22 or newer | https://go.dev/dl/ |
| Git | Any recent version | https://git-scm.com/download/win |
| Claude Desktop | Latest | https://claude.ai/download |

**Verify Go is installed** — open a terminal (`Win + R` → type `cmd` → Enter) and run:

```
go version
```

You should see something like `go version go1.22.0 windows/amd64`. If you get "command not found", Go is not in your PATH — reinstall it and make sure you check "Add to PATH" during setup.

---

## 2. Clone the Repository

You need to be added as a collaborator by the repo owner before you can clone.

Open a terminal and run:

```
git clone https://github.com/IkerPagoaga/processGuard-mcp.git
cd processGuard-mcp
```

> If git asks for credentials, use your GitHub username and a [Personal Access Token](https://github.com/settings/tokens) (not your password).

---

## 3. Build the Binary

From inside the `processGuard-mcp` folder, run:

```
go build -o processguard-mcp.exe .
```

Go will automatically download all dependencies and compile the binary. This takes about 30 seconds on first run.

**Verify it worked:**

```
dir processguard-mcp.exe
```

You should see the file listed at around 8 MB. If the build fails, make sure your Go version is 1.22 or newer (`go version`).

> **Note:** You do not need to install any extra Go packages manually. `go build` handles everything via `go.mod`.

---

## 4. Create config.json

Create a file named exactly `config.json` in the **same folder as `processguard-mcp.exe`**.

### Minimum config (no optional tools)

This is enough to get started. All 6 Stage 0 tools will work immediately with no additional software.

```json
{
  "procexp_path":  "",
  "autoruns_path": "",
  "tcpview_path":  "",
  "sysmon_log":    "Microsoft-Windows-Sysmon/Operational",
  "vt_api_key":    "",
  "geoip_db":      "",
  "audit_log":     true
}
```

Copy this exactly, save the file as `config.json`, and move on. You can fill in the optional fields later (see [Step 8](#8-optional-tools)).

### Full config (all optional tools configured)

```json
{
  "procexp_path":  "C:\\Tools\\SysinternalsSuite\\procexp64.exe",
  "autoruns_path": "C:\\Tools\\SysinternalsSuite\\autorunsc.exe",
  "tcpview_path":  "",
  "sysmon_log":    "Microsoft-Windows-Sysmon/Operational",
  "vt_api_key":    "your_virustotal_api_key_here",
  "geoip_db":      "C:\\Tools\\GeoIP\\GeoLite2-City.mmdb",
  "audit_log":     true
}
```

### Config field reference

| Field | Required | Default | Description |
|---|---|---|---|
| `procexp_path` | No | `""` | Full path to `procexp64.exe`. Enables Stage 1 tools. Falls back to PowerShell if empty. |
| `autoruns_path` | No | `""` | Full path to `autorunsc.exe`. Enables Stage 2 persistence scanning. |
| `tcpview_path` | No | `""` | Reserved — not yet active. |
| `sysmon_log` | No | `"Microsoft-Windows-Sysmon/Operational"` | Windows Event Log channel for Sysmon. Leave as default unless you have a custom Sysmon config. |
| `vt_api_key` | No | `""` | Free VirusTotal API key. Enables `lookup_hash` and Stage 5 hash escalation. |
| `geoip_db` | No | `""` | Path to MaxMind `GeoLite2-City.mmdb`. Enables country/city data on foreign connections. |
| `audit_log` | No | `true` | Writes a JSONL audit log to `%APPDATA%\ProcessGuard\audit.log`. |

> **Important:** All paths in `config.json` must use **double backslashes** (`\\`), not single backslashes. For example: `C:\\Tools\\procexp64.exe`.

---

## 5. Register with Claude Desktop

This tells Claude Desktop where to find the ProcessGuard server.

### Find the config file

Open File Explorer and navigate to:

```
%APPDATA%\Claude\
```

You can paste that path directly into the File Explorer address bar and press Enter.

Look for a file named `claude_desktop_config.json`.

- **If the file exists:** open it in Notepad or any text editor.
- **If the file does not exist:** create a new file in that folder named `claude_desktop_config.json`.

### Add the ProcessGuard entry

If the file is **empty or new**, paste this entire content:

```json
{
  "mcpServers": {
    "processguard": {
      "command": "C:\\path\\to\\processGuard-mcp\\processguard-mcp.exe"
    }
  }
}
```

If the file **already has other MCP servers**, add only the `processguard` block inside the existing `mcpServers` object:

```json
{
  "mcpServers": {
    "some-other-server": {
      "command": "..."
    },
    "processguard": {
      "command": "C:\\path\\to\\processGuard-mcp\\processguard-mcp.exe"
    }
  }
}
```

> **Replace** `C:\\path\\to\\processGuard-mcp\\` with the actual folder where you cloned the repo. Use double backslashes. Example: `C:\\Users\\YourName\\Documents\\processGuard-mcp\\processguard-mcp.exe`

### Save and close the file.

---

## 6. Run Claude Desktop as Administrator

ProcessGuard needs Administrator rights to enumerate all running processes and read the Sysmon Event Log.

**How to run Claude Desktop as Administrator:**

1. Find the Claude Desktop shortcut on your Desktop or Start Menu.
2. Right-click it.
3. Select **"Run as administrator"**.
4. Click Yes on the UAC prompt.

> If you skip this step, Stage 0 tools will still work but some processes will be hidden, and Sysmon tools will return empty results.

To make this permanent so you don't have to remember every time:

1. Right-click the Claude Desktop shortcut → **Properties**.
2. Click **Advanced**.
3. Check **"Run as administrator"**.
4. Click OK → Apply.

---

## 7. Verify the Installation

Once Claude Desktop is open (as Administrator), type the following into the chat:

```
Run list_processes and show me the top 5 by memory usage.
```

If you see a table or list of running processes with PIDs and memory figures, **the installation is working correctly**.

Then run the full baseline scan:

```
Run run_full_hunt and summarise all findings by severity.
```

This will run all available stages and return a structured report. Stages with unconfigured tools (Autoruns, Sysmon, VirusTotal) will appear as `INFO / TOOL_UNAVAILABLE` findings with instructions on how to enable them.

---

## 8. Optional Tools

Each optional tool unlocks additional hunting stages. Install them in any order. After adding each tool's path to `config.json`, **restart Claude Desktop** for the change to take effect.

---

### Sysinternals Process Explorer (Stage 1)

Enables: `get_process_tree`, `get_unsigned_processes`

**Install:**

1. Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
2. Extract the zip to a permanent folder (e.g. `C:\Tools\SysinternalsSuite\`).
3. Open `config.json` and set:

```json
"procexp_path": "C:\\Tools\\SysinternalsSuite\\procexp64.exe"
```

4. Restart Claude Desktop.

---

### Sysinternals Autoruns (Stage 2)

Enables: `get_autoruns_entries`, `flag_autoruns_anomalies`, Stage 2 in `run_full_hunt`

**Install:**

1. Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
2. Extract the zip to a permanent folder (e.g. `C:\Tools\SysinternalsSuite\`).
3. Open `config.json` and set:

```json
"autoruns_path": "C:\\Tools\\SysinternalsSuite\\autorunsc.exe"
```

> Use `autorunsc.exe` (the command-line version), not `autoruns.exe` (the GUI version).

4. Restart Claude Desktop.

**Verify it works:**

Open a terminal as Administrator and run:

```
C:\Tools\SysinternalsSuite\autorunsc.exe -a * -c -nobanner -accepteula
```

You should see CSV output with a header row. This confirms ProcessGuard can call it correctly.

---

### VirusTotal API Key (Stage 5)

Enables: `lookup_hash`, VT hash escalation in `run_full_hunt`

**Get a free API key:**

1. Go to https://www.virustotal.com and create a free account.
2. After logging in, click your profile icon (top right) → **API key**.
3. Copy the key.
4. Open `config.json` and set:

```json
"vt_api_key": "paste_your_key_here"
```

5. Restart Claude Desktop.

> The free tier allows 4 requests per minute and 500 per day. ProcessGuard's `run_full_hunt` caps VT calls at 10 per hunt to stay within these limits.

---

### MaxMind GeoIP Database (Stage 3 enrichment)

Enables: country and city data on `get_foreign_connections`

> Without this, `get_foreign_connections` still works and correctly filters out private IPs — you just won't see country names.

**Get the free database:**

1. Create a free MaxMind account at: https://www.maxmind.com/en/geolite2/signup
2. After signing in, go to **Download Databases**.
3. Download **GeoLite2-City** in `.mmdb` format.
4. Extract and place the `.mmdb` file somewhere permanent (e.g. `C:\Tools\GeoIP\GeoLite2-City.mmdb`).
5. Open `config.json` and set:

```json
"geoip_db": "C:\\Tools\\GeoIP\\GeoLite2-City.mmdb"
```

6. Restart Claude Desktop.

---

### Sysmon (Stage 4)

Enables: `query_sysmon_events`, `get_process_create_events`, `get_network_events`, Stage 4 in `run_full_hunt`

**Install:**

1. Download Sysmon from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Download a recommended config file (SwiftOnSecurity's is a solid starting point):
   https://github.com/SwiftOnSecurity/sysmon-config — download `sysmonconfig-export.xml`
3. Open a terminal **as Administrator** and run:

```
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

4. Verify Sysmon is running:

```
Get-Service Sysmon64
```

You should see `Status: Running`.

> No `config.json` change is needed. The `sysmon_log` field already defaults to the correct Windows Event Log channel (`Microsoft-Windows-Sysmon/Operational`).

5. Restart Claude Desktop.

**Verify it works in Claude:**

```
Run query_sysmon_events with event_id=1 and since_minutes=10
```

You should see a list of process creation events from the last 10 minutes.

---

## 9. Troubleshooting

### Tools don't appear in Claude Desktop

- Make sure `claude_desktop_config.json` is valid JSON (no trailing commas, all paths use `\\`).
- Confirm the path in the config points to `processguard-mcp.exe` and the file exists.
- Restart Claude Desktop **as Administrator** after every config change.

### `go build` fails

- Run `go version` — must be 1.22 or newer.
- Make sure you are inside the `processGuard-mcp` folder when you run `go build`.
- If you see network errors downloading dependencies, check your internet connection or corporate proxy settings.

### `list_processes` returns empty or fewer processes than expected

- Claude Desktop is not running as Administrator. See [Step 6](#6-run-claude-desktop-as-administrator).

### `get_foreign_connections` returns local IPs (192.168.x.x etc.)

- This is fixed in v2.0. Make sure you built the binary after cloning — don't use an old `.exe`.

### Sysmon tools return empty arrays

- Confirm Sysmon is running: open PowerShell as Administrator and run `Get-Service Sysmon64`.
- If the service is stopped, start it: `Start-Service Sysmon64`.
- If Sysmon is not installed, follow the [Sysmon install steps](#sysmon-stage-4) above.

### Autoruns returns an error

- Confirm `autoruns_path` in `config.json` points to `autorunsc.exe` (not `autoruns.exe`).
- Run `autorunsc.exe -a * -c -nobanner -accepteula` manually in an admin terminal to confirm it works.

### VirusTotal returns "rate limit reached"

- The free tier allows 4 requests per minute. Wait 60 seconds and try again.
- `run_full_hunt` caps VT calls at 10 per run automatically.

### config.json changes aren't taking effect

- You must **restart Claude Desktop** after every change to `config.json`. The server reads it once at startup.

---

## 10. Tools Reference

### Stage 0 — Native (always available, no config needed)

| Tool | Description |
|---|---|
| `list_processes` | All running processes: PID, name, PPID, CPU%, memory, exe path, user. |
| `get_process_detail` | Deep single-process view: cmdline, CWD, env vars (secrets redacted), thread count, handle count. |
| `get_network_connections` | All TCP/UDP connections via `netstat -ano`, correlated with process names. |
| `get_loaded_modules` | DLLs/modules loaded by a specific PID. Detects injection and sideloading. |
| `get_suspicious_processes` | Heuristic scan: name spoofing (`svch0st`), wrong-path system processes, hollow process patterns, unsigned binaries in temp dirs, unusual parent-child chains. |
| `get_startup_entries` | Registry Run keys and startup folder entries (lightweight). |

### Stage 1 — Process Explorer (`procexp_path` required)

| Tool | Description |
|---|---|
| `get_process_tree` | Full parent-child tree with signing status and company info. Falls back to PowerShell if procexp unavailable. |
| `get_unsigned_processes` | All running processes without a trusted digital signature. |

### Stage 2 — Autoruns (`autoruns_path` required)

| Tool | Description |
|---|---|
| `get_autoruns_entries` | All persistence points: Run/RunOnce keys, Scheduled Tasks, Services, Drivers, BHOs, Codecs, and more. |
| `flag_autoruns_anomalies` | Filtered high-risk entries only: unsigned, suspicious path, VirusTotal hits. |

### Stage 3 — Network

| Tool | Description |
|---|---|
| `get_established_connections` | ESTABLISHED TCP connections only (filters LISTENING/TIME_WAIT noise). |
| `get_foreign_connections` | Connections to non-private internet IPs, with optional GeoIP country data. Primary C2 and data-exfil candidates. |

### Stage 4 — Sysmon (Sysmon service required)

| Tool | Description |
|---|---|
| `query_sysmon_events` | Query any Sysmon Event ID within the last N minutes. IDs: 1=ProcessCreate, 3=NetworkConnect, 7=ImageLoaded, 11=FileCreate. |
| `get_process_create_events` | Sysmon Event 1 records: cmdline, parent image, user, hashes. Forensic timeline. |
| `get_network_events` | Sysmon Event 3 records: outbound connections at creation time. C2 beacon detection. |

### Stage 5 — VirusTotal (`vt_api_key` required)

| Tool | Description |
|---|---|
| `lookup_hash` | SHA256 hash reputation check. Returns detection score (e.g. `5/72`). Results cached 24 h. Rate-limited to 4 req/min. |

### Orchestration

| Tool | Description |
|---|---|
| `run_full_hunt` | Executes all stages sequentially and returns a structured `HuntReport` with `CRITICAL/HIGH/MEDIUM/INFO` severity buckets, executive summary, and recommended actions. |

---

## 11. Recommended Prompts

### Full system audit
```
Run run_full_hunt and walk me through the findings, starting with CRITICAL and HIGH severity.
For any unsigned process or suspicious autorun with a SHA256, use lookup_hash to check its reputation.
```

### Investigate a suspicious process
```
I think PID 4821 is behaving oddly. Run get_process_detail and get_loaded_modules on it,
then check its network activity with get_established_connections.
```

### Persistence check after suspected infection
```
Run flag_autoruns_anomalies and list anything that's unsigned or has a VirusTotal hit.
For each flagged entry, try to correlate with get_process_create_events for the last 120 minutes.
```

### C2 beacon hunt
```
Use get_foreign_connections to list all outbound internet connections grouped by country.
Then use get_network_events for the last 60 minutes to see which processes opened those connections.
Flag anything that beacons at a regular interval.
```

### Post-incident forensic timeline
```
Pull get_process_create_events and get_network_events for the last 240 minutes.
Build a timeline of new processes and their outbound connections.
Cross-reference any unsigned spawned process with lookup_hash.
```

---

## 12. Security Notes

- **Env var redaction:** `get_process_detail` strips any environment variable whose name contains `token`, `secret`, `password`, `key`, `credential`, `auth`, `private`, `cert`, `jwt`, or `bearer`. The value is replaced with `[REDACTED]`.
- **VT API key:** Never echoed in any tool response or written to the audit log.
- **Audit log:** Every tool call is written to `%APPDATA%\ProcessGuard\audit.log` as JSONL with tool name, safe args, duration, and any error. Audit failures are silent and never crash the server.
- **Admin rights:** Run Claude Desktop as Administrator to ensure Sysmon Event Log access and full process enumeration. ProcessGuard does not escalate privileges on its own.
- **Private repo:** This repository is private. Do not share your clone URL or invite collaborators beyond trusted testers.

---

## 13. Architecture

```
processguard-mcp.exe  (stdio JSON-RPC 2.0 — MCP protocol)
├── internal/config        Config load + tool availability matrix
├── internal/audit         Append-only JSONL audit log
├── internal/geoip         MaxMind GeoLite2 wrapper + private-IP CIDR detection
├── internal/procex        Process Explorer path verification
└── internal/tools
    ├── tools.go           Tool registry + Call() dispatcher (with audit hook)
    └── handlers/
        ├── processes.go   list_processes, get_process_detail, get_network_connections
        ├── modules.go     get_loaded_modules
        ├── heuristics.go  get_suspicious_processes (name spoof, wrong path, hollow pattern)
        ├── startup.go     get_startup_entries
        ├── procex.go      get_process_tree, get_unsigned_processes
        ├── autoruns.go    get_autoruns_entries, flag_autoruns_anomalies
        ├── network.go     get_established_connections, get_foreign_connections
        ├── sysmon.go      query_sysmon_events, get_process_create_events, get_network_events
        ├── virustotal.go  lookup_hash (24h cache + 4 req/min rate limiter)
        └── hunt.go        run_full_hunt orchestrator (Stages 1–5)
```
