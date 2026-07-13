# ProcessGuard MCP

> A free, open-source Windows security monitoring server for Claude Desktop.

ProcessGuard exposes live process telemetry, persistence checks, network analysis, and Sysmon forensics through 17 tools organised across five hunt stages plus the always-on native Stage 0 — all callable by Claude in plain language.

**Built on the belief that security tooling should be open, auditable, and free.**

---

## Principles

**Open source, fully auditable.** Every line of code is public. No telemetry, no phone-home, no hidden behaviour. If you don't trust it, read it.

**Security by design.** ProcessGuard opens no listening ports. It communicates exclusively over `stdin`/`stdout` with Claude Desktop. OS-sourced strings are stripped of control characters and length-capped before reaching Claude — this defeats terminal-escape and zero-width/bidi tricks but **cannot** neutralise semantic injection, so tool output is treated as evidence, never instructions. Environment variable values are surfaced under a default-deny allowlist (only curated non-sensitive names reveal their value). The VirusTotal API key never appears in tool output or logs.

**Read-only.** ProcessGuard observes — it does not modify files, registry keys, network settings, or any system state.

**Responsive under load.** Requests are dispatched concurrently (bounded to 16 in flight), so a multi-minute `run_full_hunt` never blocks a quick `list_processes`; the `initialize` handshake is always answered first. If the client ever disconnects, in-flight tool invocations are cancelled and their child processes killed — an orphaned elevated server never keeps scanning for nobody.

**Free as in freedom.** MIT licensed. Fork it, extend it, contribute back.

**Microsoft Sysinternals notice.** The optional Stage 2 (Autoruns) and Stage 4 (Sysmon) integrate with Sysinternals tools published by Microsoft under a [separate licence](https://learn.microsoft.com/en-us/sysinternals/license-terms). Those tools are not bundled — you download them directly from Microsoft. Because of that licence, **ProcessGuard cannot be used as part of a commercial or monetised product when Sysinternals integration is enabled.** Stages 0, 1, 3, and 5 (native process enumeration, built-in Authenticode signing, network analysis, and VirusTotal) are unrestricted. See [§15 Licence](#15-licence).

---

## Quick start

**Option A — signed release (recommended).** Download the latest signed build from
[Releases](https://github.com/IkerPagoaga/OpenProcessGuard-mcp/releases), verify it (below), then:

```powershell
.\install.ps1 -BinaryPath .\processguard-mcp.exe
```

**Option B — from source** (Go auto-selects the pinned `go1.25.12` toolchain):

```powershell
git clone https://github.com/IkerPagoaga/OpenProcessGuard-mcp.git
cd OpenProcessGuard-mcp
.\install.ps1
```

`install.ps1` installs the binary under `%ProgramFiles%\ProcessGuard` — an admin-only-writable
location, so a non-elevated attacker cannot plant a trojaned binary that the elevated server would
run — and registers it with Claude Desktop. Restart Claude Desktop and ask it to run `list_processes`. **Native tools work
immediately with no config file** — add `config.json` (copy `config.example.json`) only to enable
the optional Autoruns / Sysmon / VirusTotal / GeoIP stages.

### Verifying a release

Every release ships a `SHA256SUMS` file signed with [cosign](https://docs.sigstore.dev/) keyless
signing — no long-lived key; the signature is bound to this repo's GitHub Actions identity:

```bash
sha256sum -c processguard-mcp_<version>_SHA256SUMS
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/IkerPagoaga/OpenProcessGuard-mcp/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature processguard-mcp_<version>_SHA256SUMS.sig \
  --certificate processguard-mcp_<version>_SHA256SUMS.pem \
  processguard-mcp_<version>_SHA256SUMS
```

A CycloneDX SBOM is attached to every release for supply-chain audits.

**More docs:** [ARCHITECTURE.md](ARCHITECTURE.md) · [LIMITATIONS.md](LIMITATIONS.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md)

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
12. [Security](#12-security)
13. [Architecture](#13-architecture)
14. [Contributing](#14-contributing)
15. [Licence](#15-licence)

---

## 1. Prerequisites

Before you start, make sure the following are installed on your Windows machine.

### Required

| Software | Version | Download |
|---|---|---|
| Windows | 10 or 11 (64-bit) | — |
| Go | 1.25 or newer | https://go.dev/dl/ |
| Git | Any recent version | https://git-scm.com/download/win |
| Claude Desktop | Latest | https://claude.ai/download |

> **Go 1.25 is the source floor; the pinned build toolchain is `go1.25.12`** (it resolves several standard-library advisories reachable via the VirusTotal HTTPS client). With the default `GOTOOLCHAIN=auto`, the first build on an older Go transparently downloads `go1.25.12` — which needs network access and will fail behind a strict proxy or offline. In that case install Go 1.25.12+ directly, or set `GOTOOLCHAIN=local` to build with your installed Go (only if it is ≥ 1.25.12).

**Verify Go is installed** — open a terminal (`Win + R` → type `cmd` → Enter) and run:

```
go version
```

You should see something like `go version go1.25.12 windows/amd64`. If not, reinstall Go and check "Add to PATH" during setup.

---

## 2. Clone the Repository

> **⚠️ Dev-only path.** Sections 2–6 are the manual, build-it-yourself setup: they register the binary from your **user-writable clone folder** and then run Claude Desktop elevated. That is exactly the binary-planting scenario [SECURITY.md](SECURITY.md) warns about — anything that can write to the clone folder could replace the exe an elevated server runs. Fine on a single-user dev box you trust; for anything else, use the **recommended path** (Quick start above): a verified signed release installed by `install.ps1` into the admin-only-writable `%ProgramFiles%\ProcessGuard`.

```
git clone https://github.com/IkerPagoaga/OpenProcessGuard-mcp.git
cd OpenProcessGuard-mcp
```

---

## 3. Build the Binary

From inside the `OpenProcessGuard-mcp` folder, run:

```
go build -o processguard-mcp.exe .
```

Go downloads all dependencies automatically. This takes about 30 seconds on first run.

**Verify it worked:**

```
dir processguard-mcp.exe
```

You should see a file around 10 MB (the release pipeline's `-s -w` flags trim it further). If the build fails, confirm Go 1.25 or newer is installed (`go version`).

> You do not need to install any packages manually — `go build` handles everything via `go.mod`.

---

## 4. Create config.json

Create a file named exactly `config.json` in the **same folder as `processguard-mcp.exe`**.

You can copy the template:

```
copy config.example.json config.json
```

### Minimum config (no optional tools)

This gets all 6 Stage 0 tools working immediately — no additional software needed.

```json
{
  "autoruns_path": "",
  "sysmon_log":    "Microsoft-Windows-Sysmon/Operational",
  "vt_api_key":    "",
  "geoip_db":      "",
  "audit_log":     true
}
```

### Full config (all optional tools configured)

```json
{
  "autoruns_path": "C:\\Tools\\SysinternalsSuite\\autorunsc.exe",
  "sysmon_log":    "Microsoft-Windows-Sysmon/Operational",
  "vt_api_key":    "your_virustotal_api_key_here",
  "geoip_db":      "C:\\Tools\\GeoIP\\GeoLite2-City.mmdb",
  "audit_log":     true
}
```

### Config field reference

| Field | Required | Default | Description |
|---|---|---|---|
| `autoruns_path` | No | `""` | Full path to `autorunsc.exe`. Enables Stage 2 persistence scanning. |
| `sysmon_log` | No | `"Microsoft-Windows-Sysmon/Operational"` | Windows Event Log channel for Sysmon. Only alphanumeric characters, spaces, hyphens, slashes, underscores, and dots are allowed. |
| `vt_api_key` | No | `""` | Free VirusTotal API key. Enables `lookup_hash` and Stage 5 hash escalation. Never echoed in output or logs. |
| `geoip_db` | No | `""` | Path to MaxMind `GeoLite2-City.mmdb`. Enables country/city data on foreign connections. |
| `audit_log` | No | `true` | Writes a JSONL audit log to `%APPDATA%\ProcessGuard\audit.log`. |

> **Important:** All paths in `config.json` must use **double backslashes** (`\\`). For example: `C:\\Tools\\SysinternalsSuite\\autorunsc.exe`.

> **Security:** `config.json` is listed in `.gitignore` and must never be committed to version control — it may contain your VirusTotal API key and local paths.

---

## 5. Register with Claude Desktop

Open File Explorer and navigate to:

```
%APPDATA%\Claude\
```

Open (or create) `claude_desktop_config.json` and add the ProcessGuard entry:

```json
{
  "mcpServers": {
    "processguard": {
      "command": "C:\\path\\to\\OpenProcessGuard-mcp\\processguard-mcp.exe"
    }
  }
}
```

If the file already has other MCP servers, add the `processguard` block inside the existing `mcpServers` object.

> Replace `C:\\path\\to\\OpenProcessGuard-mcp\\` with the actual folder where you cloned the repo. Use double backslashes.

> **⚠️ Security:** this registers an exe living in a **user-writable folder** with a server you are about to run **as Administrator** (Step 6). Do not use this registration on a shared or untrusted machine — install via `install.ps1` instead, which places the binary under the admin-only-writable `%ProgramFiles%\ProcessGuard` and registers that path. See the warning in [SECURITY.md](SECURITY.md) ("Do not relocate the binary to a user-writable directory").

---

## 6. Run Claude Desktop as Administrator

ProcessGuard needs Administrator rights to enumerate all running processes and read the Sysmon Event Log.

1. Find the Claude Desktop shortcut on your Desktop or Start Menu.
2. Right-click it → **"Run as administrator"**.
3. Click Yes on the UAC prompt.

To make this permanent:

1. Right-click the shortcut → **Properties**.
2. Click **Advanced**.
3. Check **"Run as administrator"**.
4. Click OK → Apply.

> If you skip this step, Stage 0 tools still work but some processes will be hidden and Sysmon tools will return empty results.

---

## 7. Verify the Installation

Once Claude Desktop is open (as Administrator), type:

```
Run list_processes and show me the top 5 by memory usage.
```

If you see a list of running processes with PIDs and memory figures, the installation is working.

Then run the full baseline scan:

```
Run run_full_hunt and summarise all findings by severity.
```

Stages whose tools are unconfigured or not installed (Autoruns, Sysmon, VirusTotal) will appear as `INFO / TOOL_UNAVAILABLE` findings with instructions on how to enable them — Sysmon's availability is probed live against the Event Log channel, so a machine without Sysmon is reported honestly rather than counted as a clean stage.

---

## 8. Optional Tools

Each optional tool unlocks additional hunting stages. Install them in any order. After adding each tool's path to `config.json`, **restart Claude Desktop** for the change to take effect.

---

### Stage 1 — Signing (no download required)

Enables: `get_process_tree`, `get_unsigned_processes`

Stage 1 derives Authenticode signing status from the built-in Windows `Get-AuthenticodeSignature` — **no Sysinternals download is needed**, and no configuration either: these tools work out of the box.

---

### Sysinternals Autoruns (Stage 2)

Enables: `get_autoruns_entries`, `flag_autoruns_anomalies`, Stage 2 in `run_full_hunt`

1. Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
2. Extract to a permanent folder (e.g. `C:\Tools\SysinternalsSuite\`).
3. Set in `config.json`:

```json
"autoruns_path": "C:\\Tools\\SysinternalsSuite\\autorunsc.exe"
```

> Use `autorunsc.exe` (command-line version), not `autoruns.exe` (GUI version).

> **VirusTotal interaction:** if you also configure `vt_api_key`, every Autoruns scan runs `autorunsc -v -vt` — autorunsc submits the SHA256 **hashes** of your autostart binaries (never file contents) to VirusTotal through its own anonymous integration, and `-vt` records your acceptance of the [VirusTotal terms](https://www.virustotal.com/en/about/terms-of-service/) under `HKCU\Software\Sysinternals` (persistent — it also covers future manual autorunsc runs). Configuring the key is treated as that opt-in; leave `vt_api_key` empty for a fully offline Autoruns stage.

4. Restart Claude Desktop.

**Verify it works:** Open a terminal as Administrator and run:

```
C:\Tools\SysinternalsSuite\autorunsc.exe -a * -c -nobanner -accepteula
```

You should see CSV output with a header row.

---

### VirusTotal API Key (Stage 5)

Enables: `lookup_hash`, VT hash escalation in `run_full_hunt`

1. Create a free account at https://www.virustotal.com.
2. Click your profile icon → **API key**.
3. Copy the key and set in `config.json`:

```json
"vt_api_key": "paste_your_key_here"
```

4. Restart Claude Desktop.

> Free tier: 4 requests/minute, 500/day. ProcessGuard caps VT calls at 10 per full hunt automatically.

> **Side effect on the Autoruns stage:** with a key configured, Autoruns scans also query VirusTotal via autorunsc's own integration (hash submission only — see the note in the Autoruns section above). Those calls don't use your key and don't count against ProcessGuard's per-hunt cap.

---

### MaxMind GeoIP Database (Stage 3 enrichment)

Enables country and city data on `get_foreign_connections`.

> Without this, `get_foreign_connections` still works — you just won't see country names.

1. Create a free MaxMind account at: https://www.maxmind.com/en/geolite2/signup
2. Download **GeoLite2-City** in `.mmdb` format.
3. Extract and place the `.mmdb` file somewhere permanent (e.g. `C:\Tools\GeoIP\GeoLite2-City.mmdb`).
4. Set in `config.json`:

```json
"geoip_db": "C:\\Tools\\GeoIP\\GeoLite2-City.mmdb"
```

5. Restart Claude Desktop.

---

### Sysmon (Stage 4)

Enables: `query_sysmon_events`, `get_process_create_events`, `get_network_events`, Stage 4 in `run_full_hunt`

1. Download Sysmon from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Download a recommended config (SwiftOnSecurity's is a solid starting point): https://github.com/SwiftOnSecurity/sysmon-config — download `sysmonconfig-export.xml`
3. Open a terminal **as Administrator** and run:

```
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

4. Verify Sysmon is running:

```
Get-Service Sysmon64
```

You should see `Status: Running`.

> No `config.json` change needed — `sysmon_log` defaults to the correct Windows Event Log channel. **No Claude Desktop restart needed either**: events are queried live from the Event Log, so the very next `run_full_hunt` picks Sysmon up.

---

## 9. Troubleshooting

**Tools don't appear in Claude Desktop**
- Confirm `claude_desktop_config.json` is valid JSON (no trailing commas, double backslashes).
- Confirm the path points to `processguard-mcp.exe` and the file exists.
- Restart Claude Desktop as Administrator after every config change.

**`go build` fails**
- Confirm Go 1.25 or newer is installed (`go version`).
- Confirm you are inside the `OpenProcessGuard-mcp` folder when you run `go build`.

**`list_processes` returns fewer processes than expected**
- Claude Desktop is not running as Administrator. See [Step 6](#6-run-claude-desktop-as-administrator).

**Sysmon tools return empty arrays**
- Confirm Sysmon is running: `Get-Service Sysmon64`.
- If stopped: `Start-Service Sysmon64`.

**Autoruns returns an error**
- Confirm `autoruns_path` points to `autorunsc.exe`, not `autoruns.exe`.
- Test it manually: run `autorunsc.exe -a * -c -nobanner -accepteula` in an admin terminal.

**VirusTotal returns "rate limit reached"**
- Free tier is 4 requests/minute. Wait 60 seconds and retry.

**config.json changes not taking effect**
- Restart Claude Desktop after every `config.json` change — the server reads it once at startup.

---

## 10. Tools Reference

### Stage 0 — Native (always available)

| Tool | Description |
|---|---|
| `list_processes` | All running processes: PID, name, PPID, CPU%, memory, exe path, user. |
| `get_process_detail` | Deep single-process view: cmdline, CWD, env vars (all names listed; values shown only for an allowlist of non-sensitive names, everything else redacted), thread count, handle count. |
| `get_network_connections` | All TCP/UDP connections via `netstat -ano`, correlated with process names. |
| `get_loaded_modules` | DLLs/modules loaded by a specific PID. Detects injection and sideloading. |
| `get_suspicious_processes` | Heuristic scan: name spoofing, wrong-path system processes, hollow process patterns, unsigned binaries in temp dirs, unusual parent-child chains. |
| `get_startup_entries` | Registry Run keys and startup folder entries (lightweight). |

### Stage 1 — Signing (built-in, no external tools)

| Tool | Description |
|---|---|
| `get_process_tree` | Full parent-child tree with Authenticode signing status. |
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
| `get_foreign_connections` | Connections to non-private internet IPs, with optional GeoIP country data. |

### Stage 4 — Sysmon (Sysmon service required)

| Tool | Description |
|---|---|
| `query_sysmon_events` | Query any Sysmon Event ID within the last N minutes. |
| `get_process_create_events` | Sysmon Event 1: cmdline, parent image, user, hashes. Forensic timeline. |
| `get_network_events` | Sysmon Event 3: outbound connections at creation time. C2 beacon detection. |

### Stage 5 — VirusTotal (`vt_api_key` required)

| Tool | Description |
|---|---|
| `lookup_hash` | SHA256 hash reputation check. Returns detection score (e.g. `5/72`). Results cached 24 h. |

### Orchestration

| Tool | Description |
|---|---|
| `run_full_hunt` | Runs all stages sequentially. Returns a structured `HuntReport` with `CRITICAL/HIGH/MEDIUM/INFO` severity buckets, executive summary, and recommended actions. |

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
Run flag_autoruns_anomalies and list anything that is unsigned or has a VirusTotal hit.
For each flagged entry, correlate with get_process_create_events for the last 120 minutes.
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

## 12. Security

### No listening ports

ProcessGuard opens **zero listening ports**. It communicates exclusively over `stdin`/`stdout` with Claude Desktop — no TCP socket, no HTTP server, no named pipe exposed externally.

### Prompt injection mitigations

ProcessGuard collects raw OS data and passes it into Claude's context window. An adversary with local code execution could craft process names or registry keys that look like LLM instructions. The mitigations below strip control characters and cap length — defeating terminal-escape and zero-width/bidi tricks — but they **cannot** neutralise *semantic* injection: a value literally reading "ignore previous instructions and…" passes through unchanged. Tool output is therefore evidence for Claude to reason about, never instructions to follow. The following mitigations are implemented:

- **String truncation** — string fields are capped before leaving the MCP boundary: 512 characters by default, and 16384 for forensic-evidence fields (command lines, hashes, Sysmon XML) so they aren't cut off (those fields carry a larger injection surface by design).
- **Control character stripping** — ASCII control characters (< 0x20, DEL) are stripped from all output.
- **Config validation** — `sysmon_log` is validated against a strict character allowlist at startup to prevent PowerShell injection.
- **Env var allowlist** — `get_process_detail` lists every env var NAME but reveals a VALUE only for a curated allowlist of non-sensitive names (`PATH`, `OS`, `PROCESSOR_*`, program/data paths, `USERNAME`, `COMPUTERNAME`, locale/shell vars). Every other value is redacted regardless of format, so a credential in an unrecognised, benignly-named variable cannot leak. A secondary denylist (secret-ish names + **known credential prefixes** `ghp_`/`AKIA`/PEM/JWT/…) redacts even allowlisted names as defense in depth — though a no-recognised-prefix secret stuffed into an allowlisted writable var can still slip that backstop. See [LIMITATIONS.md](LIMITATIONS.md) for the residual gaps.
- **VT API key isolation** — never echoed in any tool response or written to the audit log.

See [LIMITATIONS.md](LIMITATIONS.md) for the honest trust-boundary posture (semantic injection, the env-value allowlist's residual gaps) and [SECURITY.md](SECURITY.md) for the full threat model and responsible disclosure process.

### Dependency verification

After cloning, verify dependency integrity:

```
go mod verify
govulncheck ./...
```

---

## 13. Architecture

```
processguard-mcp.exe  (stdio JSON-RPC 2.0 — MCP protocol)
├── internal/config        Config load, validation, and tool availability matrix
├── internal/audit         Append-only JSONL audit log (%APPDATA%\ProcessGuard\audit.log)
├── internal/geoip         MaxMind GeoLite2 wrapper + private-IP CIDR detection
└── internal/tools
    ├── tools.go           Registry + Call() dispatcher + output sanitisation boundary
    └── handlers/
        ├── processes.go   list_processes, get_process_detail, get_network_connections
        ├── modules.go     get_loaded_modules
        ├── heuristics.go  get_suspicious_processes
        ├── startup.go     get_startup_entries
        ├── procex.go      get_process_tree, get_unsigned_processes
        ├── autoruns.go    get_autoruns_entries, flag_autoruns_anomalies
        ├── network.go     get_established_connections, get_foreign_connections
        ├── sysmon.go      query_sysmon_events, get_process_create_events, get_network_events
        ├── virustotal.go  lookup_hash (24h cache + 4 req/min rate limiter)
        └── hunt.go        run_full_hunt orchestrator
```

### Data flow

```
Claude Desktop ──stdin──► processguard-mcp.exe
                                │
                         tools.go (dispatch)
                                │
                         handler (OS call)
                                │
                    sanitiseJSON() ◄── all output passes through here
                                │
               Claude Desktop ◄──stdout──
```

---

## 14. Contributing

Contributions are welcome. Please:

1. Fork the repository and create a feature branch.
2. Follow existing code style — no new external dependencies without discussion.
3. Add a handler test if you're adding a new tool.
4. Open a pull request with a clear description of what changed and why.

For security-related contributions, see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## 15. Licence

ProcessGuard MCP is released under the [MIT Licence](LICENSE).

**Important third-party restriction:** ProcessGuard bundles no Microsoft binaries. If you enable the optional Sysinternals-backed stages (by configuring `autoruns_path`, or installing Sysmon), the [Microsoft Sysinternals Licence Terms](https://learn.microsoft.com/en-us/sysinternals/license-terms) apply to those tools — that licence prohibits use in commercial products without a separate agreement with Microsoft. The core, Sysinternals-free stages carry no such restriction. See [LICENSE](LICENSE) for full details.
