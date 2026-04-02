# Security Policy

## Overview

ProcessGuard MCP is a **read-only** Windows security monitoring tool. It observes the local system and reports findings — it does not modify files, registry keys, network settings, or any system state. This document describes the threat model, known limitations, and how to report security issues responsibly.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| v2.x (current) | ✅ Yes |
| v1.x | ❌ No — please update |

---

## Threat Model

### What ProcessGuard does

- Reads live OS data: running processes, network connections, loaded modules, startup entries, Sysmon event logs.
- Calls optional external binaries you configure: `procexp64.exe`, `autorunsc.exe`.
- Makes outbound HTTPS requests to VirusTotal only when `vt_api_key` is configured and `lookup_hash` is called.
- Writes an append-only audit log to `%APPDATA%\ProcessGuard\audit.log`.

### What ProcessGuard does NOT do

- It opens **no listening ports** of any kind. The MCP server communicates exclusively over `stdin`/`stdout` with Claude Desktop — no TCP socket, no HTTP server, no named pipe exposed externally.
- It does not write to the registry, modify files, or change system configuration.
- It does not exfiltrate data. The only outbound network call is VirusTotal HTTPS, and only when you explicitly configure an API key.
- It does not escalate privileges on its own — it runs with whatever rights Claude Desktop was launched with.

---

## Privilege Requirements and Risks

ProcessGuard requires Claude Desktop to be run as **Administrator** in order to:
- Read the Sysmon Windows Event Log.
- Enumerate processes owned by other users and the SYSTEM account.

**This means `processguard-mcp.exe` runs with Administrator rights.**

Users should be aware of the following implications:

- Only install and run ProcessGuard on machines **you personally control**.
- Do not expose the Claude Desktop session to untrusted users or networks while ProcessGuard is enabled.
- Review the MCP server list in `claude_desktop_config.json` periodically to ensure no unintended tools are registered alongside ProcessGuard.

---

## Prompt Injection Mitigations

ProcessGuard collects raw OS data — process names, command lines, registry keys, file paths — and passes it to Claude's context window. An attacker who can run a process or set a registry key on your machine could craft a value that looks like an LLM instruction (prompt injection).

The following mitigations are implemented:

| Layer | Mitigation |
|---|---|
| **String truncation** | Every string field returned to Claude is capped at 512 characters. |
| **Control character stripping** | ASCII control characters (< 0x20, DEL) are removed from all output, except tab and newline. |
| **Non-printable Unicode removal** | Non-printable Unicode code points are replaced with `?`. |
| **Output sanitisation at boundary** | All tool output passes through `sanitiseJSON()` in `tools.go` before it reaches Claude — individual handlers do not need to sanitise. |
| **Env var redaction** | `get_process_detail` redacts any environment variable whose name matches: `token`, `secret`, `password`, `passwd`, `pwd`, `key`, `apikey`, `api_key`, `credential`, `auth`, `private`, `cert`, `jwt`, `bearer`. |
| **Config validation** | `sysmon_log` in `config.json` is validated against a strict allowlist regex at startup — only alphanumeric characters, spaces, hyphens, slashes, underscores, and dots are permitted. This prevents PowerShell injection via a crafted config value. |

**Residual risk:** These mitigations reduce the attack surface but cannot eliminate prompt injection entirely. A sophisticated attacker with local code execution could craft payloads that survive sanitisation. The primary defence is running ProcessGuard only on machines you control.

---

## API Key Handling

- The VirusTotal API key (`vt_api_key`) is stored in `config.json` on disk.
- It is sent only as an HTTPS header to `api.virustotal.com` — never logged, never included in tool responses.
- `config.json` is excluded from the repository via `.gitignore` and must never be committed.
- File permissions on `config.json` should be restricted: on Windows, ensure only your user account has read access (right-click → Properties → Security).

---

## Network Exposure

ProcessGuard does **not** open any listening ports. The attack surface is:

| Interface | Direction | Description |
|---|---|---|
| `stdin` / `stdout` | Inbound from Claude Desktop | MCP JSON-RPC 2.0 protocol — local process pipe only |
| HTTPS to `api.virustotal.com` | Outbound | Only when vt_api_key is configured and lookup_hash is called |
| HTTPS to MaxMind (none) | None | GeoIP database is a local file — no network calls |

---

## Dependency Security

ProcessGuard uses two runtime dependencies:

| Package | Purpose | Notes |
|---|---|---|
| `github.com/oschwald/geoip2-golang` | MaxMind GeoLite2 reader | Read-only local file access |
| `github.com/shirou/gopsutil/v3` | Process and network enumeration | Well-maintained, Windows-compatible |

Both are pinned in `go.sum`. Run `go mod verify` after cloning to confirm integrity.

To check for known vulnerabilities in dependencies:
```
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

---

## Microsoft Sysinternals Licence

ProcessGuard integrates with **Sysinternals** tools (Process Explorer, Autoruns) published by Microsoft. These tools are provided under the [Microsoft Software Licence Terms for Sysinternals](https://learn.microsoft.com/en-us/sysinternals/license-terms).

**Key restrictions:**
- Sysinternals tools may not be redistributed without Microsoft's permission.
- They may not be used in commercial products without a separate licence agreement with Microsoft.
- ProcessGuard does **not** bundle, redistribute, or modify any Sysinternals binary. Users download them directly from Microsoft.

Because ProcessGuard integrates with Sysinternals tools, **it cannot be used as part of a commercial product or monetised offering** without a separate agreement with Microsoft.

---

## Reporting a Vulnerability

If you discover a security vulnerability in ProcessGuard, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead:

1. Go to the [GitHub Security Advisories](https://github.com/IkerPagoaga/OpenProcessGuard-mcp/security/advisories) page.
2. Click **"New draft security advisory"**.
3. Describe the vulnerability, steps to reproduce, and potential impact.

We aim to acknowledge reports within **72 hours** and provide a resolution timeline within **7 days**.

---

## Changelog

| Date | Change |
|---|---|
| 2026-04-01 | Initial public release. Added prompt injection mitigations, config validation, PID range checks, and this security policy. |
