# Limitations

ProcessGuard is a useful triage and hunting aid, not an EDR or a rootkit detector.
Know what it can and cannot do before relying on it.

## Scope

- **User-mode (ring 3) visibility only.** It enumerates via Windows APIs and
  standard tools. A kernel-mode rootkit that hides processes, connections, or
  modules from those APIs will hide from ProcessGuard too.
- **Windows only.** It shells out to Windows-specific tools (netstat, tasklist,
  reg, PowerShell, optional Sysinternals). There is no Linux/macOS build.
- **Point-in-time.** Tools observe the current state; they are not a continuous
  monitor. Process-hollowing and beacon detection depend on Sysmon's historical
  event log, which only covers what Sysmon was configured to record.

## Detection caveats

- **Heuristics produce candidates, not verdicts.** Name-spoofing, wrong-path,
  suspicious-parent, and temp-path flags are starting points for investigation,
  not proof of compromise. Expect false positives and false negatives.
- **Signing status depends on the platform.** `get_unsigned_processes` reflects
  `Get-AuthenticodeSignature`; catalog-signed system binaries and revoked/expired
  certificates are reported as the OS sees them.
- **Optional stages need setup.** Autoruns, Sysmon, VirusTotal, and GeoIP each
  require configuration or installation; when absent, their stage is reported
  `TOOL_UNAVAILABLE`, never silently counted as clean. Sysmon's health is probed
  live in two layers: a missing Event Log channel reports "not installed"
  (`TOOL_UNAVAILABLE`), and a channel that exists but cannot be *read* — access
  denied on a non-elevated host, or the EventLog service down — reports a query
  failure (`SCAN_ERROR`) instead of masquerading as zero events. One residual
  ambiguity: a channel whose *registration* is unreadable by the server's token
  fails the existence probe and is reported as not-installed; the finding and
  recommendation text both carry the "or run elevated" hedge for that case.

## Trust boundary

- **Output is untrusted.** All returned strings originate from the live OS and can
  contain adversary-controlled text. ProcessGuard sanitises them at the MCP
  boundary, but prompt-injection cannot be prevented with 100% certainty — treat
  tool output as evidence to read, never as instructions to follow.
- **Environment-variable values are allowlist-gated, not fully secret-proof.**
  `get_process_detail` lists every variable NAME but reveals a VALUE only for a
  curated set of non-sensitive names (`PATH`, `OS`, `PROCESSOR_*`, program/data
  paths, `USERNAME`, `COMPUTERNAME`, locale/shell, …); every other value is redacted,
  so an unknown-format credential in an unrecognised variable does not leak. Three
  residual points to know: (1) a secret deliberately placed in an *allowlisted*,
  writable variable (e.g. stuffed into `PATH` or `TEMP`) is caught only by the
  secondary denylist, which matches **known credential prefixes** (`ghp_`, `AKIA`,
  PEM, JWT, …) — a raw password or a bare hex/base64 key with no recognised prefix
  would still be shown; (2) allowlisted values still expose the local username and
  machine name (not a secret, but recon — the AD domain and domain-controller are
  deliberately withheld); (3) variable NAMES are never gated, so the *presence* of a
  var like `AWS_SECRET_ACCESS_KEY` is visible even though its value is redacted.
  Values are gated, names are not.
- **Privileges.** Full visibility across all processes requires the MCP client to
  run elevated. ProcessGuard inherits the client's rights and never escalates.
- **Shutdown on a dead client cancels in-flight work.** When the host's stdout pipe
  dies the server cancels its lifetime context: running tool invocations abort and
  their child processes are killed immediately (`exec.CommandContext`), no new
  requests are accepted, and the server exits — even if the host still holds stdin
  open. The one residual is a host that *wedges*: it keeps reading neither pipe nor
  closing them (e.g. a suspended host process), which blocks a stdout write forever
  with no error to detect. That is a failure mode of the trusted MCP host itself —
  the only process holding the pipes — not attacker-reachable surface, and it is in
  the same class as the host suspending the server outright.

## Not included

- No remediation, quarantine, or process termination (read-only by design).
- No memory forensics, no disk imaging, no network capture.
- No telemetry or phone-home of any kind.
