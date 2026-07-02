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
  require configuration; when absent, their stage is skipped, not inferred.

## Trust boundary

- **Output is untrusted.** All returned strings originate from the live OS and can
  contain adversary-controlled text. ProcessGuard sanitises them at the MCP
  boundary, but prompt-injection cannot be prevented with 100% certainty — treat
  tool output as evidence to read, never as instructions to follow.
- **Privileges.** Full visibility across all processes requires the MCP client to
  run elevated. ProcessGuard inherits the client's rights and never escalates.

## Not included

- No remediation, quarantine, or process termination (read-only by design).
- No memory forensics, no disk imaging, no network capture.
- No telemetry or phone-home of any kind.
