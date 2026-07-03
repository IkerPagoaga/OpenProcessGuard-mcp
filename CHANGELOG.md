# Changelog

All notable changes to ProcessGuard MCP are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Central `internal/run` external-process runner with a bounded context timeout on
  every shell-out (a hung `netstat`/`powershell`/`reg`/`autorunsc` can no longer stall
  the server).
- Pure, unit-tested `internal/parse` package (netstat, autoruns CSV, Sysmon XML).
- Structured `slog` logging; build metadata (version/commit/date) injected via `-ldflags`.
- CI workflow: build, `go vet`, gofmt gate, race tests + coverage, `govulncheck`, staticcheck.
- Signed-release pipeline: goreleaser, `SHA256SUMS`, cosign keyless signatures, CycloneDX SBOM.
- `install.ps1` one-command installer and zero-config first run (native tools work immediately).

### Fixed
- First-run no longer reads stdin (which hung the MCP handshake under Claude Desktop); a
  malformed `config.json` now fails fast instead of dropping into an interactive prompt.
- VirusTotal score denominator now includes every analysis bucket — previously understated
  (e.g. `0/12` for a clean file scanned by 72 engines).
- Process tree / unsigned detection derive signatures via `Get-AuthenticodeSignature` instead
  of a non-functional Process Explorer CSV launch that stalled ~30s per call.
- Autoruns CSV parsed per RFC-4180; an absent Signer column no longer flags every entry UNSIGNED.
- Sysmon XML parsing tolerates markup inside values and unescapes entities (command-line
  evidence is no longer truncated).
- `run_full_hunt` executive summary reports the real duration (was always `0ms`).
- Forensic fields (command lines, hashes, Sysmon XML) are no longer truncated to 512 runes or
  HTML-escaped in tool output.
- `netstat` PID parsing is checked (a non-numeric PID is dropped, not coerced to System PID 0).
- Process Explorer is no longer a dependency: Stage 1 uses the built-in `Get-AuthenticodeSignature`,
  so the docs/LICENSE no longer instruct users to download it. LICENSE clarified — ProcessGuard bundles
  no Microsoft binaries; only Autoruns (Stage 2) and Sysmon (Stage 4) are optional Sysinternals integrations.
- Release workflow guarded to the public repo (`OpenProcessGuard-mcp`) so the private mirror stops failing
  with a cross-repo 403 on publish.

### Security
- SHA256 hashes are hex-validated before use in VirusTotal request URLs.
- Race-free VirusTotal cache coalescing (concurrent identical lookups make one upstream call).

## [2.0.0] - 2026-04-01

### Added
- 17 tools across 5 hunting stages (native, signing, Autoruns, Sysmon, VirusTotal, GeoIP).
- Prompt-injection output sanitisation, PID/since-minutes bounds, `sysmon_log` whitelist,
  append-only audit log, threat model (SECURITY.md), MIT + Sysinternals-carve-out LICENSE.

## [1.0.0] - 2026-03-28

### Added
- Initial release: native process enumeration, a 5-flag heuristic engine, netstat-based network
  connections, DLL enumeration, and startup-entry discovery over stdio JSON-RPC 2.0.
