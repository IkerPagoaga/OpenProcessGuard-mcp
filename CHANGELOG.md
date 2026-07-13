# Changelog

All notable changes to ProcessGuard MCP are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.4.0] - 2026-07-13

Polish release driven by a fifth external review (every finding of which was
verified against the code before being acted on).

### Fixed
- **Sysmon availability is now probed live — a machine without Sysmon can no longer
  read as a clean Stage 4.** `sysmon_log` always carries a default, so the config-level
  availability flag was permanently true: the Stage-4 `TOOL_UNAVAILABLE` finding and the
  "Install Sysmon" recommendation were unreachable dead code, and on a Sysmon-less
  machine the query's `-ErrorAction SilentlyContinue` swallowed the missing-channel
  error, reporting the stage silently clean — a violation of the project's own
  "absence of findings is not proof" principle. The query script now checks the Event
  Log channel exists first (`Get-WinEvent -ListLog`) and emits a distinguishable
  marker when it doesn't; `run_full_hunt` reports the probed availability, surfaces
  the `INFO / TOOL_UNAVAILABLE` finding, and recommends installing Sysmon. The three
  standalone Sysmon tools return a clear "is Sysmon installed?" error instead of `[]`.
  The event query itself also fails loud now: it runs with `-ErrorAction Stop`,
  classifies the benign zero-events case by locale-invariant
  `FullyQualifiedErrorId` (never message text), and reports every other read
  failure — access denied on a non-elevated host, EventLog service down — as a
  query error (`SCAN_ERROR` in the hunt) instead of masquerading as an empty
  result, closing the second silent-clean lane the probe alone did not cover.
- **`autorunsc` is invoked with `-vt` alongside `-v`.** Without `-vt`, a machine where
  the VirusTotal terms of service were never accepted gets an interactive prompt (per
  Microsoft's Autoruns documentation) — in this headless context that meant Stage 2
  and `get_autoruns_entries` stalled until the 45s timeout killed them. Because `-v`
  performs a VirusTotal hash lookup per unique autostart binary, the VT-enabled
  autorunsc path now runs under a raised (still hard-bounded) 180s budget so a
  cold-cache first scan is not killed by the 45s default. SECURITY.md and README §8
  now disclose the full behavior: with a key configured, Autoruns scans submit binary
  **hashes** (never file contents) to VirusTotal via autorunsc's own integration, and
  `-vt` records a persistent ToS acceptance under `HKCU\Software\Sysinternals`.
- **`get_process_detail.open_handles` is real now.** gopsutil's `NumFDs` is not
  implemented on Windows (the only supported OS), so the field always rendered 0. The
  count now comes from the Windows `GetProcessHandleCount` API (via
  `golang.org/x/sys/windows`, resolved from System32 only) and is omitted entirely
  when it cannot be read — never a fake zero.
- **`get_process_tree` can no longer fail on a PPID cycle.** Windows PID reuse can
  make a snapshot claim A's parent is B while B's recorded parent PID was reused by
  A; linking both built a cyclic node graph, and `json.Marshal` fails on cycles,
  killing the whole response. A cycle-breaking ancestry check roots the offending
  node instead (regression-tested).

### Removed
- **`list_processes.status` field** — gopsutil's `Status` is likewise unimplemented on
  Windows, so it was a permanently-empty column implying a capability the tool never
  had.
- **`procexp_path` and `tcpview_path` config fields, and the reserved `internal/procex`
  package.** Stage-1 signing has come from the built-in `Get-AuthenticodeSignature`
  since v2.1.0 and the TCPView integration was never activated — the fields were pure
  carrying cost. Config compatibility: old `config.json` files that still carry these
  keys keep working (unknown fields are ignored). `run_full_hunt`'s `tool_availability`
  no longer reports `process_explorer`, and its `sysmon` value now reflects the live
  probe rather than the config default.

### Changed
- **Toolchain pinned to `go1.25.12`** (carries stdlib fixes that landed after
  go1.25.11). `golang.org/x/sys` promoted to a direct dependency (for
  `GetProcessHandleCount`) and bumped v0.20.0 → v0.47.0, clearing the uncalled
  GO-2026-5024 advisory — `govulncheck` now reports zero vulnerabilities anywhere
  in the dependency graph. The x/sys bump raises the source floor from Go 1.22 to
  Go 1.25 (with the default `GOTOOLCHAIN=auto` this is transparent — older Go
  fetches the pinned toolchain automatically). CI actions bumped to their Node-24
  majors (`actions/checkout@v7`, `actions/setup-go@v6`).
- `install.ps1` source builds now inject `Commit` and `BuildDate` (matching the
  Makefile/goreleaser), so `serverInfo` no longer reports `commit: none` on a source
  install.
- `config.example.json` ships all-empty (no pre-filled paths to tools that are not
  installed), matching the README's minimum config.

### Documentation
- **Corrected the README's Sysinternals licensing notice**, which contradicted the
  LICENSE: the Sysinternals-licensed integrations are Stage 2 (Autoruns) and Stage 4
  (Sysmon) — not "Stages 1 and 2" — and the unrestricted stages are 0, 1, 3, and 5.
- **The manual build-and-register path (README §2–6) is now explicitly labeled
  dev-only**, with a warning that registering an exe from a user-writable clone folder
  with an elevated Claude Desktop is the binary-planting scenario SECURITY.md warns
  about; the recommended path is the verified signed release via `install.ps1`.
- Sysmon setup no longer instructs a needless Claude Desktop restart (events are
  queried live); the from-source size estimate corrected to ~10 MB; the stage count
  phrased as "five hunt stages plus the always-on Stage 0".

## [2.3.0] - 2026-07-13

### Changed
- **Concurrent request dispatch.** The stdio JSON-RPC loop now reads requests serially
  but dispatches them concurrently (bounded to 16 in flight), so a long `run_full_hunt`
  no longer blocks a quick `list_processes`. Responses carry their own id and are
  serialised onto stdout through a write mutex; a panic in any single request can no
  longer take down the server. Two deliberate exceptions: the `initialize` handshake is
  answered synchronously (a pipelining client can never observe a `tools/*` reply
  arriving ahead of the handshake), and a failed stdout write cancels the server's
  lifetime context — in-flight tool invocations abort with their child processes
  killed, no new requests are accepted, and the server exits even if the host still
  holds stdin open — instead of silently dispatching work to a dead client pipe
  forever.
- **Every shell-out and the VirusTotal HTTP call now run under the server's lifetime
  context.** `tools.Call` threads a context through every handler down to
  `exec.CommandContext` / `http.NewRequestWithContext`, so cancellation (host death)
  kills children mid-flight instead of letting them run to their own timeouts; a
  cancelled `run_full_hunt` also skips its remaining stages and stops consuming
  VirusTotal quota.
- **`get_process_detail` env-var redaction is now a default-deny allowlist.** Every
  variable NAME is still listed, but a VALUE is revealed only for a curated set of
  non-sensitive names (`PATH`, `OS`, `PROCESSOR_*`, program/data paths, locale/shell
  vars); every other value is redacted regardless of format, so an unknown-format
  credential in an unrecognised, benignly-named variable can no longer leak into the
  model context. The prior name/prefix denylist is retained as a secondary check on
  allowlisted names. See LIMITATIONS.md for the residual gaps.

### Fixed
- **VirusTotal result cache is now bounded.** Expired entries are evicted on read and
  swept on the leader path of each upstream lookup, instead of accumulating for the life
  of the process (reads gated on the 24h TTL but nothing was ever freed).
- **Audit log's enabled/file check moved inside its mutex.** The unguarded fast-path
  read could race a concurrent `Close()` under any future teardown refactor (latent
  today — shutdown drains all in-flight requests first). The audit package also gains
  its first test: 16 concurrent writers + a Log-vs-Close overlap, asserting every JSONL
  line lands intact (race-detector-verified).
- **Sysmon query timestamp is culture-safe and DST-exact.** `query_sysmon_events` /
  `get_process_create_events` / `get_network_events` compute the lookback window
  in-script as `[datetime]::UtcNow.AddMinutes(-N)` — a direct UTC clock read — instead
  of round-tripping a Go-formatted timestamp through `[datetime]::Parse`, which is
  culture-sensitive and mis-parsed on non-English Windows. Reading UTC directly also
  makes the window exactly N minutes across every DST transition (local-time
  arithmetic was off by up to the offset, and even a local→UTC conversion is
  ambiguous during the fall-back hour).

### Security
- **Tool panic details no longer reach the model.** A handler panic is converted to a
  generic error at the tool boundary; the full panic value **and stack trace** go to
  the operator's stderr log only, so uncontrolled internal state (paths, indexes,
  partial values) cannot enter the LLM context through a crash message.
- **Panicking tool calls are still audit-logged.** The audit write now runs in a defer,
  so the invocation that crashed — exactly the one a forensics audit trail must not
  lose — is recorded (with a generic panic marker) instead of being skipped by the
  unwind.

### Added
- `initialize` `serverInfo` now surfaces `commit` and `buildDate` (injected at release
  time via `-ldflags`) alongside `version`, so a running server reports its exact build.

### Docs
- README documents that Go 1.22 is the source-compatibility floor while the build
  toolchain auto-upgrades to the pinned `go1.25.11` (network-dependent on first build;
  offline/proxy guidance added). README's prompt-injection section now points at
  LIMITATIONS.md for the honest trust-boundary posture.

## [2.2.0] - 2026-07-06

### Added
- **`run_full_hunt` Stage 1 now runs the Authenticode signing lens** alongside the
  gopsutil heuristics. A plain unsigned or untrusted binary that trips no heuristic
  (not name-spoofing, not in a temp dir, not Office-spawned) previously produced zero
  findings in the flagship hunt, even though `get_unsigned_processes` would surface it.
  Tampering (`HashMismatch`) and untrusted issuers (`NotTrusted`) escalate to HIGH;
  merely-unsigned processes are surfaced as INFO and counted (unsigned is common for
  legitimate software); a signature present-but-unverifiable is reported as
  UNVERIFIED (not "unsigned"); an un-evaluable signature (unreadable path when
  non-elevated) is treated as UNKNOWN and skipped. The pass runs under a bounded
  sub-timeout and degrades to an INFO note — never a whole-hunt PARTIAL — if it
  cannot complete.

### Security
- System binaries (`netstat`, `reg`, `tasklist`, `powershell`) are executed by their
  absolute, canonical `C:\Windows\System32` path — resolved WITHOUT trusting the
  `%SystemRoot%` environment variable — instead of a bare name, closing a PATH-order
  hijack against the elevated server. Operator-configured tool paths (e.g. `autorunsc`)
  are unchanged.
- `get_process_detail` env-var redaction now also catches connection-string / DSN
  variable names and values carrying a well-known secret prefix (`ghp_`, `AKIA`,
  `xox…`, `sk-`, `AIza`, PEM, JWT), so a credential in an oddly-named variable no
  longer leaks into the model context.

### Fixed
- README documented the install path as `%LOCALAPPDATA%\ProcessGuard`; `install.ps1`
  actually installs to the admin-only `%ProgramFiles%\ProcessGuard`. The docs now match
  the code and its anti-binary-plant rationale.
- `query_sysmon_events` clamps an out-of-range `since_minutes` to the valid window
  (matching `get_process_create_events` / `get_network_events`) instead of erroring.
- Corrected the `run_full_hunt` "4-stage" label (it runs five stages) across the tool
  description and code comments; SECURITY.md changelog now reflects the real v2.1.x
  release history.

### Changed
- `list_processes` documents that `cpu_percent` is a cumulative average over the
  process's lifetime, not an instantaneous sample.
- Documented that the heuristic parent-child check uses a live PID→name snapshot (which
  misses an already-exited parent and is PPID-spoofable); Sysmon Event 1 in Stage 4 is
  authoritative for that pattern where Sysmon is present.
- First unit tests for `internal/run` (absolute-path resolver + command timeout), the
  `tools` dispatch/validation layer (`dispatchPID` bounds, `sinceArg` clamp,
  `safeAuditArgs` redaction), env-var redaction, and the Stage-1 signing-lens classifier
  (`signingFindings`) — the untested paths the external review flagged.

## [2.1.2] - 2026-07-03

### Security
- `install.ps1` restricts `config.json` (which may hold the VirusTotal API key) to
  Administrators + SYSTEM via `icacls`, and prints the command to run after creating
  it — files under `%ProgramFiles%` are world-readable by default, so this keeps the
  key out of reach of non-admin accounts.
- Removed the legacy `PROCEXP_PATH` environment variable: config is now read only from
  `config.json` in the admin-only install directory, so no user-scoped env var can
  steer the elevated server.

### Fixed
- VirusTotal rate-limit token is refunded when a lookup never reaches the upstream
  (transport failure / panic), so a VirusTotal outage no longer drains the per-minute
  budget. An HTTP error response still counts (it consumed real VT quota).

## [2.1.1] - 2026-07-03

### Fixed
- **Autoruns signing verdict inverted (false negative):** `autorunsc` emits the signer
  as `(Not verified) <Publisher>`, but the check compared against the bare
  `(Not verified)` string, so a real unverified entry was marked verified — suppressing
  the `UNSIGNED` flag and the Stage-2 HIGH escalation. Verification is now a `(Verified)`
  prefix test, and a "Microsoft" publisher is trusted only when actually verified.
- **`explorer.exe` flagged as malware on every hunt:** the name-spoof check matched the
  pattern `"explore"` as a substring, tripping on the legitimate Windows shell and
  `iexplore.exe` (NAME_SPOOF → HIGH). Spoof patterns now match the base name exactly.
- **Unreachable CRITICAL, renamed for accuracy:** the only Stage-1 CRITICAL was declared but
  never emitted. It now fires as `SYSTEM_MASQUERADE` when a core system-process name (svchost,
  lsass, csrss, …) runs from a user-writable/temp directory — a near-certain masquerade. It
  detects on-disk path masquerade, not in-memory hollowing, hence the accurate name; dual-use
  binaries (cmd/powershell/rundll32) from temp stay at HIGH rather than escalating to CRITICAL.
- **Unsigned-process bypass:** `get_unsigned_processes` skipped any process whose signer
  subject merely contained "microsoft"; an invalid or self-signed certificate naming
  Microsoft no longer evades the check (trust requires a Valid Authenticode status).
- **Silent scan failures:** a configured stage that errored returned no findings,
  indistinguishable from a clean result. Failed stages now emit a visible `SCAN_ERROR`.
- **Duplicate Autoruns scan:** `run_full_hunt` ran `autorunsc -a *` twice (Stages 2 and 5);
  it now runs once and shares the parsed entries, roughly halving hunt time when Autoruns
  is enabled.
- GeoIP private-range detection now covers IPv6 link-local (`fe80::/10`) and CGNAT
  (`100.64.0.0/10`), previously reported as foreign/internet.
- VirusTotal `permalink` is now the human `gui/file/<hash>` URL, not the auth-only API
  `self` link; the rate limiter refills gradually (a true token bucket) instead of
  resetting at a fixed-window boundary; `startup` registry parsing also reads
  `REG_MULTI_SZ` values.

### Changed
- Tool-execution failures are returned as MCP results with `isError: true` (so the model
  sees the failure as tool output) rather than as JSON-RPC `-32603` transport errors.
- `install.ps1` installs to `%ProgramFiles%\ProcessGuard` (admin-only) and requires
  elevation, preventing a non-admin binary-plant against the elevated server.

### Removed
- Never-populated fields (`ProcessNode` company/description/cpu/mem; GeoIP `asn`/`asn_org`)
  and the "country/ASN data" claim from `get_foreign_connections` (ASN was never produced).
  README prompt-injection wording aligned with SECURITY.md — control-character stripping and
  length caps only; semantic injection is not neutralised.

## [2.1.0] - 2026-07-03

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
