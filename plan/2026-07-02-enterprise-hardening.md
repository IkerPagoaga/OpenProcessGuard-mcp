# ProcessGuard MCP — Enterprise Hardening Roadmap

_Status: in progress · started 2026-07-02 · target release: **v2.1.0** (first signed public release)_

ProcessGuard is a read-only Windows process-forensics MCP server. This roadmap takes the
v2.0 codebase — already sound in architecture and security model — to an enterprise bar:
verifiable signed releases, verified dependencies, full test coverage, a smooth install,
and complete documentation.

An external review plus a three-lens internal audit (architecture, security/supply-chain,
testing/install/docs) produced the finding set below. The verdict: a genuinely useful,
well-architected tool that is not yet enterprise-ready. This roadmap closes that gap.

## Findings addressed

**Correctness**
- First-run config prompt reads `os.Stdin`, which collides with the MCP stdio channel and can
  hang the handshake; a malformed `config.json` silently falls into the same trap. → fail-fast
  on invalid config, gate any prompt on a real TTY.
- `run_full_hunt` executive summary always reported `0ms` (duration set after the summary was built).
- VirusTotal score denominator omitted `harmless`/`timeout`/`type-unsupported` → wrong totals.
- Autoruns CSV parsed with a hand-rolled splitter (no RFC-4180 `""` escaping); a missing Signer
  column flagged every entry `UNSIGNED`. → parse with `encoding/csv`; treat absent signer as *unknown*.
- Process Explorer has no CSV-export CLI switch; the old path launched the GUI and stalled ~30s each
  call before falling back. → make the PowerShell signing path primary.
- Output sanitiser truncated forensic fields (command lines, hashes, Sysmon XML) to 512 runes and
  HTML-escaped `<>&`. → exempt forensic fields; disable HTML escaping.
- No `context` timeout on any external process → a hung child could block the server. → central
  tool-runner with `exec.CommandContext` + shared timeout.
- Locale/column-fragile `netstat` parsing; unchecked `fmt.Sscanf`; Sysmon XML truncation on
  `</Data>` inside a value; PowerShell single-object-vs-array dropout; unvalidated sha256 before URL.
- UTF-8 BOM in one source file; formatting drift across the tree.

**Supply chain & release**
- No CI, no `govulncheck`, no checksums, no SBOM, no signing, no tags; version hardcoded; committed binary.

**Testing** — zero test files; parsers entangled with live `exec` calls.

**Install** — build-from-source only; manual config with absolute paths; external Sysinternals deps.

## Phased plan

0. **Setup** — this roadmap; baseline build verified green.
1. **Architecture** — extract pure parsers into `internal/parse`; central `internal/run` tool-runner
   with context timeouts; structured `slog`; coalesce the VirusTotal cache.
2. **Correctness** — land every fix above on the new structure.
3. **Security** — MCP protocol-version negotiation; SHA256 hex validation before the VirusTotal
   request; disclosure note in SECURITY.md. (config.json is user-created under user-scoped
   `%LOCALAPPDATA%`, so no extra ACL step is applied; the audit log is written `0600`.)
4. **Testing** — table-driven unit tests over the extracted parsers + the sanitiser/config/cache;
   coverage gate in CI.
5. **Supply chain** — CI (build, vet, gofmt gate, `go test -race` + coverage, `govulncheck`,
   staticcheck); release pipeline (goreleaser, `windows/amd64`+`arm64`, `-ldflags` version injection,
   `SHA256SUMS`, cosign keyless signing, SBOM); `CHANGELOG.md`.
6. **Install** — zero-config first run; Sysinternals auto-discovery; `install.ps1`; README rewrite
   around a signed-release download with a copy-paste Claude Desktop config block.
7. **Docs** — `CONTRIBUTING.md`, `ARCHITECTURE.md`, `LIMITATIONS.md`, README polish.
8. **Release** — purge the committed binaries + old `config.json` from git history, then cut the
   first signed release. This step rewrites public history and force-pushes; it is destructive and
   runs only under explicit approval. No secret was ever committed (`vt_api_key` is empty in every
   historical blob), so this is history *hygiene*, not secret remediation — no key rotation needed.

   Safe procedure (order matters — the hardening commits currently exist only locally):
   1. **Back up first.** Push the current hardening commits to both remotes so nothing is lost if the
      rewrite goes wrong: `git push origin main` and `git push public main`.
   2. **Fresh mirror clone** (filter-repo refuses to rewrite a working repo): `git clone --mirror <url> pg-mirror`.
   3. **Purge** in the mirror: `git filter-repo --path-glob '*.exe' --path-glob '*.exe~' --path config.json --invert-paths`.
   4. **Verify clean:** `git -C pg-mirror rev-list --objects --all | grep -iE '\.exe|config\.json'` returns nothing.
   5. **Force-push the rewritten history to BOTH remotes** (`origin` = `processGuard-mcp`, `public` =
      `OpenProcessGuard-mcp`) so they don't diverge. This also publishes the already-local #3/#4/#6/#7 fixes.
   6. **Tag `v2.1.0`** on the rewritten tip and push the tag — this fires `release.yml` (goreleaser +
      cosign keyless + SBOM). Publish the drafted GitHub Release after verifying the artifact.
9. **Verify** — full build/test/vuln pass + end-to-end MCP checks + release-artifact verification.

## Verifying a release (target UX)

```bash
sha256sum -c processguard-mcp_2.1.0_SHA256SUMS
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/IkerPagoaga/OpenProcessGuard-mcp/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature processguard-mcp_2.1.0_SHA256SUMS.sig \
  --certificate processguard-mcp_2.1.0_SHA256SUMS.pem \
  processguard-mcp_2.1.0_SHA256SUMS
```
