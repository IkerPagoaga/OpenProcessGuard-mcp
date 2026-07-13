# Architecture

ProcessGuard is a read-only Windows process-forensics MCP server. It speaks stdio
JSON-RPC 2.0 to an MCP client (e.g. Claude Desktop), exposes a set of read-only
tools, and returns structured JSON. It never modifies the system and opens no
listening ports.

## Layering

```
main.go                     JSON-RPC 2.0 framing + method dispatch (stdio)
  └── internal/tools         tool registry + dispatcher + output sanitiser (the MCP boundary)
        └── handlers          one file per tool/category — thin: run a tool, hand output to a parser
              ├── internal/parse   PURE output parsers (no I/O) — netstat, autoruns CSV, Sysmon XML
              ├── internal/run     external-process runner (exec + timeout + cancellation context)
              ├── internal/config  config load, validation, tool availability
              ├── internal/audit   append-only JSONL audit log
              └── internal/geoip   MaxMind reader + RFC-1918 private-range detection
```

The dependency arrows point inward: handlers depend on `parse`/`run`/`config`,
never the reverse. `parse` is a leaf package (imports nothing internal), which is
what makes it exhaustively unit-testable.

## Two seams that define the design

**1. `run` — the single external-process choke point.** Every shell-out (netstat,
tasklist, reg, powershell, autorunsc) goes through `run.ToolCtx` / `run.PowerShellCtx`,
which wrap `exec.CommandContext` with one shared timeout AND the caller's request
context. A hung child process therefore cannot block the server (timeout), and a
dead client cancels the request context so in-flight children are killed rather than
left running elevated for nobody. The timeout/cancellation policy lives in exactly
one place instead of being re-derived per handler.

**2. `parse` — the pure-function seam.** Each handler is split into "run the tool"
(impure, in `handlers/`) and "interpret its output" (pure, in `parse/`). The parsers
take a raw string and return structured data with no I/O, so the tricky logic —
locale-robust netstat rows, RFC-4180 CSV, Sysmon XML with markup inside values — is
tested against fixture strings rather than a live Windows box.

## The MCP output boundary

Every tool response is data sourced from the live OS — process names, command
lines, registry values — which is untrusted from an LLM's perspective (a process
name can be crafted to look like an instruction). `internal/tools` sanitises every
string leaving the boundary: strips control characters, normalises non-printable
Unicode, and caps field length. Forensic fields (command lines, hashes, Sysmon XML)
get a much larger cap so evidence is not truncated, and JSON HTML-escaping is
disabled so `<`, `>`, `&` render literally.

## Request lifecycle

1. A dedicated reader goroutine in `main.go` reads JSON-RPC frames from stdin and
   feeds them to the consumer loop, which dispatches each request in its own
   goroutine (bounded to 16 in flight). A long `run_full_hunt` therefore never
   blocks a quick `list_processes`; responses may complete out of order (JSON-RPC
   correlates by id) and every stdout write is serialised through one mutex so
   concurrent responses never interleave.
2. `initialize` is the exception: it is answered synchronously — its response is
   written before the next frame is consumed — so a pipelining client can never
   observe a `tools/*` reply arriving ahead of the handshake. It echoes the
   client's requested protocol version; `tools/list` returns the registry;
   `tools/call` routes to `tools.Call`.
3. `tools.Call` invokes the handler under the server's lifetime context, records
   an audit entry (secrets redacted; written in a defer so even a panicking call
   is recorded), sanitises the JSON result, and returns it. A handler panic is
   converted to a generic error at this boundary — full detail + stack go to
   stderr only, never the LLM context.
4. The handler runs its external tool via `run` (which threads that context into
   `exec.CommandContext`), hands the output to a `parse` function, maps the
   parsed rows onto its response type, and marshals JSON.
5. Shutdown: stdin EOF drains in-flight requests and exits. A FAILED stdout write
   (the client died) instead cancels the lifetime context — in-flight children
   are killed, no new requests are accepted, and the server exits even if the
   client still holds stdin open.

## Design principles

- **Read-only.** No tool mutates the system.
- **Graceful degradation.** Optional stages (Autoruns,
  Sysmon, VirusTotal, GeoIP) are unavailable, never fatal, when unconfigured.
  Native Stage-0 tools always work.
- **No secrets on the wire.** The VirusTotal key is never echoed in output, errors,
  or the audit log.
- **Bounded everything.** Timeouts AND lifetime-cancellation on external
  processes; a 16-request concurrency cap; response-size and rate limits on
  VirusTotal (with a TTL-evicted result cache); field-length caps on output.
