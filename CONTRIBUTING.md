# Contributing

Thanks for your interest in ProcessGuard. This is a security tool, so correctness
and clarity matter more than feature count.

## Development setup

- Go 1.25.11+ (the module pins this toolchain to stay clear of known stdlib
  advisories; `go` will fetch it automatically).
- Windows to exercise the handlers at runtime; the pure `internal/parse` tests run
  on any OS.

```
go build ./...
go test -race -cover ./...
make check            # gofmt + vet + test + govulncheck
```

## Ground rules

- **Put logic in `internal/parse`.** New output parsing belongs in a pure function
  with a table test, not inline in a handler. Handlers should stay thin: run a tool
  via `internal/run`, hand the output to a parser, map to the response type.
- **All shell-outs go through `internal/run`** so they inherit the timeout. Do not
  call `os/exec` directly from a handler.
- **Never interpolate untrusted input into a PowerShell `-Command` string.** Numeric
  inputs are range-checked; string inputs (e.g. `sysmon_log`) are whitelisted in
  `internal/config`. Preserve that discipline.
- **Keep the tool read-only.** No PR should add a tool that modifies the system.
- **Formatting + lint are CI gates:** `gofmt -l .` must be empty, and `go vet`,
  `govulncheck`, and `staticcheck` must pass.

## Pull requests

1. Branch from `main`.
2. Add or update tests for the behaviour you change.
3. Run `make check` locally.
4. Describe the security impact of the change, if any.

## Reporting security issues

Please do **not** open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md)
for the private disclosure process.
