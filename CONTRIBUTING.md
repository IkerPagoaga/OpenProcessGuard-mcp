# Contributing

Thanks for your interest in ProcessGuard. This is a security tool, so correctness
and clarity matter more than feature count.

## Development setup

- Go 1.25.12+ (the module pins this toolchain to stay clear of known stdlib
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
- **All shell-outs go through `internal/run`** (`ToolCtx` / `PowerShellCtx`) so they
  inherit both the timeout and the server's lifetime-cancellation context — pass the
  request `ctx` through, never `context.Background()`. Do not call `os/exec` directly
  from a handler. One invariant to preserve: on Windows, cancellation kills only the
  DIRECT child, so a PowerShell `-Command` script must not spawn its own child
  processes (see the `run.ToolCtx` doc comment).
- **Never interpolate untrusted input into a PowerShell `-Command` string.** Numeric
  inputs are range-checked; string inputs (e.g. `sysmon_log`) are whitelisted in
  `internal/config`. Preserve that discipline.
- **Keep the tool read-only.** No PR should add a tool that modifies the system.
- **Formatting + lint are CI gates:** `gofmt -l .` must be empty, and `go vet`,
  `govulncheck`, and `staticcheck` must pass.

## Pull requests

External contributors: **fork** the repository, branch from `main`, and open a PR
from your fork. Direct pushes to `main` are disabled for everyone.

1. Add or update tests for the behaviour you change.
2. Run `make check` locally (gofmt + vet + test + govulncheck).
3. Describe the security impact of the change, if any.

## How contributions land (branch protection)

`main` is a protected branch. Every change — including the maintainer's — arrives
through a pull request; nothing is pushed directly.

- **PRs only.** No direct pushes to `main`; force-pushes and branch deletion are blocked.
- **CI must pass.** The `build-test` check (gofmt, `go vet`, race tests, `govulncheck`,
  `staticcheck`) is a required status check — a red build cannot merge.
- **Maintainer review is required.** [@IkerPagoaga](https://github.com/IkerPagoaga) is the
  sole code owner ([`.github/CODEOWNERS`](.github/CODEOWNERS)); every PR needs their
  approval before it can merge, and only the maintainer merges.
- **Supply-chain guardrails.** Third-party GitHub Actions are pinned to full commit SHAs
  (not moving tags), SHA-pinning is enforced repo-wide, and Dependabot proposes updates.
  Secret-scanning push protection blocks commits that contain credentials. Releases are
  built by the tagged pipeline and signed with cosign (keyless / Sigstore) — see the
  README's "Verifying a release" section.

Because a fork PR runs CI with a read-only token and no access to repository secrets,
an untrusted contribution cannot exfiltrate anything or publish a release.

## Reporting security issues

Please do **not** open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md)
for the private disclosure process.
