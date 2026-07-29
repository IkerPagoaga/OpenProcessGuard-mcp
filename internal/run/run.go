// Package run centralises external-process execution for ProcessGuard.
//
// Every shell-out (netstat, tasklist, reg, powershell, autorunsc, …) goes
// through this package so that a single, uniform timeout is enforced. Without a
// bounded context a hung child process would block the MCP server indefinitely
// and starve every client — so Tool always runs under a deadline.
package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds any single external command. Windows forensic helpers
// (autorunsc, Get-WinEvent, Get-AuthenticodeSignature over many paths) can be
// slow, so this is generous — but it is never unbounded.
const DefaultTimeout = 45 * time.Second

// Output bounds. MaxOutputBytes is a memory backstop, not a working limit: it sits far
// above any legitimate result (a full `autorunsc -a *` CSV is a few MB), so hitting it
// means a child is misbehaving. maxStderrBytes only needs to hold a diagnostic message.
const (
	MaxOutputBytes = 16 * 1024 * 1024
	maxStderrBytes = 64 * 1024
)

// ErrOutputTruncated reports that a child exceeded MaxOutputBytes and its output was
// cut. Callers must not parse the result: a clipped CSV or JSON document parses into a
// plausible but INCOMPLETE forensic answer, which is worse than a visible failure.
var ErrOutputTruncated = errors.New("child process output exceeded the size limit")

// limitedBuffer accumulates at most limit bytes and discards the rest, recording that
// it did so. Writes always report full success: returning a short count would surface
// to the child as a broken pipe and could kill it for the wrong reason, muddling the
// diagnosis.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte   { return b.buf.Bytes() }
func (b *limitedBuffer) Truncated() bool { return b.truncated }

// system32Dir resolves the absolute System32 directory ONCE. It prefers the
// canonical, non-environment location so that an attacker who can influence the
// elevated server's %SystemRoot% cannot redirect a system-tool exec; only a
// non-standard (non-C:) Windows install falls back to the environment.
var system32Dir = sync.OnceValue(func() string {
	const canonical = `C:\Windows\System32`
	if st, err := os.Stat(canonical); err == nil && st.IsDir() {
		return canonical
	}
	if r := os.Getenv("SystemRoot"); r != "" {
		return filepath.Join(r, "System32")
	}
	return canonical
})

// system32Binaries are the bare Windows tool names ProcessGuard shells out to.
// They are rewritten to their absolute System32 path before exec so a PATH-order
// hijack (a same-named binary in a writable directory earlier on PATH) cannot
// substitute for the genuine system tool. Go >=1.19 refuses only the implicit
// current-directory lookup — PATH-order resolution against any writable PATH
// entry still applies — so pinning the absolute path is what actually closes the
// hijack and makes the elevated server's execution surface explicit.
var system32Binaries = map[string]bool{
	"netstat":  true,
	"reg":      true,
	"tasklist": true,
}

// resolveSystemBinary maps a bare system-tool name to its absolute path. A name
// that already contains a path separator (an operator-configured tool path such
// as autorunsc.exe) is returned unchanged, as is any bare name not in the known
// set. NOTE: an unmapped bare name still resolves via PATH at exec time; every
// current caller passes either a mapped name or an absolute path (see the
// run.ToolCtx / run.PowerShellCtx call sites), so a new system tool must be
// added here deliberately to preserve this guarantee.
func resolveSystemBinary(name string) string {
	if strings.ContainsAny(name, `\/:`) {
		return name // already an explicit path
	}
	switch lower := strings.ToLower(strings.TrimSuffix(name, ".exe")); {
	case lower == "powershell":
		return filepath.Join(system32Dir(), "WindowsPowerShell", "v1.0", "powershell.exe")
	case system32Binaries[lower]:
		return filepath.Join(system32Dir(), lower+".exe")
	default:
		return name
	}
}

// ToolCtx runs an external command under an explicit parent context + timeout.
// Every call site passes the server's request context, so cancelling it (the
// client pipe died) KILLS the child process via exec.CommandContext instead of
// letting it run to its own deadline for nobody. A deadline overrun is reported
// as a clear, typed error; a parent cancellation as a typed cancellation.
//
// INVARIANT: on Windows exec.CommandContext kills only the DIRECT child, not a
// process tree. That is sufficient here because every command run through this
// package is a leaf (netstat/reg/tasklist/autorunsc) or a `powershell -Command`
// running an INLINE script that spawns no grandchildren. Any future handler that
// runs a script which itself launches child processes must instead wrap the child
// in a Windows Job Object (KILL_ON_JOB_CLOSE), or those grandchildren would orphan
// on cancel/timeout.
func ToolCtx(parent context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolveSystemBinary(name), args...)
	// Suppress the console window Windows would allocate for this child; the MCP
	// host is a GUI process, so without this every shell-out flashes a black window.
	// No-op off Windows (see nowindow_other.go).
	hideWindow(cmd)

	// Bounded buffers instead of cmd.Output(): Output() accumulates a child's ENTIRE
	// stdout in memory, so one runaway producer (a wide autorunsc scan, an unfiltered
	// Get-WinEvent) could exhaust the server's memory before any timeout fired.
	stdout := &limitedBuffer{limit: MaxOutputBytes}
	stderr := &limitedBuffer{limit: maxStderrBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	out := stdout.Bytes()

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	case parent.Err() != nil:
		return out, fmt.Errorf("%s cancelled: %w", name, parent.Err())
	}

	// Truncation is a hard error, not a warning. Handing a half-read CSV or a clipped
	// JSON document to a parser yields a plausible-looking PARTIAL forensic result,
	// which is more dangerous than an explicit failure: findings would silently be
	// missing. The limit is far above any legitimate output, so reaching it means
	// something is genuinely wrong.
	if stdout.Truncated() {
		return out, fmt.Errorf("%s produced more than %d bytes on stdout; refusing to parse a truncated result: %w",
			name, MaxOutputBytes, ErrOutputTruncated)
	}

	if err != nil {
		if msg := strings.TrimSpace(string(stderr.Bytes())); msg != "" {
			return out, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return out, err
	}
	return out, nil
}

// PowerShellCtx runs a -Command script with the standard non-interactive flags
// under an explicit context + timeout. -NonInteractive guarantees the child
// never blocks waiting on stdin.
func PowerShellCtx(parent context.Context, timeout time.Duration, script string) ([]byte, error) {
	return ToolCtx(parent, timeout, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}
