// Package run centralises external-process execution for ProcessGuard.
//
// Every shell-out (netstat, tasklist, reg, powershell, autorunsc, …) goes
// through this package so that a single, uniform timeout is enforced. Without a
// bounded context a hung child process would block the MCP server indefinitely
// and starve every client — so Tool always runs under a deadline.
package run

import (
	"context"
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
// run.Tool / run.PowerShell call sites), so a new system tool must be added here
// deliberately to preserve this guarantee.
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

// Tool runs an external command under DefaultTimeout and returns its stdout.
// A deadline overrun is reported as a clear, typed error rather than a hang.
func Tool(name string, args ...string) ([]byte, error) {
	return ToolCtx(context.Background(), DefaultTimeout, name, args...)
}

// ToolCtx runs an external command under an explicit parent context + timeout.
func ToolCtx(parent context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolveSystemBinary(name), args...)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

// PowerShell runs a -Command script with the standard non-interactive flags.
// -NonInteractive guarantees the child never blocks waiting on stdin.
func PowerShell(script string) ([]byte, error) {
	return PowerShellCtx(context.Background(), DefaultTimeout, script)
}

// PowerShellCtx is PowerShell with an explicit context + timeout.
func PowerShellCtx(parent context.Context, timeout time.Duration, script string) ([]byte, error) {
	return ToolCtx(parent, timeout, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

// TrimmedString runs Tool and returns stdout as a trimmed string.
func TrimmedString(name string, args ...string) (string, error) {
	out, err := Tool(name, args...)
	return strings.TrimSpace(string(out)), err
}
