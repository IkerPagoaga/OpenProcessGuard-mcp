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
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds any single external command. Windows forensic helpers
// (autorunsc, Get-WinEvent, Get-AuthenticodeSignature over many paths) can be
// slow, so this is generous — but it is never unbounded.
const DefaultTimeout = 45 * time.Second

// Tool runs an external command under DefaultTimeout and returns its stdout.
// A deadline overrun is reported as a clear, typed error rather than a hang.
func Tool(name string, args ...string) ([]byte, error) {
	return ToolCtx(context.Background(), DefaultTimeout, name, args...)
}

// ToolCtx runs an external command under an explicit parent context + timeout.
func ToolCtx(parent context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
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
