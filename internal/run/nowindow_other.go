//go:build !windows

package run

import "os/exec"

// hideWindow is a no-op off Windows: there is no console-window allocation to
// suppress. It exists so ToolCtx stays platform-neutral, which keeps this package
// compiling on Linux — where CI runs go vet, staticcheck, go test -race and
// govulncheck against the host build.
func hideWindow(_ *exec.Cmd) {}
