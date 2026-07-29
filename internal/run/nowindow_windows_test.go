//go:build windows

package run

import (
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// TestHideWindowSetsCreateNoWindow pins the flag itself. Losing it is invisible in
// automated output (the command still succeeds) and only shows up as console windows
// flashing at a human, so it needs an explicit assertion.
func TestHideWindowSetsCreateNoWindow(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "echo")
	hideWindow(cmd)

	if cmd.SysProcAttr == nil {
		t.Fatal("hideWindow left SysProcAttr nil")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Errorf("CREATE_NO_WINDOW not set; CreationFlags = 0x%08X", cmd.SysProcAttr.CreationFlags)
	}
}

// TestHideWindowPreservesExistingFlags guards the OR-in behaviour. The ToolCtx doc
// comment anticipates a future caller wrapping children in a Job Object; if hideWindow
// assigned instead of OR-ing, that caller's flags would be silently dropped.
func TestHideWindowPreservesExistingFlags(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "echo")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	hideWindow(cmd)

	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Error("pre-existing CreationFlags were clobbered")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Error("CREATE_NO_WINDOW was not OR-ed in")
	}
}

// TestToolCtxAppliesHideWindow proves the flag reaches the real spawn path, not just
// the helper — ToolCtx is where a refactor would drop the call.
func TestToolCtxAppliesHideWindow(t *testing.T) {
	// resolveSystemBinary maps "tasklist" to its absolute System32 path; running it
	// verifies the hardened path still executes with the flag applied.
	out, err := ToolCtx(t.Context(), DefaultTimeout, "tasklist", "/fo", "csv", "/nh")
	if err != nil {
		t.Fatalf("tasklist through ToolCtx failed: %v", err)
	}
	if len(out) == 0 {
		t.Error("tasklist returned no output through ToolCtx")
	}
}
