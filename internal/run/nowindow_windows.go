//go:build windows

package run

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// hideWindow suppresses the console window Windows allocates for a console-subsystem
// child process.
//
// ProcessGuard's host is a GUI application (Claude Desktop is Electron) launched with
// pipes and no attached console. Without CREATE_NO_WINDOW, Windows gives every
// console-subsystem child its own new console — so each shell-out flashes a black
// window at the user. That is not cosmetic at this call volume: a single
// run_full_hunt spawns up to five children (autorunsc, PowerShell signing, netstat,
// two Sysmon queries) and get_startup_entries alone spawns nine (eight `reg query`
// plus one PowerShell), producing a visible cascade on routine use.
//
// The flag is OR-ed into any existing CreationFlags rather than assigned, so a future
// caller that sets its own flags (e.g. a Job Object wrapper, per the ToolCtx
// grandchild invariant) does not silently lose them.
func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW
}
