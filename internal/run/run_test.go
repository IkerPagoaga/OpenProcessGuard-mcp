package run

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestResolveSystemBinary locks the PATH-hijack hardening: a bare system-tool
// name is rewritten to an absolute System32 path, while an explicit path (an
// operator-configured tool such as autorunsc.exe) or an unknown bare name is
// passed through unchanged.
func TestResolveSystemBinary(t *testing.T) {
	cases := []struct {
		name       string
		wantChange bool // resolved should differ from input
		wantSubstr string
	}{
		{"netstat", true, "netstat.exe"},
		{"reg", true, "reg.exe"},
		{"tasklist", true, "tasklist.exe"},
		{"powershell", true, "powershell.exe"},
		{"POWERSHELL", true, "powershell.exe"},                  // case-insensitive
		{`C:\Tools\SysinternalsSuite\autorunsc.exe`, false, ""}, // explicit path — unchanged
		{"autorunsc.exe", false, ""},                            // unknown bare name — unchanged
		{"whoami", false, ""},                                   // not in the resolve set
	}
	for _, c := range cases {
		got := resolveSystemBinary(c.name)
		if !c.wantChange {
			if got != c.name {
				t.Errorf("resolveSystemBinary(%q) = %q, want unchanged", c.name, got)
			}
			continue
		}
		if got == c.name {
			t.Errorf("resolveSystemBinary(%q) was not rewritten to an absolute path", c.name)
		}
		lower := strings.ToLower(got)
		if !strings.Contains(lower, c.wantSubstr) {
			t.Errorf("resolveSystemBinary(%q) = %q, want it to contain %q", c.name, got, c.wantSubstr)
		}
		if !strings.Contains(lower, "system32") {
			t.Errorf("resolveSystemBinary(%q) = %q, want it under System32", c.name, got)
		}
	}
}

// TestToolCtxTimeout proves the DoS guarantee: a child that outlives the deadline
// is killed and reported as a typed timeout error, never left to hang.
func TestToolCtxTimeout(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("timeout test shells out to powershell; Windows-only")
	}
	start := time.Now()
	_, err := ToolCtx(context.Background(), 100*time.Millisecond, "powershell",
		"-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 5")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error should report a timeout, got: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("command was not killed at the deadline (took %s)", elapsed)
	}
}

// TestToolCtxCancelKillsChild proves the shutdown guarantee behind the dead-pipe
// path: cancelling the PARENT context (the serve-level lifetime context) kills the
// child process immediately — a host death mid-hunt stops the elevated children
// instead of letting them run to their own timeouts for nobody.
func TestToolCtxCancelKillsChild(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cancel test shells out to powershell; Windows-only")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := ToolCtx(ctx, 30*time.Second, "powershell",
		"-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 25")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a cancellation error, got nil")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error should report the cancellation, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("child was not killed on cancel (took %s; its own budget was 30s)", elapsed)
	}
}
