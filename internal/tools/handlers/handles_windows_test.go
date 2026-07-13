//go:build windows

package handlers

import (
	"os"
	"testing"
)

// TestProcessHandleCountSelf proves the GetProcessHandleCount wiring returns a
// real, non-zero figure for the current process. Guards the v2.4.0 fix for the
// dead open_handles field: gopsutil's NumFDs is unimplemented on Windows and
// always yielded 0, so a zero here means the field has regressed to fiction.
func TestProcessHandleCountSelf(t *testing.T) {
	n, err := processHandleCount(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("processHandleCount(self) error: %v", err)
	}
	if n <= 0 {
		t.Fatalf("processHandleCount(self) = %d, want > 0 (a live process always holds handles)", n)
	}
}

// TestProcessHandleCountInvalidPID proves a nonexistent PID reports an error
// rather than a fake zero — the omitempty contract depends on the error path.
func TestProcessHandleCountInvalidPID(t *testing.T) {
	if n, err := processHandleCount(int32(-1)); err == nil {
		t.Fatalf("processHandleCount(-1) = %d, want error", n)
	}
}
