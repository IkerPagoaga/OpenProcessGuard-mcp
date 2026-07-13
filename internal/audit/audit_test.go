package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestConcurrentLogIntegrity is the audit trail's concurrency guarantee: many
// goroutines logging at once (as the concurrent dispatch loop now does) must produce
// an intact JSONL file — every line valid JSON, no interleaved/torn writes, one line
// per call. It also overlaps Log with Close to prove the guarded fast-path cannot
// race a teardown (run under -race in CI). Uses a temp APPDATA so no real state is
// touched.
func TestConcurrentLogIntegrity(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	const writers = 16
	const perWriter = 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				var callErr error
				if i%5 == 0 {
					callErr = errors.New("synthetic failure")
				}
				Log("stress_tool", map[string]any{"writer": w, "i": i}, 3*time.Millisecond, callErr)
			}
		}(w)
	}
	wg.Wait()

	// Log after Close must be a safe no-op (the guarded fast path), and a straggler
	// racing Close must not tear the file or crash — exercise the overlap.
	var closers sync.WaitGroup
	closers.Add(2)
	go func() { defer closers.Done(); Log("late_tool", nil, time.Millisecond, nil) }()
	go func() { defer closers.Done(); Close() }()
	closers.Wait()
	Log("post_close", nil, time.Millisecond, nil) // must not panic or write

	logPath := filepath.Join(os.Getenv("APPDATA"), "ProcessGuard", "audit.log")
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()

	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines++
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not valid JSON (torn/interleaved write): %q", lines, sc.Text())
		}
		if e.Tool == "" || e.Timestamp == "" {
			t.Errorf("line %d missing fields: %+v", lines, e)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// All pre-Close writes must be present; the Close-racing straggler may or may
	// not have landed (both orders are legal); the post-Close write must NOT be.
	wantMin, wantMax := writers*perWriter, writers*perWriter+1
	if lines < wantMin || lines > wantMax {
		t.Errorf("audit log has %d lines, want %d–%d (no lost or post-Close writes)", lines, wantMin, wantMax)
	}
}
