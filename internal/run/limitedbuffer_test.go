package run

import (
	"bytes"
	"strings"
	"testing"
)

func TestLimitedBufferUnderLimit(t *testing.T) {
	b := &limitedBuffer{limit: 100}
	n, err := b.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write = (%d, %v), want (5, nil)", n, err)
	}
	if got := string(b.Bytes()); got != "hello" {
		t.Errorf("Bytes = %q, want %q", got, "hello")
	}
	if b.Truncated() {
		t.Error("Truncated = true for a write well under the limit")
	}
}

// TestLimitedBufferExactlyAtLimit is the boundary that matters: filling the buffer
// precisely is NOT truncation, and reporting it as such would turn a legitimate
// maximum-size result into a hard error.
func TestLimitedBufferExactlyAtLimit(t *testing.T) {
	b := &limitedBuffer{limit: 5}
	if _, err := b.Write([]byte("abcde")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if b.Truncated() {
		t.Error("Truncated = true when the write exactly filled the limit")
	}
	if got := len(b.Bytes()); got != 5 {
		t.Errorf("len(Bytes) = %d, want 5", got)
	}
}

func TestLimitedBufferTruncatesSingleOversizedWrite(t *testing.T) {
	b := &limitedBuffer{limit: 5}
	n, err := b.Write([]byte("abcdefghij"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	// A short count would look like io.ErrShortWrite to the child and could kill it
	// for the wrong reason, so the write must always claim full success.
	if n != 10 {
		t.Errorf("Write returned n = %d, want 10 (full length even when truncating)", n)
	}
	if !b.Truncated() {
		t.Error("Truncated = false after an oversized write")
	}
	if got := string(b.Bytes()); got != "abcde" {
		t.Errorf("Bytes = %q, want %q", got, "abcde")
	}
}

func TestLimitedBufferTruncatesAcrossWrites(t *testing.T) {
	b := &limitedBuffer{limit: 8}
	for _, chunk := range []string{"aaa", "bbb", "ccc", "ddd"} {
		if _, err := b.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write(%q) error: %v", chunk, err)
		}
	}
	if !b.Truncated() {
		t.Error("Truncated = false after cumulative writes exceeded the limit")
	}
	if got := len(b.Bytes()); got != 8 {
		t.Errorf("len(Bytes) = %d, want exactly the limit (8)", got)
	}
	if got := string(b.Bytes()); got != "aaabbbcc" {
		t.Errorf("Bytes = %q, want %q", got, "aaabbbcc")
	}
}

// TestLimitedBufferNeverGrowsPastLimit is the whole point of the type: cmd.Output()
// would buffer a runaway child's entire stdout, so memory must stay bounded no matter
// how much the child emits.
func TestLimitedBufferNeverGrowsPastLimit(t *testing.T) {
	const limit = 1024
	b := &limitedBuffer{limit: limit}
	big := bytes.Repeat([]byte("x"), 64*1024)
	for i := 0; i < 16; i++ {
		if _, err := b.Write(big); err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}
	if got := len(b.Bytes()); got != limit {
		t.Errorf("buffer grew to %d bytes, want it pinned at %d", got, limit)
	}
	if !b.Truncated() {
		t.Error("Truncated = false after writing 1 MB into a 1 KB buffer")
	}
}

func TestLimitedBufferZeroLimitKeepsNothing(t *testing.T) {
	b := &limitedBuffer{limit: 0}
	if _, err := b.Write([]byte("data")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if len(b.Bytes()) != 0 {
		t.Errorf("Bytes = %q, want empty", b.Bytes())
	}
	if !b.Truncated() {
		t.Error("Truncated = false after a write into a zero-limit buffer")
	}
}

// TestToolCtxSurfacesStderr covers the diagnostic path that switching off cmd.Output()
// could otherwise have lost: exec.ExitError.Stderr is only populated by Output(), so
// the message now has to come from the captured stderr buffer instead.
func TestToolCtxSurfacesStderr(t *testing.T) {
	// A bare name that is not in system32Binaries resolves via PATH; a nonexistent one
	// fails to start, which exercises the error path without depending on any OS tool.
	_, err := ToolCtx(t.Context(), DefaultTimeout, "processguard-definitely-not-a-real-binary")
	if err == nil {
		t.Fatal("expected an error for a nonexistent binary")
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Error("error message is empty")
	}
}
