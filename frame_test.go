package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// oversizedPayload builds a single frame guaranteed to exceed maxFrameBytes.
func oversizedPayload() string {
	return `{"jsonrpc":"2.0","id":2,"method":"ping","params":{"pad":"` +
		strings.Repeat("A", maxFrameBytes) + `"}}`
}

func TestReadFrameReadsSuccessiveFrames(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("alpha\nbravo\ncharlie\n"), initialFrameBuf)
	for _, want := range []string{"alpha\n", "bravo\n", "charlie\n"} {
		got, err := readFrame(r)
		if err != nil {
			t.Fatalf("readFrame(%q) error: %v", want, err)
		}
		if string(got) != want {
			t.Errorf("readFrame = %q, want %q", got, want)
		}
	}
	if _, err := readFrame(r); !errors.Is(err, io.EOF) {
		t.Errorf("after last frame err = %v, want io.EOF", err)
	}
}

// TestReadFrameOversizeThenResync is THE regression test for this fix. Before it, an
// oversized frame permanently killed the reader (bufio.Scanner returns ErrTooLong and
// never scans again), which took the whole process down and silently dropped every
// later request from a live client. The load-bearing assertion is the SECOND read.
func TestReadFrameOversizeThenResync(t *testing.T) {
	stream := oversizedPayload() + "\n" + `{"jsonrpc":"2.0","id":3,"method":"ping"}` + "\n"
	r := bufio.NewReaderSize(strings.NewReader(stream), initialFrameBuf)

	if _, err := readFrame(r); !errors.Is(err, errFrameTooLong) {
		t.Fatalf("oversized frame err = %v, want errFrameTooLong", err)
	}

	got, err := readFrame(r)
	if err != nil {
		t.Fatalf("frame after oversized one failed to read: %v", err)
	}
	if !strings.Contains(string(got), `"id":3`) {
		t.Errorf("did not resync onto the next frame; got %q", got)
	}
}

func TestReadFrameFinalFrameWithoutTrailingNewline(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("only-frame"), initialFrameBuf)
	got, err := readFrame(r)
	if err != nil {
		t.Fatalf("unterminated final frame error: %v", err)
	}
	if string(got) != "only-frame" {
		t.Errorf("readFrame = %q, want %q", got, "only-frame")
	}
	if _, err := readFrame(r); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

// TestReadFrameResultIsIndependentOfReaderBuffer pins the invariant the consumer relies
// on: the returned slice is handed across a channel and read while the reader goroutine
// is already refilling its buffer, so it must not alias that buffer.
func TestReadFrameResultIsIndependentOfReaderBuffer(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("first\nsecond\n"), initialFrameBuf)
	first, err := readFrame(r)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := readFrame(r); err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first) != "first\n" {
		t.Errorf("first frame mutated by the subsequent read: %q", first)
	}
}

// TestServeResyncsAfterOversizedFrame drives the real serve loop end-to-end: an
// oversized frame must be answered with -32700 and the stream must stay usable.
func TestServeResyncsAfterOversizedFrame(t *testing.T) {
	var in bytes.Buffer
	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	in.WriteString(oversizedPayload() + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":3,"method":"ping"}` + "\n")

	var out bytes.Buffer
	if err := serve(nil, &in, &out); err != nil {
		t.Fatalf("serve returned error: %v", err)
	}

	type resp struct {
		ID    interface{} `json:"id"`
		Error *RPCError   `json:"error"`
	}
	var (
		sawParseError bool
		answered      = map[float64]bool{}
	)
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r resp
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("undecodable response %q: %v", line, err)
		}
		if r.Error != nil {
			if r.Error.Code != -32700 {
				t.Errorf("error code = %d, want -32700", r.Error.Code)
			}
			if r.ID != nil {
				t.Errorf("parse-error id = %v, want null", r.ID)
			}
			sawParseError = true
			continue
		}
		if id, ok := r.ID.(float64); ok {
			answered[id] = true
		}
	}

	if !sawParseError {
		t.Error("oversized frame produced no -32700 response")
	}
	if !answered[1] {
		t.Error("request before the oversized frame was not answered")
	}
	// The whole point: the server survived and kept serving.
	if !answered[3] {
		t.Error("request AFTER the oversized frame was not answered — serve did not resync")
	}
}
