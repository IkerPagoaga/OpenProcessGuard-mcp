package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestInitializeServerInfo verifies the initialize handshake surfaces the build
// provenance (commit + buildDate), not just the version, via the real dispatch path.
func TestInitializeServerInfo(t *testing.T) {
	result, rpcErr := dispatch(context.Background(), nil, Request{Method: "initialize"})
	if rpcErr != nil {
		t.Fatalf("initialize returned RPC error: %+v", rpcErr)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("initialize result is %T, want map", result)
	}
	si, ok := m["serverInfo"].(map[string]string)
	if !ok {
		t.Fatalf("serverInfo is %T, want map[string]string", m["serverInfo"])
	}
	for _, k := range []string{"name", "version", "commit", "buildDate"} {
		if _, present := si[k]; !present {
			t.Errorf("serverInfo missing %q", k)
		}
	}
	if si["commit"] != Commit {
		t.Errorf("serverInfo.commit = %q, want %q", si["commit"], Commit)
	}
	if si["buildDate"] != BuildDate {
		t.Errorf("serverInfo.buildDate = %q, want %q", si["buildDate"], BuildDate)
	}
}

// TestServeConcurrentDispatch feeds serve a burst of requests and confirms every one
// is answered exactly once (ids returned, order-independent) and that a notification
// (no id) is not. Under `go test -race` it proves serve's write mutex serialises the
// concurrent goroutines' stdout writes — a missing mutex races the shared bytes.Buffer.
//
// SCOPE (honest): ping/initialize are near-instant and cfg-free, so this stresses
// serve's OWN wiring — write-mutex, drain-on-exit, id plumbing, notification-skip —
// not handler-vs-handler contention. Real shared-handler-state race coverage comes
// from the two-lens shared-state review + -race CI across the full suite. Keep this
// test non-parallel so its serve run stays deterministic.
func TestServeConcurrentDispatch(t *testing.T) {
	const n = 24
	var sb strings.Builder
	for i := 1; i <= n; i++ {
		method := "ping"
		if i%3 == 0 {
			method = "initialize"
		}
		fmt.Fprintf(&sb, `{"jsonrpc":"2.0","id":%d,"method":%q}`+"\n", i, method)
	}
	sb.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n") // no id → no response

	var out bytes.Buffer
	if err := serve(nil, strings.NewReader(sb.String()), &out); err != nil {
		t.Fatalf("serve returned error: %v", err)
	}

	seen := map[float64]bool{}
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r map[string]interface{}
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decoding responses: %v", err)
		}
		if id, ok := r["id"].(float64); ok {
			seen[id] = true
		}
	}
	for i := 1; i <= n; i++ {
		if !seen[float64(i)] {
			t.Errorf("no response for request id %d", i)
		}
	}
	if len(seen) != n {
		t.Errorf("got %d responses, want %d (the notification must not be answered)", len(seen), n)
	}
}

// failingWriter fails every write — a stand-in for a client that closed the pipe.
type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errors.New("pipe closed") }

// TestServeStopsOnDeadPipe locks the dead-client behavior: when stdout writes fail,
// serve must stop reading further requests, cancel/drain what is in flight, and
// surface the write error — never keep silently dispatching work nobody can receive.
func TestServeStopsOnDeadPipe(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 50; i++ {
		fmt.Fprintf(&sb, `{"jsonrpc":"2.0","id":%d,"method":"ping"}`+"\n", i)
	}
	err := serve(nil, strings.NewReader(sb.String()), failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "stdout write failed") {
		t.Fatalf("serve = %v, want a surfaced stdout-write failure", err)
	}
}

// stallingReader yields its data once, then blocks forever — a host that half-closed:
// our stdout read end is gone (writes fail) but it holds stdin open without sending.
type stallingReader struct {
	data []byte
	sent bool
}

func (r *stallingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.data), nil
	}
	select {} // block forever — the host never sends another byte
}

// TestServeUnblocksOnDeadPipeWithOpenStdin locks the half-close fix: with stdin held
// open and silent, a dead stdout must still terminate serve (previously the loop was
// parked inside Scan() and the elevated server stayed resident indefinitely). The
// reader goroutine stays blocked by design; serve must return without its help.
func TestServeUnblocksOnDeadPipeWithOpenStdin(t *testing.T) {
	in := &stallingReader{data: []byte(
		`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n")}

	done := make(chan error, 1)
	go func() { done <- serve(nil, in, failingWriter{}) }()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "stdout write failed") {
			t.Fatalf("serve = %v, want a surfaced stdout-write failure", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not return within 15s — half-closed host still parks the server")
	}
}

// TestInitializeOrdering locks the synchronous handshake: with pipelined input the
// FIRST response on the wire must be the initialize reply — no tools/* or ping reply
// may beat it, even though everything after the handshake is dispatched concurrently.
func TestInitializeOrdering(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")
	for i := 2; i <= 12; i++ {
		fmt.Fprintf(&sb, `{"jsonrpc":"2.0","id":%d,"method":"ping"}`+"\n", i)
	}

	var out bytes.Buffer
	if err := serve(nil, strings.NewReader(sb.String()), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	dec := json.NewDecoder(&out)
	var first map[string]interface{}
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if id, _ := first["id"].(float64); id != 1 {
		t.Errorf("first response id = %v, want 1 (initialize must be answered before any later request)", first["id"])
	}
	if _, hasResult := first["result"]; !hasResult {
		t.Errorf("initialize response missing result: %v", first)
	}
}
