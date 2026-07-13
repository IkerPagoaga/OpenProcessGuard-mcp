package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	"processguard-mcp/internal/audit"
	"processguard-mcp/internal/config"
	"processguard-mcp/internal/tools"
)

// Build metadata, injected at release time via -ldflags. Defaults identify a
// local/dev build so `serverInfo.version` is always meaningful.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// defaultProtocolVersion is used only when the client does not request one.
const defaultProtocolVersion = "2024-11-05"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	// Structured logs go to stderr; stdout is reserved for JSON-RPC framing.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	if cfg.AuditLog {
		if err := audit.Init(); err != nil {
			slog.Warn("audit log init failed; continuing without audit", "err", err)
		} else {
			defer audit.Close()
			slog.Info("audit log active")
		}
	}

	avail := cfg.Availability()
	slog.Info("ProcessGuard MCP ready",
		"version", Version, "commit", Commit, "built", BuildDate,
		"autoruns", avail.Autoruns,
		// "configured" only — whether the channel actually exists on this
		// machine is probed live per query (ErrSysmonChannelMissing).
		"sysmon_log_configured", avail.Sysmon,
		"virustotal", avail.VirusTotal,
		"geoip", avail.GeoIP,
	)

	if err := serve(cfg, os.Stdin, os.Stdout); err != nil {
		slog.Error("server terminated", "err", err)
		os.Exit(1)
	}
}

// maxConcurrentRequests caps in-flight tool executions. Requests are read serially
// (stdin is one stream) but dispatched concurrently, and each dispatch may shell out
// to netstat/PowerShell against the often-elevated host — this bound stops a
// misbehaving client from spawning unbounded goroutines and child processes.
const maxConcurrentRequests = 16

// serve runs the JSON-RPC loop over in/out. Requests are read one at a time (a
// dedicated reader goroutine feeds a channel) but dispatched CONCURRENTLY, so a
// long run_full_hunt no longer blocks a quick list_processes. Responses carry
// their own id and MCP does not require in-order replies, so out-of-order
// completion is fine; every stdout write goes through writeMu so concurrent
// responses never interleave. Deliberate exceptions to the concurrency:
//   - the initialize handshake is answered synchronously (strict ordering even
//     for a client that pipelines);
//   - a failed stdout write CANCELS the lifetime context — in-flight handlers'
//     child processes are killed via the runner, no new requests are accepted,
//     and serve returns even if stdin is still open (the reader goroutine may
//     stay parked in a blocking Read; the process exits right after).
func serve(cfg *config.Config, in io.Reader, out io.Writer) error {
	// ctx is the server's lifetime context, threaded through every dispatch down
	// to exec.CommandContext / the VT HTTP client. Cancelled on stdout death.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	encoder := json.NewEncoder(out)

	var (
		writeMu  sync.Mutex
		writeErr error // first stdout failure; guarded by writeMu
	)
	writeResp := func(resp Response) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if writeErr != nil {
			return // pipe already dead — draining, nothing left to write to
		}
		if err := encoder.Encode(resp); err != nil {
			// A stdio pipe write failure is permanent (the client is gone). Record
			// it and cancel the lifetime context: in-flight children are killed,
			// the consumer loop below stops, and serve returns.
			writeErr = err
			cancel()
			slog.Error("response write failed — cancelling in-flight work and shutting down", "err", err)
		}
	}
	respond := func(id interface{}, result interface{}, rpcErr *RPCError) {
		if rpcErr != nil {
			writeResp(Response{JSONRPC: "2.0", ID: id, Error: rpcErr})
		} else {
			writeResp(Response{JSONRPC: "2.0", ID: id, Result: result})
		}
	}
	// dispatchAndRespond runs one request and writes exactly one response, converting
	// any panic below the handler-level recover into a generic Internal-error reply
	// (full detail + stack to stderr only). Used by BOTH the synchronous initialize
	// path and the concurrent goroutine path, so neither can crash the server.
	dispatchAndRespond := func(req Request, id interface{}) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("dispatch panic", "method", req.Method, "err", r, "stack", string(debug.Stack()))
				writeResp(Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: -32603, Message: "Internal error"}})
			}
		}()
		result, rpcErr := dispatch(ctx, cfg, req)
		respond(id, result, rpcErr)
	}

	// Reader goroutine: owns the scanner, hands each frame to the consumer loop.
	// Decoupling the blocking Scan from the consumer is what lets serve return
	// when the pipe dies even though stdin never delivers another byte.
	lines := make(chan []byte)
	scanErrCh := make(chan error, 1)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
		for scanner.Scan() {
			// Tolerate a stray UTF-8 BOM on the first frame (some clients/proxies
			// prepend one); JSON-RPC itself is BOM-free UTF-8.
			line := bytes.TrimPrefix(scanner.Bytes(), []byte{0xEF, 0xBB, 0xBF})
			if len(line) == 0 {
				continue
			}
			// LOAD-BEARING copy: the scanner reuses its buffer on the next Scan,
			// which now happens concurrently with the consumer processing this
			// frame on the other side of the channel.
			buf := make([]byte, len(line))
			copy(buf, line)
			select {
			case lines <- buf:
			case <-ctx.Done():
				return // consumer is gone — stop reading
			}
		}
		scanErrCh <- scanner.Err() // buffered send completes before close(lines)
	}()

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRequests)

consume:
	for {
		var buf []byte
		select {
		case <-ctx.Done():
			break consume // stdout died — stop accepting work
		case b, ok := <-lines:
			if !ok {
				break consume // stdin EOF — normal shutdown
			}
			buf = b
		}

		var req Request
		if err := json.Unmarshal(buf, &req); err != nil {
			slog.Error("json-rpc parse error", "err", err)
			writeResp(Response{JSONRPC: "2.0", ID: nil, Error: &RPCError{Code: -32700, Message: "Parse error"}})
			continue
		}

		if strings.HasPrefix(req.Method, "notifications/") {
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}

		var id interface{}
		json.Unmarshal(req.ID, &id)

		// Answer the initialize handshake synchronously: its response is written
		// before the next frame is consumed, so a client that pipelines requests can
		// never observe a tools/* reply arriving ahead of the handshake. initialize
		// is instant and touches no shared state, so holding the loop costs nothing.
		if req.Method == "initialize" {
			dispatchAndRespond(req, id)
			continue
		}

		// Backpressure: block when maxConcurrent are in flight — but never past
		// shutdown (in-flight work is being cancelled, slots will free instantly).
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break consume
		}
		wg.Add(1)
		go func(req Request, id interface{}) {
			defer wg.Done()
			defer func() { <-sem }()
			dispatchAndRespond(req, id)
		}(req, id)
	}

	wg.Wait() // drain in-flight requests (cancelled ones finish near-instantly)

	// Surface BOTH failure channels — a read error must not mask a dead pipe.
	var errs []error
	select {
	case err := <-scanErrCh:
		if err != nil {
			errs = append(errs, err)
		}
	default:
		// Reader still parked in a blocking Read (dead pipe with stdin held open)
		// — there is no read error to report; the process exits right after.
	}
	writeMu.Lock()
	werr := writeErr
	writeMu.Unlock()
	if werr != nil {
		errs = append(errs, fmt.Errorf("stdout write failed: %w", werr))
	}
	return errors.Join(errs...)
}

func dispatch(ctx context.Context, cfg *config.Config, req Request) (interface{}, *RPCError) {
	switch req.Method {

	case "initialize":
		// Echo back the client's requested protocol version when it sends one,
		// rather than forcing a hardcoded value the client may not speak.
		protocolVersion := defaultProtocolVersion
		if len(req.Params) > 0 {
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if json.Unmarshal(req.Params, &p) == nil && p.ProtocolVersion != "" {
				protocolVersion = p.ProtocolVersion
			}
		}
		return map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":      "processguard-mcp",
				"version":   Version,
				"commit":    Commit,
				"buildDate": BuildDate,
			},
		}, nil

	case "tools/list":
		return map[string]interface{}{"tools": tools.Registry()}, nil

	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &RPCError{Code: -32602, Message: "Invalid params"}
		}
		// tools.Call converts handler panics to a generic error at the tool boundary
		// (full detail + stack to stderr only, audit entry still written). This outer
		// recover is the second line of defense — a panic in Call's own dispatch or
		// sanitisation machinery — with the same posture: detail to the operator's
		// log, a generic message to the model.
		var content string
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("tool dispatch panicked", "tool", p.Name, "panic", r, "stack", string(debug.Stack()))
					err = fmt.Errorf("tool %q failed with an internal error (details in the server log)", p.Name)
				}
			}()
			content, err = tools.Call(ctx, cfg, p.Name, p.Arguments)
		}()
		if err != nil {
			// MCP convention: a tool that RAN but failed returns a normal result
			// with isError=true and the message as content, so the model sees the
			// failure as tool output. Transport/protocol errors (invalid params,
			// unknown method) still use JSON-RPC error codes.
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": tools.SanitiseText(fmt.Sprintf("Tool error: %v", err))},
				},
				"isError": true,
			}, nil
		}
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": content},
			},
			"isError": false,
		}, nil

	case "ping":
		return map[string]interface{}{}, nil

	default:
		return nil, &RPCError{Code: -32601, Message: "Method not found: " + req.Method}
	}
}
