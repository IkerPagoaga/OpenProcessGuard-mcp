package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"processguard-mcp/internal/audit"
	"processguard-mcp/internal/config"
	"processguard-mcp/internal/procex"
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

	if err := procex.VerifyPath(cfg.ProcessExplorerPath); err != nil {
		slog.Warn("ProcessExplorer not configured — signing derived via Get-AuthenticodeSignature", "path", cfg.ProcessExplorerPath)
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
		"process_explorer", avail.ProcessExplorer,
		"autoruns", avail.Autoruns,
		"sysmon", avail.Sysmon,
		"virustotal", avail.VirusTotal,
		"geoip", avail.GeoIP,
	)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		// Tolerate a stray UTF-8 BOM on the first frame (some clients/proxies
		// prepend one); JSON-RPC itself is BOM-free UTF-8.
		line := bytes.TrimPrefix(scanner.Bytes(), []byte{0xEF, 0xBB, 0xBF})
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			slog.Error("json-rpc parse error", "err", err)
			writeError(encoder, nil, -32700, "Parse error")
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

		result, rpcErr := dispatch(cfg, req)
		if rpcErr != nil {
			encoder.Encode(Response{JSONRPC: "2.0", ID: id, Error: rpcErr})
		} else {
			encoder.Encode(Response{JSONRPC: "2.0", ID: id, Result: result})
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("stdin scanner error", "err", err)
		os.Exit(1)
	}
}

func dispatch(cfg *config.Config, req Request) (interface{}, *RPCError) {
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
				"name":    "processguard-mcp",
				"version": Version,
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
		content, err := tools.Call(cfg, p.Name, p.Arguments)
		if err != nil {
			return nil, &RPCError{Code: -32603, Message: fmt.Sprintf("Tool error: %v", err)}
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

func writeError(enc *json.Encoder, id interface{}, code int, msg string) {
	enc.Encode(Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg},
	})
}
