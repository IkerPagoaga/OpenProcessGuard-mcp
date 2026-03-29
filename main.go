package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"processguard-mcp/internal/config"
	"processguard-mcp/internal/procex"
	"processguard-mcp/internal/tools"
)

// rawMessage lets us detect missing vs null fields
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // may be number, string, or absent (notification)
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
	log.SetOutput(os.Stderr)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := procex.VerifyPath(cfg.ProcessExplorerPath); err != nil {
		log.Fatalf("ProcessExplorer not found at %q: %v", cfg.ProcessExplorerPath, err)
	}

	log.Printf("ProcessGuard MCP ready | procexp: %s", cfg.ProcessExplorerPath)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("parse error: %v | raw: %s", err, string(line))
			writeError(encoder, nil, -32700, "Parse error")
			continue
		}

		// Notifications: method starts with "notifications/" — no response sent
		if strings.HasPrefix(req.Method, "notifications/") {
			log.Printf("notification received: %s (ignored)", req.Method)
			continue
		}

		// Requests with no id are also notifications — skip
		if len(req.ID) == 0 || string(req.ID) == "null" {
			if req.Method != "" {
				log.Printf("null-id message: %s (ignored)", req.Method)
			}
			continue
		}

		// Parse id as raw value (could be number or string)
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
		log.Fatalf("stdin scanner error: %v", err)
	}
}

func dispatch(cfg *config.Config, req Request) (interface{}, *RPCError) {
	switch req.Method {

	case "initialize":
		return map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":    "processguard-mcp",
				"version": "1.0.0",
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
