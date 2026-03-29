package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is a single audit log record written as a JSONL line.
type Entry struct {
	Timestamp string `json:"ts"`
	Tool      string `json:"tool"`
	// Args contains safe, non-sensitive metadata about the call (e.g. {"pid": 1234}).
	// Sensitive values (API keys, env vars) are NEVER written here.
	Args   map[string]any `json:"args,omitempty"`
	DuraMs int64          `json:"dur_ms"`
	Error  string         `json:"error,omitempty"`
}

var (
	mu      sync.Mutex
	logFile *os.File
	enabled bool
)

// Init opens (or creates) the audit log file.
// Path: %APPDATA%\ProcessGuard\audit.log
// Call once at startup when cfg.AuditLog == true.
func Init() error {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	dir := filepath.Join(appData, "ProcessGuard")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("audit: failed to create log dir: %w", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("audit: failed to open log file: %w", err)
	}
	logFile = f
	enabled = true
	return nil
}

// Log writes a single audit entry. Safe to call concurrently.
// If audit is not enabled or write fails, the error is silently discarded
// (audit failures must never break the MCP server).
func Log(tool string, args map[string]any, dur time.Duration, callErr error) {
	if !enabled || logFile == nil {
		return
	}
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tool:      tool,
		Args:      args,
		DuraMs:    dur.Milliseconds(),
	}
	if callErr != nil {
		entry.Error = callErr.Error()
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	logFile.Write(append(data, '\n'))
}

// Close flushes and closes the audit log. Call on graceful shutdown.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		logFile.Sync()
		logFile.Close()
		logFile = nil
	}
}
