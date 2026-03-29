package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"processguard-mcp/internal/config"
)

// VTReport holds the VirusTotal analysis result for a single file hash.
type VTReport struct {
	Hash        string `json:"hash"`
	Malicious   int    `json:"malicious"`
	Suspicious  int    `json:"suspicious"`
	Undetected  int    `json:"undetected"`
	TotalEngines int   `json:"total_engines"`
	Score       string `json:"score"`      // "5/72" human-readable
	Permalink   string `json:"permalink"`
	Error       string `json:"error,omitempty"`
}

// vtCache is an in-memory cache keyed by SHA256 hash.
// Entries expire after 24 hours to stay within VT free-tier limits.
type vtCacheEntry struct {
	report    VTReport
	cachedAt  time.Time
}

var (
	vtCacheMu sync.Mutex
	vtCache   = map[string]vtCacheEntry{}
)

const vtCacheTTL = 24 * time.Hour

// rateLimiter provides a simple token bucket at 4 requests per 60 seconds
// to stay within the VirusTotal free tier (4 req/min).
var vtRateLimiter = newTokenBucket(4, 60*time.Second)

// LookupHash queries VirusTotal for a SHA256 hash.
// Returns a cached result if available and fresh.
// NEVER exposes the API key in the returned data.
func LookupHash(cfg *config.Config, sha256 string) (string, error) {
	if cfg.VTAPIKey == "" {
		return "", fmt.Errorf("vt_api_key not configured — add your free VirusTotal API key to config.json")
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if len(sha256) != 64 {
		return "", fmt.Errorf("invalid SHA256 hash (expected 64 hex chars, got %d)", len(sha256))
	}

	// Check cache
	vtCacheMu.Lock()
	if entry, ok := vtCache[sha256]; ok && time.Since(entry.cachedAt) < vtCacheTTL {
		vtCacheMu.Unlock()
		result, err := json.MarshalIndent(entry.report, "", "  ")
		return string(result), err
	}
	vtCacheMu.Unlock()

	// Rate limit
	if !vtRateLimiter.Allow() {
		return "", fmt.Errorf("VirusTotal rate limit reached (4 req/min on free tier) — retry in a moment")
	}

	report, err := fetchVTReport(cfg.VTAPIKey, sha256)
	if err != nil {
		return "", err
	}

	// Store in cache
	vtCacheMu.Lock()
	vtCache[sha256] = vtCacheEntry{report: report, cachedAt: time.Now()}
	vtCacheMu.Unlock()

	result, err := json.MarshalIndent(report, "", "  ")
	return string(result), err
}

// fetchVTReport makes the actual VirusTotal API v3 call.
func fetchVTReport(apiKey, sha256 string) (VTReport, error) {
	report := VTReport{Hash: sha256}

	url := "https://www.virustotal.com/api/v3/files/" + sha256
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return report, fmt.Errorf("VT request build failed: %w", err)
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return report, fmt.Errorf("VT request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return report, fmt.Errorf("VT response read failed: %w", err)
	}

	if resp.StatusCode == 404 {
		report.Score = "not found"
		return report, nil
	}
	if resp.StatusCode != 200 {
		return report, fmt.Errorf("VT API returned HTTP %d", resp.StatusCode)
	}

	// Parse the VT API v3 response structure
	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
			Links struct {
				Self string `json:"self"`
			} `json:"links"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return report, fmt.Errorf("VT response parse failed: %w", err)
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	report.Malicious = stats.Malicious
	report.Suspicious = stats.Suspicious
	report.Undetected = stats.Undetected
	report.TotalEngines = stats.Malicious + stats.Suspicious + stats.Undetected
	report.Score = fmt.Sprintf("%d/%d", stats.Malicious, report.TotalEngines)
	report.Permalink = vtResp.Data.Links.Self

	return report, nil
}

// ── Token bucket rate limiter ─────────────────────────────────────────────

type tokenBucket struct {
	mu       sync.Mutex
	tokens   int
	capacity int
	lastFill time.Time
	fillEvery time.Duration
}

func newTokenBucket(capacity int, per time.Duration) *tokenBucket {
	return &tokenBucket{
		tokens:    capacity,
		capacity:  capacity,
		lastFill:  time.Now(),
		fillEvery: per,
	}
}

func (tb *tokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastFill)
	if elapsed >= tb.fillEvery {
		tb.tokens = tb.capacity
		tb.lastFill = now
	}

	if tb.tokens <= 0 {
		return false
	}
	tb.tokens--
	return true
}
