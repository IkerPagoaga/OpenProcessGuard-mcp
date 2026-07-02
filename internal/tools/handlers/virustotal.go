package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"processguard-mcp/internal/config"
)

// VTReport holds the VirusTotal analysis result for a single file hash.
type VTReport struct {
	Hash         string `json:"hash"`
	Malicious    int    `json:"malicious"`
	Suspicious   int    `json:"suspicious"`
	Undetected   int    `json:"undetected"`
	Harmless     int    `json:"harmless"`
	TotalEngines int    `json:"total_engines"`
	Score        string `json:"score"` // "5/72" human-readable
	Permalink    string `json:"permalink"`
	Error        string `json:"error,omitempty"`
}

// vtCacheEntry is an in-memory cache record keyed by SHA256 hash.
type vtCacheEntry struct {
	report   VTReport
	cachedAt time.Time
}

// vtCall coalesces concurrent lookups of the same hash so that N simultaneous
// callers make ONE upstream request and share the result (a manual
// singleflight, keeping this dependency-free).
type vtCall struct {
	wg     sync.WaitGroup
	report VTReport
	err    error
}

var (
	vtCacheMu  sync.Mutex
	vtCache    = map[string]vtCacheEntry{}
	vtInflight = map[string]*vtCall{}
)

const vtCacheTTL = 24 * time.Hour

// vtHashRe validates a SHA256 as exactly 64 lowercase hex characters before it
// is ever interpolated into the request URL.
var vtHashRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// rateLimiter provides a token bucket at 4 requests per 60 seconds to stay
// within the VirusTotal free tier (4 req/min).
var vtRateLimiter = newTokenBucket(4, 60*time.Second)

// LookupHash queries VirusTotal for a SHA256 hash. Returns a fresh cached result
// when available, coalesces concurrent identical lookups, and NEVER exposes the
// API key in the returned data.
func LookupHash(cfg *config.Config, sha256 string) (string, error) {
	if cfg.VTAPIKey == "" {
		return "", fmt.Errorf("vt_api_key not configured — add your free VirusTotal API key to config.json")
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if !vtHashRe.MatchString(sha256) {
		return "", fmt.Errorf("invalid SHA256 hash — expected 64 hex characters")
	}

	vtCacheMu.Lock()
	// Fresh cache hit.
	if entry, ok := vtCache[sha256]; ok && time.Since(entry.cachedAt) < vtCacheTTL {
		vtCacheMu.Unlock()
		return marshalReport(entry.report)
	}
	// A lookup for this hash is already in flight — join it.
	if call, ok := vtInflight[sha256]; ok {
		vtCacheMu.Unlock()
		call.wg.Wait()
		if call.err != nil {
			return "", call.err
		}
		return marshalReport(call.report)
	}
	// We are the leader: consume a rate-limit token and register the in-flight call.
	if !vtRateLimiter.Allow() {
		vtCacheMu.Unlock()
		return "", fmt.Errorf("VirusTotal rate limit reached (4 req/min on free tier) — retry in a moment")
	}
	call := &vtCall{}
	call.wg.Add(1)
	vtInflight[sha256] = call
	vtCacheMu.Unlock()

	// The fetch runs inside a recover so a panic cannot leave the in-flight slot
	// registered and the WaitGroup un-Done — which would block every follower
	// forever and permanently poison this hash until restart.
	var report VTReport
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("VirusTotal lookup panicked: %v", r)
			}
		}()
		report, err = fetchVTReport(cfg.VTAPIKey, sha256)
	}()

	vtCacheMu.Lock()
	if err == nil {
		vtCache[sha256] = vtCacheEntry{report: report, cachedAt: time.Now()}
	}
	call.report, call.err = report, err
	delete(vtInflight, sha256)
	vtCacheMu.Unlock()
	call.wg.Done()

	if err != nil {
		return "", err
	}
	return marshalReport(report)
}

func marshalReport(r VTReport) (string, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	return string(out), err
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

	// Parse the VT API v3 response structure. The denominator MUST include every
	// analysis bucket — omitting harmless/timeout/type-unsupported understated the
	// engine total (e.g. "0/12" for a clean file that scanned 72 engines).
	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious        int `json:"malicious"`
					Suspicious       int `json:"suspicious"`
					Undetected       int `json:"undetected"`
					Harmless         int `json:"harmless"`
					Timeout          int `json:"timeout"`
					ConfirmedTimeout int `json:"confirmed-timeout"`
					Failure          int `json:"failure"`
					TypeUnsupported  int `json:"type-unsupported"`
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
	report.Harmless = stats.Harmless
	report.TotalEngines = stats.Malicious + stats.Suspicious + stats.Undetected +
		stats.Harmless + stats.Timeout + stats.ConfirmedTimeout + stats.Failure + stats.TypeUnsupported
	report.Score = fmt.Sprintf("%d/%d", stats.Malicious, report.TotalEngines)
	report.Permalink = vtResp.Data.Links.Self

	return report, nil
}

// ── Token bucket rate limiter ─────────────────────────────────────────────

type tokenBucket struct {
	mu        sync.Mutex
	tokens    int
	capacity  int
	lastFill  time.Time
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
