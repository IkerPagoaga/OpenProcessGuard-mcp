package handlers

import (
	"context"
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
// API key in the returned data. The context aborts the upstream HTTP call when
// the server is shutting down (all requests share the serve-level context, so a
// follower waiting on the in-flight leader unblocks when the leader aborts).
func LookupHash(ctx context.Context, cfg *config.Config, sha256 string) (string, error) {
	if cfg.VTAPIKey == "" {
		return "", fmt.Errorf("vt_api_key not configured — add your free VirusTotal API key to config.json")
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if !vtHashRe.MatchString(sha256) {
		return "", fmt.Errorf("invalid SHA256 hash — expected 64 hex characters")
	}

	vtCacheMu.Lock()
	// Fresh cache hit; an entry found past its TTL is evicted on sight so a
	// re-looked-up stale hash does not linger (evict-on-expired-read).
	if entry, ok := vtCache[sha256]; ok {
		if time.Since(entry.cachedAt) < vtCacheTTL {
			vtCacheMu.Unlock()
			return marshalReport(entry.report)
		}
		delete(vtCache, sha256)
	}
	// A lookup for this hash is already in flight — join it and share its result.
	// This is safe because ALL callers share the one serve-lifetime context: if the
	// leader's fetch is cancelled, this follower's context is the same one and is
	// also cancelled, so inheriting the leader's cancellation error is correct. (If
	// per-request contexts are ever introduced, a follower with a still-live request
	// would need to re-lead rather than inherit the leader's cancellation.)
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
	var reached bool
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("VirusTotal lookup panicked: %v", r)
			}
		}()
		report, reached, err = fetchVTReport(ctx, cfg.VTAPIKey, sha256)
	}()

	vtCacheMu.Lock()
	// Bound the cache: sweep aged-out entries on the leader path of a genuine upstream
	// lookup. Reads gate on the TTL but never freed memory, so a long-lived server that
	// looked up many one-shot hashes grew vtCache without limit — this reclaims them.
	evictExpiredLocked(time.Now())
	if err == nil {
		vtCache[sha256] = vtCacheEntry{report: report, cachedAt: time.Now()}
	}
	call.report, call.err = report, err
	delete(vtInflight, sha256)
	vtCacheMu.Unlock()
	call.wg.Done()

	// A request that never reached VirusTotal (transport failure or panic) consumed
	// no upstream quota — return the token so a VT outage doesn't drain the budget.
	// An HTTP error response DID reach VT and is left counted.
	if err != nil && !reached {
		vtRateLimiter.Refund()
	}

	if err != nil {
		return "", err
	}
	return marshalReport(report)
}

func marshalReport(r VTReport) (string, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	return string(out), err
}

// evictExpiredLocked removes every cache entry at or past its TTL and returns the
// number dropped. The caller MUST hold vtCacheMu. Together with evict-on-expired-read
// this bounds vtCache instead of letting it grow for the life of the process.
func evictExpiredLocked(now time.Time) int {
	removed := 0
	for h, e := range vtCache {
		if now.Sub(e.cachedAt) >= vtCacheTTL {
			delete(vtCache, h)
			removed++
		}
	}
	return removed
}

// fetchVTReport makes the actual VirusTotal API v3 call. The bool return reports
// whether the request actually REACHED VirusTotal (i.e. produced an HTTP response):
// a transport failure that never reached the upstream should not consume the
// caller's per-minute rate budget, whereas an HTTP error response DID consume real
// VT quota and must count.
func fetchVTReport(ctx context.Context, apiKey, sha256 string) (VTReport, bool, error) {
	report := VTReport{Hash: sha256}

	url := "https://www.virustotal.com/api/v3/files/" + sha256
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return report, false, fmt.Errorf("VT request build failed: %w", err)
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return report, false, fmt.Errorf("VT request failed: %w", err)
	}
	defer resp.Body.Close()

	// From here on we have an HTTP response — the request reached VirusTotal.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return report, true, fmt.Errorf("VT response read failed: %w", err)
	}

	if resp.StatusCode == 404 {
		report.Score = "not found"
		return report, true, nil
	}
	if resp.StatusCode != 200 {
		return report, true, fmt.Errorf("VT API returned HTTP %d", resp.StatusCode)
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
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return report, true, fmt.Errorf("VT response parse failed: %w", err)
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	report.Malicious = stats.Malicious
	report.Suspicious = stats.Suspicious
	report.Undetected = stats.Undetected
	report.Harmless = stats.Harmless
	report.TotalEngines = stats.Malicious + stats.Suspicious + stats.Undetected +
		stats.Harmless + stats.Timeout + stats.ConfirmedTimeout + stats.Failure + stats.TypeUnsupported
	report.Score = fmt.Sprintf("%d/%d", stats.Malicious, report.TotalEngines)
	// Human-facing GUI URL, not the API "self" link (which requires auth and is
	// not viewable in a browser).
	report.Permalink = "https://www.virustotal.com/gui/file/" + sha256

	return report, true, nil
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

	// Refill gradually — one token per (fillEvery / capacity) — rather than
	// resetting to full at a window boundary, which allowed a burst of up to
	// 2x-capacity straddling the boundary. This is a real token bucket.
	interval := tb.fillEvery / time.Duration(tb.capacity)
	if interval <= 0 {
		interval = tb.fillEvery
	}
	if refill := int(time.Since(tb.lastFill) / interval); refill > 0 {
		tb.tokens += refill
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastFill = tb.lastFill.Add(time.Duration(refill) * interval)
	}

	if tb.tokens <= 0 {
		return false
	}
	tb.tokens--
	return true
}

// Refund returns a previously-consumed token (never exceeding capacity). Used when
// a request never reached the upstream, so a transient VirusTotal outage does not
// permanently reduce the minute's budget.
func (tb *tokenBucket) Refund() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.tokens < tb.capacity {
		tb.tokens++
	}
}
