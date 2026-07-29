package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"processguard-mcp/internal/config"
)

// TestEveryToolWithAHintIsRegistered keeps narrowingHints from rotting: a hint naming a
// tool that no longer exists would never fire, and the tool that replaced it would fall
// back to the generic message.
func TestEveryToolWithAHintIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, tool := range Registry() {
		registered[tool.Name] = true
	}
	for name := range narrowingHints {
		if !registered[name] {
			t.Errorf("narrowingHints names %q, which is not a registered tool", name)
		}
	}
}

// TestBudgetRefusalNamesTheLever is the contract that makes the budget useful: a
// refusal must tell the model what to change, not merely that it failed.
func TestBudgetRefusalNamesTheLever(t *testing.T) {
	for _, tool := range Registry() {
		hint, ok := narrowingHints[tool.Name]
		if !ok {
			continue
		}
		if strings.TrimSpace(hint) == "" {
			t.Errorf("tool %q has an empty narrowing hint", tool.Name)
		}
	}
	// The highest-volume tools must all carry a hint — they are the ones that can
	// realistically reach the budget.
	for _, name := range []string{
		"list_processes", "get_autoruns_entries", "run_full_hunt",
		"query_sysmon_events", "get_process_create_events", "get_network_events",
	} {
		if _, ok := narrowingHints[name]; !ok {
			t.Errorf("high-volume tool %q has no narrowing hint", name)
		}
	}
}

// TestListProcessesRespectsLimit exercises the real dispatch path end-to-end: the
// budget only holds if the tools that can produce unbounded output actually bound it.
func TestListProcessesRespectsLimit(t *testing.T) {
	out, err := callInner(context.Background(), &config.Config{}, "list_processes",
		json.RawMessage(`{"limit":3}`))
	if err != nil {
		t.Fatalf("list_processes: %v", err)
	}
	var res struct {
		Total     int  `json:"total_matched"`
		Returned  int  `json:"returned"`
		Truncated bool `json:"truncated"`
		Processes []struct {
			PID int32 `json:"pid"`
		} `json:"processes"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Returned > 3 || len(res.Processes) > 3 {
		t.Errorf("limit=3 returned %d rows (%d in array)", res.Returned, len(res.Processes))
	}
	// A truncated listing must say so AND report the true match count, otherwise a
	// short list reads as a complete one.
	if res.Total > res.Returned && !res.Truncated {
		t.Errorf("returned %d of %d matches without setting truncated", res.Returned, res.Total)
	}
	if len(out) > MaxToolOutputBytes {
		t.Errorf("a limit=3 listing produced %d bytes, over the budget", len(out))
	}
}

// TestListProcessesNameFilterNarrows proves the lever the budget refusal points at
// actually works.
func TestListProcessesNameFilterNarrows(t *testing.T) {
	all, err := callInner(context.Background(), &config.Config{}, "list_processes",
		json.RawMessage(`{"limit":2000}`))
	if err != nil {
		t.Fatalf("unfiltered: %v", err)
	}
	filtered, err := callInner(context.Background(), &config.Config{}, "list_processes",
		json.RawMessage(`{"name_filter":"zzz-no-such-process-zzz"}`))
	if err != nil {
		t.Fatalf("filtered: %v", err)
	}
	if len(filtered) >= len(all) {
		t.Errorf("name_filter did not narrow output: filtered=%d unfiltered=%d", len(filtered), len(all))
	}
}
