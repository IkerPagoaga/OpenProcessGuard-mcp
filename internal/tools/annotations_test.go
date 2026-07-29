package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"processguard-mcp/internal/config"
)

// TestEveryToolIsAnnotatedReadOnly is the machine-readable counterpart to the guarantee
// the docs assert in prose. A tool that ships without readOnlyHint silently downgrades
// the product's central claim to something a client cannot verify.
func TestEveryToolIsAnnotatedReadOnly(t *testing.T) {
	tools := Registry()
	if len(tools) == 0 {
		t.Fatal("Registry() returned no tools")
	}
	for _, tool := range tools {
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("tool %q is missing readOnlyHint:true", tool.Name)
		}
	}
}

// TestOpenWorldHintMarksOnlyNetworkTools pins the single exception. Every other tool
// inspects the local machine only; mislabelling one as open-world (or failing to label
// lookup_hash) misrepresents where the data goes.
func TestOpenWorldHintMarksOnlyNetworkTools(t *testing.T) {
	for _, tool := range Registry() {
		want := openWorldTools[tool.Name]
		if tool.Annotations.OpenWorldHint != want {
			t.Errorf("tool %q openWorldHint = %v, want %v", tool.Name, tool.Annotations.OpenWorldHint, want)
		}
	}
	if !openWorldTools["lookup_hash"] {
		t.Error("lookup_hash must be marked open-world — it queries the VirusTotal API")
	}
}

// TestAnnotationsSerialiseForTheWire guards the JSON field names: a client reads
// "readOnlyHint", so a struct-tag typo would leave the annotation invisible despite
// every in-process assertion above passing.
func TestAnnotationsSerialiseForTheWire(t *testing.T) {
	b, err := json.Marshal(Registry()[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"annotations"`, `"readOnlyHint":true`, `"openWorldHint"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("serialised tool is missing %s; got %s", want, b)
		}
	}
}

// TestRegistryDispatcherNoDrift catches the exact failure of registering a tool and
// forgetting its case in callInner: the tool would advertise itself and then fail with
// "unknown tool" the first time a model called it. The context is pre-cancelled so no
// handler does real work — only the dispatch lookup is under test.
func TestRegistryDispatcherNoDrift(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &config.Config{}
	for _, tool := range Registry() {
		t.Run(tool.Name, func(t *testing.T) {
			_, err := callInner(ctx, cfg, tool.Name, json.RawMessage(`{}`))
			if err != nil && strings.Contains(err.Error(), "unknown tool") {
				t.Errorf("tool %q is registered but not handled by callInner: %v", tool.Name, err)
			}
		})
	}
}

// TestUnknownToolIsRejected is the negative control for the drift test above: if
// callInner stopped reporting "unknown tool", TestRegistryDispatcherNoDrift would pass
// vacuously for every tool.
func TestUnknownToolIsRejected(t *testing.T) {
	_, err := callInner(context.Background(), &config.Config{}, "definitely_not_a_tool", json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("callInner on an unregistered name returned %v, want an 'unknown tool' error", err)
	}
}
