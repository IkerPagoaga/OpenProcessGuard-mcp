package handlers

import (
	"encoding/json"
	"testing"
)

// TestBuildTreeCycle proves a PPID loop (possible via Windows PID reuse: A's
// recorded parent is B while B's recorded parent PID was reused by A) cannot
// produce a cyclic node graph. json.Marshal fails on cycles, which would kill
// the whole get_process_tree response — the offending link must be broken by
// rooting one of the nodes instead.
func TestBuildTreeCycle(t *testing.T) {
	procs := []procRow{
		{PID: 100, PPID: 200, Name: "a.exe"},
		{PID: 200, PPID: 100, Name: "b.exe"},
	}

	roots := buildTree(procs)
	if len(roots) == 0 {
		t.Fatal("cycle swallowed both nodes — no roots returned")
	}
	if _, err := json.Marshal(roots); err != nil {
		t.Fatalf("tree still cyclic — json.Marshal failed: %v", err)
	}

	// Both processes must remain reachable from the roots.
	seen := map[int32]bool{}
	var walk func(n *ProcessNode)
	walk = func(n *ProcessNode) {
		seen[n.PID] = true
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, r := range roots {
		walk(r)
	}
	if !seen[100] || !seen[200] {
		t.Fatalf("nodes lost breaking the cycle: reachable=%v", seen)
	}
}

// TestBuildTreeDuplicatePID pins the defensive guard for duplicate PID rows:
// without it, a later duplicate overwrites the parentOf bookkeeping while the
// earlier Children link survives, letting a subsequent row slip past
// createsCycle and rebuild the exact json.Marshal-killing cycle the visited
// check exists to prevent. (Win32_Process yields unique PIDs today — this
// locks the invariant the cycle guard depends on.)
func TestBuildTreeDuplicatePID(t *testing.T) {
	procs := []procRow{
		{PID: 300, PPID: 0, Name: "root.exe"},
		{PID: 100, PPID: 200, Name: "a.exe"},
		{PID: 100, PPID: 300, Name: "a-dup.exe"}, // duplicate PID row
		{PID: 200, PPID: 100, Name: "b.exe"},
	}

	roots := buildTree(procs)
	if _, err := json.Marshal(roots); err != nil {
		t.Fatalf("duplicate-PID rows rebuilt a cycle — json.Marshal failed: %v", err)
	}

	seen := map[int32]bool{}
	var walk func(n *ProcessNode)
	walk = func(n *ProcessNode) {
		if seen[n.PID] {
			t.Fatalf("node %d reachable twice — graph is not a forest", n.PID)
		}
		seen[n.PID] = true
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, r := range roots {
		walk(r)
	}
	if !seen[100] || !seen[200] || !seen[300] {
		t.Fatalf("nodes lost handling duplicates: reachable=%v", seen)
	}
}

// TestBuildTreeNormal guards the ordinary case around the cycle fix: a plain
// parent→child chain still nests, and a self-parented or orphaned process
// still lands at the root.
func TestBuildTreeNormal(t *testing.T) {
	procs := []procRow{
		{PID: 4, PPID: 0, Name: "system"},
		{PID: 300, PPID: 4, Name: "services.exe"},
		{PID: 400, PPID: 300, Name: "svchost.exe"},
		{PID: 500, PPID: 500, Name: "self.exe"},    // self-parent → root
		{PID: 600, PPID: 9999, Name: "orphan.exe"}, // unknown parent → root
	}

	roots := buildTree(procs)
	if len(roots) != 3 {
		t.Fatalf("want 3 roots (system, self, orphan), got %d", len(roots))
	}
	if _, err := json.Marshal(roots); err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
}
