package harness

import (
	"testing"
)

func TestPlan_ReadyNodes_NoDeps(t *testing.T) {
	plan := &Plan{
		ID: "test",
		Nodes: map[string]*Node{
			"a": {ID: "a", Status: NodePending},
			"b": {ID: "b", Status: NodePending},
		},
		EntryNode: "a",
	}

	ready := plan.ReadyNodes()
	if len(ready) != 2 {
		t.Fatalf("expected 2 ready nodes, got %d: %v", len(ready), ready)
	}
}

func TestPlan_ReadyNodes_WithDeps(t *testing.T) {
	plan := &Plan{
		ID: "test",
		Nodes: map[string]*Node{
			"a": {ID: "a", DependsOn: nil, Status: NodePending},
			"b": {ID: "b", DependsOn: []string{"a"}, Status: NodePending},
			"c": {ID: "c", DependsOn: []string{"b"}, Status: NodePending},
		},
		EntryNode: "a",
	}

	// only a has no deps
	ready := plan.ReadyNodes()
	if len(ready) != 1 || ready[0] != "a" {
		t.Fatalf("expected only 'a' ready, got %v", ready)
	}

	// mark a done
	plan.Nodes["a"].Status = NodeSucceeded
	ready = plan.ReadyNodes()
	if len(ready) != 1 || ready[0] != "b" {
		t.Fatalf("expected 'b' ready after a completes, got %v", ready)
	}

	// mark b done
	plan.Nodes["b"].Status = NodeSucceeded
	ready = plan.ReadyNodes()
	if len(ready) != 1 || ready[0] != "c" {
		t.Fatalf("expected 'c' ready after b completes, got %v", ready)
	}
}

func TestPlan_ReadyNodes_SkipFailed(t *testing.T) {
	plan := &Plan{
		ID: "test",
		Nodes: map[string]*Node{
			"a": {ID: "a", Status: NodePending},
			"b": {ID: "b", DependsOn: []string{"a"}, Status: NodePending},
		},
	}

	// mark a as failed — b should still become ready (failed deps count as "done" for readiness)
	plan.Nodes["a"].Status = NodeFailed
	ready := plan.ReadyNodes()
	if len(ready) != 1 || ready[0] != "b" {
		t.Fatalf("expected 'b' ready after a fails, got %v", ready)
	}
}

func TestPlan_ReadyNodes_BlockedNotReady(t *testing.T) {
	plan := &Plan{
		ID: "test",
		Nodes: map[string]*Node{
			"a": {ID: "a", Status: NodeBlocked},
			"b": {ID: "b", DependsOn: []string{"a"}, Status: NodePending},
		},
	}

	ready := plan.ReadyNodes()
	if len(ready) != 0 {
		t.Fatalf("expected 0 ready (a is blocked), got %v", ready)
	}

	// a becomes skipped
	plan.Nodes["a"].Status = NodeSkipped
	ready = plan.ReadyNodes()
	if len(ready) != 1 || ready[0] != "b" {
		t.Fatalf("expected 'b' ready after a skipped, got %v", ready)
	}
}

func TestAllTerminal(t *testing.T) {
	plan := &Plan{
		Nodes: map[string]*Node{
			"a": {ID: "a", Status: NodeSucceeded},
			"b": {ID: "b", Status: NodeFailed},
			"c": {ID: "c", Status: NodeSkipped},
		},
	}
	if !allTerminal(plan) {
		t.Fatal("expected all terminal")
	}
}

func TestAllTerminal_Running(t *testing.T) {
	plan := &Plan{
		Nodes: map[string]*Node{
			"a": {ID: "a", Status: NodeSucceeded},
			"b": {ID: "b", Status: NodeRunning},
		},
	}
	if allTerminal(plan) {
		t.Fatal("expected not all terminal (b is running)")
	}
}
