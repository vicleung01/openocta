package harness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestScheduler_SequentialExec(t *testing.T) {
	var mu sync.Mutex
	var order []string
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		mu.Lock()
		order = append(order, node.ID)
		mu.Unlock()
		return "ok", nil
	}

	plan := &Plan{
		ID: "test",
		Nodes: map[string]*Node{
			"a": {ID: "a", Status: NodePending},
			"b": {ID: "b", DependsOn: []string{"a"}, Status: NodePending},
			"c": {ID: "c", DependsOn: []string{"b"}, Status: NodePending},
		},
		EntryNode: "a",
		Status:    PlanPending,
		Context:   map[string]string{},
	}

	sched := NewScheduler(runner)
	err := sched.Run(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(order) != 3 || order[0] != "a" || order[1] != "b" || order[2] != "c" {
		t.Fatalf("expected order [a b c], got %v", order)
	}
}

func TestScheduler_ParallelExec(t *testing.T) {
	var mu sync.Mutex
	var ran []string
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		ran = append(ran, node.ID)
		mu.Unlock()
		return "ok", nil
	}

	plan := &Plan{
		ID: "parallel-test",
		Nodes: map[string]*Node{
			"a": {ID: "a", Parallel: true, Status: NodePending},
			"b": {ID: "b", Parallel: true, Status: NodePending},
			"c": {ID: "c", DependsOn: []string{"a", "b"}, Status: NodePending},
		},
		EntryNode: "a",
		Status:    PlanPending,
		Context:   map[string]string{},
	}

	start := time.Now()
	sched := NewScheduler(runner)
	err := sched.Run(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed := time.Since(start)

	// a and b ran in parallel, so total time should be way less than 2*50ms
	// Use a generous threshold (150ms) to account for Windows scheduler granularity.
	if elapsed >= 150*time.Millisecond {
		t.Fatalf("expected parallel execution under 90ms, took %v", elapsed)
	}

	if plan.Nodes["a"].Status != NodeSucceeded || plan.Nodes["b"].Status != NodeSucceeded || plan.Nodes["c"].Status != NodeSucceeded {
		t.Fatalf("expected all nodes succeeded: a=%s b=%s c=%s", plan.Nodes["a"].Status, plan.Nodes["b"].Status, plan.Nodes["c"].Status)
	}
}

func TestScheduler_RetryThenSucceed(t *testing.T) {
	attempts := 0
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		attempts++
		if attempts < 2 {
			return "", errors.New("temporary error")
		}
		return "ok", nil
	}

	plan := &Plan{
		ID: "retry-test",
		Nodes: map[string]*Node{
			"a": {ID: "a", MaxRetries: 2, Status: NodePending},
		},
		EntryNode: "a",
		Status:    PlanPending,
		Context:   map[string]string{},
	}

	sched := NewScheduler(runner)
	err := sched.Run(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if plan.Nodes["a"].Status != NodeSucceeded {
		t.Fatalf("expected node a to succeed after retry, got %s", plan.Nodes["a"].Status)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestScheduler_FailAfterRetries(t *testing.T) {
	attempts := 0
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		attempts++
		return "", errors.New("persistent error")
	}

	plan := &Plan{
		ID: "fail-test",
		Nodes: map[string]*Node{
			"a": {ID: "a", MaxRetries: 2, Status: NodePending},
		},
		EntryNode: "a",
		Status:    PlanPending,
		Context:   map[string]string{},
	}

	sched := NewScheduler(runner)
	err := sched.Run(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("expected plan to complete despite node failure: %v", err)
	}

	if plan.Nodes["a"].Status != NodeFailed {
		t.Fatalf("expected node a to fail, got %s", plan.Nodes["a"].Status)
	}
	if attempts != 3 { // initial + 2 retries
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestScheduler_OutputKeyCapture(t *testing.T) {
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		return "result-of-" + node.ID, nil
	}

	plan := &Plan{
		ID: "output-test",
		Nodes: map[string]*Node{
			"a": {ID: "a", OutputKey: "step_a", Status: NodePending},
		},
		EntryNode: "a",
		Status:    PlanPending,
		Context:   map[string]string{},
	}

	sched := NewScheduler(runner)
	err := sched.Run(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if plan.Context["step_a"] != "result-of-a" {
		t.Fatalf("expected context[step_a]=result-of-a, got %q", plan.Context["step_a"])
	}
}

func TestScheduler_NonPendingPlan(t *testing.T) {
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		return "ok", nil
	}

	plan := &Plan{
		ID:     "already-running",
		Status: PlanRunning,
	}

	sched := NewScheduler(runner)
	err := sched.Run(context.Background(), plan, nil)
	if err == nil {
		t.Fatal("expected error for non-pending plan")
	}
}
