package harness

import (
	"context"
	"fmt"
	"sync"

	"github.com/openocta/openocta/pkg/agent/runtime"
	"github.com/stellarlinkco/agentsdk-go/pkg/api"
)

// Harness orchestrates DAG-based plan execution on top of OpenOcta's agent runtime.
type Harness struct {
	rt       *runtime.Runtime
	approval ApprovalGate
	mu       sync.Mutex
}

// New creates a Harness that uses the given runtime for node execution.
func New(rt *runtime.Runtime) *Harness {
	return &Harness{rt: rt}
}

// Runtime returns the underlying agent runtime (used for LLM-based plan generation).
func (h *Harness) Runtime() *runtime.Runtime {
	return h.rt
}

// WithApproval configures Harness to use the given approval gate for gated nodes.
func (h *Harness) WithApproval(gate ApprovalGate) *Harness {
	h.approval = gate
	return h
}

// ExecutePlan executes a plan DAG, streaming events through the given sink.
func (h *Harness) ExecutePlan(ctx context.Context, plan *Plan, sink StreamSink) error {
	h.mu.Lock()
	if plan.Status != PlanPending {
		h.mu.Unlock()
		return fmt.Errorf("harness: plan %s is not pending (status=%s)", plan.ID, plan.Status)
	}
	h.mu.Unlock()

	if plan.Context == nil {
		plan.Context = map[string]string{}
	}
	if _, ok := plan.Context["session_id"]; !ok {
		plan.Context["session_id"] = plan.ID
	}

	// NodeRunner wraps the agent runtime with per-node tool isolation and timeout.
	runner := func(ctx context.Context, node *Node, planCtx map[string]string) (string, error) {
		req := api.Request{
			Prompt:    node.Prompt,
			SessionID: planCtx["session_id"],
		}
		if len(node.Tools) > 0 {
			req.ToolWhitelist = node.Tools
		}
		resp, err := h.rt.Run(ctx, req)
		if err != nil {
			return "", fmt.Errorf("node %s: %w", node.ID, err)
		}
		if resp != nil && resp.Result != nil {
			return resp.Result.Output, nil
		}
		return "", nil
	}

	sched := NewScheduler(runner)
	if h.approval != nil {
		sched.WithApproval(h.approval)
	}
	return sched.Run(ctx, plan, sink)
}
