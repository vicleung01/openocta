package harness

import (
	"context"
	"fmt"
	"sync"
)

// ApprovalGate is the interface for node-level approval gating.
type ApprovalGate interface {
	Request(sessionID, nodeName, description string) (string, error)
	Wait(ctx context.Context, recordID string) (bool, error)
}

// NodeRunner executes a single node and returns its text output.
type NodeRunner func(ctx context.Context, node *Node, planCtx map[string]string) (string, error)

// Scheduler executes a Plan DAG by managing node lifecycle, concurrency, and routing.
type Scheduler struct {
	runNode  NodeRunner
	approval ApprovalGate
}

// NewScheduler creates a scheduler with the given node execution function.
func NewScheduler(runNode NodeRunner) *Scheduler {
	return &Scheduler{runNode: runNode}
}

// WithApproval configures the scheduler to use the given approval gate.
func (s *Scheduler) WithApproval(gate ApprovalGate) *Scheduler {
	s.approval = gate
	return s
}

// Run executes the plan DAG, calling sink for each lifecycle event.
func (s *Scheduler) Run(ctx context.Context, plan *Plan, sink StreamSink) error {
	if plan.Status != PlanPending {
		return fmt.Errorf("scheduler: plan %s is not pending (status=%s)", plan.ID, plan.Status)
	}
	plan.Status = PlanRunning
	emit(sink, Event{Type: EventPlanStart, PlanID: plan.ID, PlanName: plan.Name})

	defer func() {
		if plan.Status == PlanRunning {
			plan.Status = PlanFailed
			emit(sink, Event{Type: EventPlanComplete, PlanID: plan.ID, Status: string(PlanFailed)})
		}
	}()

	for {
		ready := plan.ReadyNodes()
		if len(ready) == 0 {
			if allTerminal(plan) {
				plan.Status = PlanSucceeded
				emit(sink, Event{Type: EventPlanComplete, PlanID: plan.ID, Status: string(PlanSucceeded)})
				return nil
			}
			return s.handleStall(plan, sink)
		}

		// separate parallel vs serial nodes
		var parallel, serial []string
		for _, id := range ready {
			if plan.Nodes[id].Parallel {
				parallel = append(parallel, id)
			} else {
				serial = append(serial, id)
			}
		}

		// run parallel batch
		if len(parallel) > 0 {
			s.runParallel(ctx, plan, parallel, sink)
		}

		// run serial batch
		for _, id := range serial {
			s.runSingle(ctx, plan, plan.Nodes[id], sink)
		}

		// evaluate routing conditions after execution
		s.evaluateRouting(plan)

		// if all remaining nodes are blocked, stop
		if allBlocked(plan) {
			plan.Status = PlanFailed
			emit(sink, Event{Type: EventPlanComplete, PlanID: plan.ID, Status: string(PlanFailed), Message: "all remaining nodes blocked"})
			return fmt.Errorf("scheduler: plan %s stalled — all remaining nodes blocked", plan.ID)
		}
	}
}

// runSingle executes one node with retries.
func (s *Scheduler) runSingle(ctx context.Context, plan *Plan, node *Node, sink StreamSink) {
	// approval gating comes before execution state
	if node.RequireApproval {
		node.Status = NodeBlocked
		emit(sink, Event{Type: EventNodeBlocked, PlanID: plan.ID, NodeID: node.ID, NodeName: node.Name, Reason: "awaiting approval"})

		if s.approval == nil {
			node.Status = NodeFailed
			emit(sink, Event{Type: EventNodeComplete, PlanID: plan.ID, NodeID: node.ID, Status: string(NodeFailed), Message: "no approval gate configured"})
			return
		}

		recordID, err := s.approval.Request(plan.Context["session_id"], node.Name, node.Description)
		if err != nil {
			node.Status = NodeFailed
			emit(sink, Event{Type: EventNodeComplete, PlanID: plan.ID, NodeID: node.ID, Status: string(NodeFailed), Message: fmt.Sprintf("approval request failed: %v", err)})
			return
		}
		emit(sink, Event{Type: EventNodeBlocked, PlanID: plan.ID, NodeID: node.ID, Reason: fmt.Sprintf("approval_id=%s", recordID)})

		approved, err := s.approval.Wait(ctx, recordID)
		if err != nil {
			node.Status = NodeFailed
			emit(sink, Event{Type: EventNodeComplete, PlanID: plan.ID, NodeID: node.ID, Status: string(NodeFailed), Message: fmt.Sprintf("approval wait failed: %v", err)})
			return
		}
		if !approved {
			node.Status = NodeSkipped
			emit(sink, Event{Type: EventNodeSkip, PlanID: plan.ID, NodeID: node.ID, Message: "approval denied"})
			return
		}
		// approved — fall through to execution
	}

	// mark running and execute
	node.Status = NodeRunning
	emit(sink, Event{Type: EventNodeStart, PlanID: plan.ID, NodeID: node.ID, NodeName: node.Name})

	// retry loop
	var lastErr error
	for attempt := 0; attempt <= node.MaxRetries; attempt++ {
		if attempt > 0 {
			emit(sink, Event{Type: EventNodeRetry, PlanID: plan.ID, NodeID: node.ID, Message: fmt.Sprintf("retry %d/%d", attempt, node.MaxRetries)})
		}

		output, err := s.runNode(ctx, node, plan.Context)
		if err == nil {
			node.Status = NodeSucceeded
			if node.OutputKey != "" {
				plan.Context[node.OutputKey] = output
			}
			emit(sink, Event{Type: EventNodeComplete, PlanID: plan.ID, NodeID: node.ID, Status: string(NodeSucceeded)})
			return
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}

	node.Status = NodeFailed
	msg := lastErr.Error()
	emit(sink, Event{Type: EventNodeComplete, PlanID: plan.ID, NodeID: node.ID, Status: string(NodeFailed), Message: msg})

	if node.OnFailure != "" {
		if target := plan.Nodes[node.OnFailure]; target != nil && target.Status == NodePending {
			s.runSingle(ctx, plan, target, sink)
		}
	}
}

// runParallel executes multiple nodes concurrently.
func (s *Scheduler) runParallel(ctx context.Context, plan *Plan, ids []string, sink StreamSink) {
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		node := plan.Nodes[id]
		go func() {
			defer wg.Done()
			s.runSingle(ctx, plan, node, sink)
		}()
	}
	wg.Wait()
}

// evaluateRouting checks OnSuccess conditions to determine which nodes to activate next.
func (s *Scheduler) evaluateRouting(plan *Plan) {
	for _, n := range plan.Nodes {
		if n.Status != NodeSucceeded || len(n.OnSuccess) == 0 {
			continue
		}
		output := plan.Context[n.OutputKey]
		if next, ok := n.OnSuccess[output]; ok {
			_ = next
		} else if next, ok := n.OnSuccess["default"]; ok {
			_ = next
		}
	}
}

// handleStall detects why a plan stalled and returns an appropriate error.
func (s *Scheduler) handleStall(plan *Plan, sink StreamSink) error {
	var pending, blocked []string
	for _, n := range plan.Nodes {
		switch n.Status {
		case NodePending:
			pending = append(pending, n.ID)
		case NodeBlocked:
			blocked = append(blocked, n.ID)
		}
	}
	if len(blocked) > 0 {
		emit(sink, Event{Type: EventPlanComplete, PlanID: plan.ID, Status: string(PlanFailed), Message: "blocked by approvals"})
		return fmt.Errorf("scheduler: plan %s blocked by nodes: %v", plan.ID, blocked)
	}
	if len(pending) > 0 {
		emit(sink, Event{Type: EventPlanComplete, PlanID: plan.ID, Status: string(PlanFailed), Message: "nodes unreachable"})
		return fmt.Errorf("scheduler: plan %s has unreachable nodes: %v (check dependency graph)", plan.ID, pending)
	}
	return fmt.Errorf("scheduler: plan %s stalled with no ready nodes", plan.ID)
}

// allBlocked returns true when every non-terminal node is blocked (waiting for approval).
func allBlocked(plan *Plan) bool {
	hasAnyNonTerminal := false
	allNonTerminalAreBlocked := true
	for _, n := range plan.Nodes {
		if isTerminal(n.Status) {
			continue
		}
		hasAnyNonTerminal = true
		if n.Status != NodeBlocked {
			allNonTerminalAreBlocked = false
		}
	}
	return hasAnyNonTerminal && allNonTerminalAreBlocked
}

func isTerminal(s NodeStatus) bool {
	return s == NodeSucceeded || s == NodeFailed || s == NodeSkipped
}

func emit(sink StreamSink, evt Event) {
	if sink != nil {
		sink(evt)
	}
}
