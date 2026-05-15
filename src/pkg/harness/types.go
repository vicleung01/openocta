// Package harness provides DAG-based agent orchestration on top of OpenOcta's runtime.
// It enables multi-step plans with conditional branching, parallel execution,
// approval gates, and retry/fallback — capabilities absent from the linear ReAct loop.
package harness

import "time"

// NodeStatus represents the execution state of a single plan node.
type NodeStatus string

const (
	NodePending   NodeStatus = "pending"
	NodeRunning   NodeStatus = "running"
	NodeSucceeded NodeStatus = "succeeded"
	NodeFailed    NodeStatus = "failed"
	NodeSkipped   NodeStatus = "skipped"
	NodeBlocked   NodeStatus = "blocked" // waiting for human approval
)

// PlanStatus represents the overall execution state of a plan.
type PlanStatus string

const (
	PlanPending   PlanStatus = "pending"
	PlanRunning   PlanStatus = "running"
	PlanSucceeded PlanStatus = "succeeded"
	PlanFailed    PlanStatus = "failed"
	PlanCancelled PlanStatus = "cancelled"
)

// Node defines a single step in a plan DAG.
type Node struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	Prompt          string            `json:"prompt"`
	Tools           []string          `json:"tools,omitempty"`            // allowed tools (empty = all)
	DependsOn       []string          `json:"depends_on,omitempty"`       // upstream node IDs
	OnSuccess       map[string]string `json:"on_success,omitempty"`       // condition → next node; "default" is the fallback
	OnFailure       string            `json:"on_failure,omitempty"`       // fallback node on error
	MaxRetries      int               `json:"max_retries,omitempty"`      // 0 = no retry
	Timeout         time.Duration     `json:"timeout,omitempty"`          // per-node timeout
	RequireApproval bool              `json:"require_approval,omitempty"` // block until approved
	Parallel        bool              `json:"parallel,omitempty"`         // can run in parallel with siblings
	OutputKey       string            `json:"output_key,omitempty"`       // key to store result in plan context
	Status          NodeStatus        `json:"status"`
}

// Plan represents a full DAG workflow.
type Plan struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Nodes     map[string]*Node    `json:"nodes"`
	EntryNode string              `json:"entry_node"`
	Context   map[string]string   `json:"context,omitempty"` // shared state across nodes
	Status    PlanStatus          `json:"status"`
}

// ReadyNodes returns node IDs whose dependencies are all satisfied.
func (p *Plan) ReadyNodes() []string {
	done := map[string]bool{}
	for _, n := range p.Nodes {
		if n.Status == NodeSucceeded || n.Status == NodeSkipped || n.Status == NodeFailed {
			done[n.ID] = true
		}
	}
	var ready []string
	for _, n := range p.Nodes {
		if n.Status != NodePending {
			continue
		}
		allDepDone := true
		for _, dep := range n.DependsOn {
			if !done[dep] {
				allDepDone = false
				break
			}
		}
		if allDepDone {
			ready = append(ready, n.ID)
		}
	}
	return ready
}

// allTerminal returns true when every node has reached a terminal status.
func allTerminal(plan *Plan) bool {
	for _, n := range plan.Nodes {
		switch n.Status {
		case NodePending, NodeRunning, NodeBlocked:
			return false
		}
	}
	return true
}
