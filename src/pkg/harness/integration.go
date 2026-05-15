package harness

import (
	"context"
	"fmt"
	"strings"

	"github.com/openocta/openocta/pkg/agent/runtime"
	"github.com/openocta/openocta/pkg/security"
	"github.com/stellarlinkco/agentsdk-go/pkg/api"
)

// PlanCommandPrefixes are the message prefixes that trigger plan mode.
var PlanCommandPrefixes = []string{"/plan", "!plan", ".plan"}

// DetectPlanRequest checks if a message is a plan request and extracts the plan name/description.
func DetectPlanRequest(message string) (isPlan bool, identifier string) {
	msg := strings.TrimSpace(message)
	for _, prefix := range PlanCommandPrefixes {
		if strings.HasPrefix(strings.ToLower(msg), prefix) {
			rest := strings.TrimSpace(msg[len(prefix):])
			if rest == "" {
				return true, "help"
			}
			return true, rest
		}
	}
	return false, ""
}

// PlanExecutor bridges the Harness with the Gateway's chat flow.
type PlanExecutor struct {
	harness *Harness
	planner *Planner
}

// NewPlanExecutor creates a PlanExecutor with the given runtime.
func NewPlanExecutor(rt *runtime.Runtime) *PlanExecutor {
	return &PlanExecutor{
		harness: New(rt),
		planner: NewPlanner(),
	}
}

// Planner returns the underlying Planner.
func (e *PlanExecutor) Planner() *Planner {
	return e.planner
}

// ExecuteTemplate loads a template by name and executes it as a plan.
func (e *PlanExecutor) ExecuteTemplate(ctx context.Context, templateName string, sink StreamSink) error {
	tmpl, err := e.planner.GetTemplate(templateName)
	if err != nil {
		return fmt.Errorf("plan: template %q: %w", templateName, err)
	}
	plan := BuildPlanFromTemplate(tmpl, fmt.Sprintf("plan-%s", templateName))
	return e.harness.ExecutePlan(ctx, plan, sink)
}

// ExecutePrompt treats the message as a plan description and handles execution.
func (e *PlanExecutor) ExecutePrompt(ctx context.Context, message string, sessionID string, sink StreamSink) error {
	for _, name := range e.planner.ListTemplates() {
		if strings.Contains(strings.ToLower(message), strings.ToLower(name)) ||
			strings.Contains(strings.ToLower(message), strings.ReplaceAll(name, "_", " ")) {
			return e.ExecuteTemplate(ctx, name, sink)
		}
	}
	// No template matched — try LLM-based plan generation
	if e.harness != nil && e.harness.Runtime() != nil {
		plan, err := e.GeneratePlan(ctx, message, sessionID)
		if err == nil {
			return e.harness.ExecutePlan(ctx, plan, sink)
		}
	}
	names := e.planner.ListTemplates()
	return fmt.Errorf("plan: no template matched. Available templates: %s\n\nTry: /plan slow_query_analysis", strings.Join(names, ", "))
}

// GeneratePlan uses the LLM to decompose a natural language description into a Plan DAG.
func (e *PlanExecutor) GeneratePlan(ctx context.Context, description, sessionID string) (*Plan, error) {
	if e.harness == nil || e.harness.Runtime() == nil {
		return nil, fmt.Errorf("plan: runtime not available for LLM generation")
	}
	rt := e.harness.Runtime()
	callLLM := func(ctx context.Context, prompt string) (string, error) {
		req := api.Request{
			Prompt:    prompt,
			SessionID: sessionID,
		}
		resp, err := rt.Run(ctx, req)
		if err != nil {
			return "", err
		}
		if resp != nil && resp.Result != nil {
			return resp.Result.Output, nil
		}
		return "", fmt.Errorf("empty response from runtime")
	}
	return LLMGeneratePlan(ctx, description, callLLM)
}

// WithApprovalQueue configures the PlanExecutor to use the given approval queue.
func (e *PlanExecutor) WithApprovalQueue(q *security.ApprovalQueue) *PlanExecutor {
	e.harness.WithApproval(NewSecurityApprovalGate(q))
	return e
}

// SecurityApprovalGate adapts security.ApprovalQueue to the harness.ApprovalGate interface.
type SecurityApprovalGate struct {
	inner *security.ApprovalQueue
}

// NewSecurityApprovalGate creates an adapter around the existing OpenOcta approval queue.
func NewSecurityApprovalGate(q *security.ApprovalQueue) *SecurityApprovalGate {
	return &SecurityApprovalGate{inner: q}
}

func (g *SecurityApprovalGate) Request(sessionID, nodeName, description string) (string, error) {
	cmd := fmt.Sprintf("[Plan Node] %s: %s", nodeName, description)
	rec, err := g.inner.Request(sessionID, cmd, nil)
	if err != nil {
		return "", err
	}
	return rec.ID, nil
}

func (g *SecurityApprovalGate) Wait(ctx context.Context, recordID string) (bool, error) {
	rec, err := g.inner.Wait(ctx, recordID)
	if err != nil {
		return false, err
	}
	return rec.State == security.ApprovalApproved, nil
}

// --- Streaming helpers ---

func StreamToEventChan(ctx context.Context) (StreamSink, <-chan Event) {
	ch := make(chan Event, 64)
	sink := func(evt Event) {
		select {
		case ch <- evt:
		case <-ctx.Done():
		}
	}
	return sink, ch
}

func PlanStreamSinkFromChan(ch chan<- Event) StreamSink {
	return func(evt Event) {
		select {
		case ch <- evt:
		default:
		}
	}
}

func adaptEventsToGateway(planID string, events <-chan Event, broadcast func(eventType string, payload interface{})) {
	for evt := range events {
		payload := map[string]interface{}{
			"plan_id":   planID,
			"event":     string(evt.Type),
			"node_id":   evt.NodeID,
			"node_name": evt.NodeName,
			"status":    evt.Status,
			"message":   evt.Message,
		}
		broadcast("plan_"+string(evt.Type), payload)
	}
	broadcast("plan_complete", map[string]interface{}{
		"plan_id": planID,
	})
}

// AdaptGatewayBroadcast wraps the Gateway's broadcast function for harness events.
func (e *PlanExecutor) AdaptGatewayBroadcast(ctx context.Context, planID string, broadcastFn func(string, interface{})) StreamSink {
	return func(evt Event) {
		payload := map[string]interface{}{
			"plan_id":   planID,
			"event":     string(evt.Type),
			"node_id":   evt.NodeID,
			"node_name": evt.NodeName,
			"status":    evt.Status,
			"message":   evt.Message,
		}
		eventType := "plan_" + string(evt.Type)
		broadcastFn(eventType, payload)

		if evt.Type == EventNodeComplete && evt.Status == string(NodeSucceeded) {
			broadcastFn("plan_node_output", map[string]interface{}{
				"plan_id": planID,
				"node_id": evt.NodeID,
			})
		}
	}
}

var _ = &PlanExecutor{}

// PlanCommandHandler returns a handler function compatible with the Gateway's command pattern.
func PlanCommandHandler(executor *PlanExecutor) func(ctx context.Context, message, sessionID string, sink StreamSink) error {
	return func(ctx context.Context, message, sessionID string, sink StreamSink) error {
		_, identifier := DetectPlanRequest(message)
		if identifier == "help" {
			var templateNames []string
			if executor != nil {
				templateNames = executor.Planner().ListTemplates()
			}
			helpMsg := "可用模板: " + strings.Join(templateNames, ", ")
			helpMsg += "\n\n使用示例: /plan slow_query_analysis"
			if sink != nil {
				sink(Event{
					Type:    EventPlanStart,
					PlanID:  "help",
					Message: helpMsg,
				})
			}
			return nil
		}
		if executor == nil {
			return fmt.Errorf("plan: no executor configured")
		}
		return executor.ExecutePrompt(ctx, identifier, sessionID, sink)
	}
}

// NewRequest creates an agentsdk-go api.Request from a node's prompt and plan context.
func NewRequest(node *Node, planCtx map[string]string) api.Request {
	return api.Request{
		Prompt:    node.Prompt,
		SessionID: planCtx["session_id"],
	}
}
