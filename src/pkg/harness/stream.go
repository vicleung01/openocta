package harness

// EventType classifies harness lifecycle events for streaming to UI/IM.
type EventType string

const (
	EventPlanStart   EventType = "plan_start"
	EventPlanComplete EventType = "plan_complete"
	EventNodeStart   EventType = "node_start"
	EventNodeComplete EventType = "node_complete"
	EventNodeBlocked EventType = "node_blocked"
	EventNodeSkip    EventType = "node_skip"
	EventNodeRetry   EventType = "node_retry"
)

// Event is emitted at each harness lifecycle point.
type Event struct {
	Type     EventType `json:"type"`
	PlanID   string    `json:"plan_id,omitempty"`
	PlanName string    `json:"plan_name,omitempty"`
	NodeID   string    `json:"node_id,omitempty"`
	NodeName string    `json:"node_name,omitempty"`
	Status   string    `json:"status,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Message  string    `json:"message,omitempty"`
}

// StreamSink receives harness lifecycle events.
// Implementations can broadcast to WebSocket, write to a log, or aggregate for UI.
type StreamSink func(Event)
