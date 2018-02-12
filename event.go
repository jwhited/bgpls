package bgpls

import "time"

// Event is a Collector event associated with a neighbor.
//
// Neighbor() returns the associated neighbor's configuration.
//
// Timestamp() returns the time at which the event occurred.
//
// Type() returns the event type.
type Event interface {
	Neighbor() *NeighborConfig
	Timestamp() time.Time
	Type() EventType
}

// EventType describes the type of event
type EventType int

// EventType values
const (
	_ EventType = iota
	EventTypeNeighborErr
	EventTypeNeighborHoldTimerExpired
	EventTypeNeighborStateTransition
	EventTypeNeighborUpdateReceived
	EventTypeNeighborNotificationReceived
)

func (e EventType) String() string {
	switch e {
	case EventTypeNeighborErr:
		return "neighbor error"
	case EventTypeNeighborHoldTimerExpired:
		return "neighbor hold timer expired"
	case EventTypeNeighborStateTransition:
		return "neighbor state changed"
	case EventTypeNeighborUpdateReceived:
		return "received update message from neighbor"
	case EventTypeNeighborNotificationReceived:
		return "received notification message from neighbor"
	default:
		return "unknown event type"
	}
}

// BaseEvent is included in every Event
type BaseEvent struct {
	t time.Time
	n *NeighborConfig
}

// Timestamp returns the time at which the event occurred
func (b *BaseEvent) Timestamp() time.Time {
	return b.t
}

// Neighbor returns the NeighborConfig associated with the event
func (b *BaseEvent) Neighbor() *NeighborConfig {
	return b.n
}

// EventNeighborErr is generated when a neighbor encounters an error
type EventNeighborErr struct {
	BaseEvent
	Err error
}

// Type returns the appropriate EventType for EventNeighborErr
func (e *EventNeighborErr) Type() EventType {
	return EventTypeNeighborErr
}

func newEventNeighborErr(c *NeighborConfig, err error) Event {
	return &EventNeighborErr{
		BaseEvent: BaseEvent{
			t: time.Now(),
			n: c,
		},
		Err: err,
	}
}

// EventNeighborHoldTimerExpired is generated when a neighbor's hold timer expires
type EventNeighborHoldTimerExpired struct {
	BaseEvent
}

// Type returns the appropriate EventType for EventNeighborHoldTimerExpired
func (e *EventNeighborHoldTimerExpired) Type() EventType {
	return EventTypeNeighborHoldTimerExpired
}

func newEventNeighborHoldTimerExpired(c *NeighborConfig) Event {
	return &EventNeighborHoldTimerExpired{
		BaseEvent: BaseEvent{
			t: time.Now(),
			n: c,
		},
	}
}

// EventNeighborStateTransition is generated when a neighbor's fsm transitions to a new state
type EventNeighborStateTransition struct {
	BaseEvent
	State FSMState
}

// Type returns the appropriate EventType for EventNeighborStateTransition
func (e *EventNeighborStateTransition) Type() EventType {
	return EventTypeNeighborStateTransition
}

func newEventNeighborStateTransition(c *NeighborConfig, s FSMState) Event {
	return &EventNeighborStateTransition{
		BaseEvent: BaseEvent{
			t: time.Now(),
			n: c,
		},
		State: s,
	}
}

// EventNeighborUpdateReceived is generated when an update message is received
type EventNeighborUpdateReceived struct {
	BaseEvent
	Message *UpdateMessage
}

// Type returns the appropriate EventType for EventNeighborUpdateReceived
func (e *EventNeighborUpdateReceived) Type() EventType {
	return EventTypeNeighborUpdateReceived
}

func newEventNeighborUpdateReceived(c *NeighborConfig, u *UpdateMessage) Event {
	return &EventNeighborUpdateReceived{
		BaseEvent: BaseEvent{
			t: time.Now(),
			n: c,
		},
		Message: u,
	}
}

// EventNeighborNotificationReceived is generated when a notification message is received
type EventNeighborNotificationReceived struct {
	BaseEvent
	Message *NotificationMessage
}

// Type returns the appropriate EventType for EventNeighborNotificationReceived
func (e *EventNeighborNotificationReceived) Type() EventType {
	return EventTypeNeighborNotificationReceived
}

func newEventNeighborNotificationReceived(c *NeighborConfig, n *NotificationMessage) Event {
	return &EventNeighborNotificationReceived{
		BaseEvent: BaseEvent{
			t: time.Now(),
			n: c,
		},
		Message: n,
	}
}
