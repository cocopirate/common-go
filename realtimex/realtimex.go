// Package realtimex defines the transport-neutral contract between the
// realtime-gateway and business services.
//
// The gateway owns WebSocket connections, authentication, rooms and fanout.
// Business services own domain events and persistence. A client event is
// forwarded to a business dispatcher; the dispatcher returns publish/join/
// leave/close actions that the gateway applies to the connection.
package realtimex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Gateway-generated event names.
const (
	EventReady = "ready"
	EventPing  = "ping"
	EventPong  = "pong"
	EventError = "error"
)

// Target identifies where a gateway publish should go.
type TargetType string

const (
	TargetConnection TargetType = "connection"
	TargetUser       TargetType = "user"
	TargetRoom       TargetType = "room"
)

// Target is one publish destination. User/room IDs are scoped by Tenant;
// connection IDs are globally unique.
type Target struct {
	Type TargetType `json:"type"`
	ID   string     `json:"id"`
}

func (t Target) Validate() error {
	switch t.Type {
	case TargetConnection, TargetUser, TargetRoom:
	default:
		return fmt.Errorf("invalid target type %q", t.Type)
	}
	if strings.TrimSpace(t.ID) == "" {
		return errors.New("target id is required")
	}
	return nil
}

// ClientEvent is the browser -> gateway envelope.
type ClientEvent struct {
	Event     string          `json:"event"`
	RequestID string          `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

func (e ClientEvent) Validate() error {
	if strings.TrimSpace(e.Event) == "" {
		return errors.New("event is required")
	}
	if len(e.Event) > 64 {
		return errors.New("event is too long")
	}
	return nil
}

// ServerEvent is the gateway -> browser envelope.
//
// Data is often a json.RawMessage so business payloads are forwarded without
// a decode/re-encode cycle.
type ServerEvent struct {
	Event     string          `json:"event"`
	RequestID string          `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     *Error          `json:"error,omitempty"`
}

// Error is the gateway error payload. Code is an application code, not an
// HTTP status; business services may use their own ranges.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// DispatchRequest is the gateway -> business-service envelope. Identity is
// derived from the verified auth token, never from client data.
type DispatchRequest struct {
	Tenant       string      `json:"tenant,omitempty"`
	UserID       string      `json:"user_id"`
	ConnectionID string      `json:"connection_id"`
	DeviceID     string      `json:"device_id,omitempty"`
	Event        ClientEvent `json:"event"`
}

// PublishRequest is the business-service -> gateway envelope. It may be sent
// to the gateway's internal publish endpoint or returned as a DispatchAction.
type PublishRequest struct {
	Tenant              string          `json:"tenant,omitempty"`
	Targets             []Target        `json:"targets"`
	Event               string          `json:"event"`
	Data                json.RawMessage `json:"data,omitempty"`
	ExcludeConnectionID string          `json:"exclude_connection_id,omitempty"`
}

func (p PublishRequest) Validate() error {
	if strings.TrimSpace(p.Event) == "" {
		return errors.New("event is required")
	}
	if len(p.Targets) == 0 {
		return errors.New("at least one target is required")
	}
	for i := range p.Targets {
		if err := p.Targets[i].Validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
	}
	return nil
}

// PublishResult reports local deliveries for a synchronous publish. Accepted
// is true when the request was handed to the cross-node bus; Delivered is then
// the local count only.
type PublishResult struct {
	Accepted  bool `json:"accepted"`
	Delivered int  `json:"delivered"`
}

// KickRequest closes matching connections. ConnectionID takes precedence;
// otherwise all connections for Tenant+UserID (optionally DeviceID) are closed.
type KickRequest struct {
	Tenant       string `json:"tenant,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func (k KickRequest) Validate() error {
	if strings.TrimSpace(k.ConnectionID) != "" {
		return nil
	}
	if strings.TrimSpace(k.UserID) == "" {
		return errors.New("connection_id or user_id is required")
	}
	return nil
}

// KickResult reports the number of local connections closed.
type KickResult struct {
	Kicked int `json:"kicked"`
}

// DispatchAction tells the gateway what to do after a business event.
type ActionType string

const (
	ActionPublish ActionType = "publish"
	ActionJoin    ActionType = "join"
	ActionLeave   ActionType = "leave"
	ActionClose   ActionType = "close"
)

type DispatchAction struct {
	Type                ActionType      `json:"type"`
	Target              *Target         `json:"target,omitempty"`
	Rooms               []string        `json:"rooms,omitempty"`
	Event               string          `json:"event,omitempty"`
	Data                json.RawMessage `json:"data,omitempty"`
	ExcludeConnectionID string          `json:"exclude_connection_id,omitempty"`
	Code                int             `json:"code,omitempty"`
	Message             string          `json:"message,omitempty"`
}

// DispatchResult is returned by the business-service dispatcher.
type DispatchResult struct {
	Actions []DispatchAction `json:"actions,omitempty"`
}
