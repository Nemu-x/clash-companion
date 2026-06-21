// Package agent implements the clashctl gateway server — the only surface exposed
// on the LAN (PROTOCOL.md §1.1, §8). App-only operations are delegated to a
// consumer-provided Hooks implementation; whitelist core forwarding (P2) is handled
// by the forwarder package.
package agent

import (
	"context"

	"github.com/Nemu-x/clash-companion/go/protocol"
)

// Hooks are the platform actions the core cannot perform, supplied by the consumer
// (PROTOCOL.md §8). A consumer (ClashFest, SlothClash) implements these against its
// own platform (VpnService intents, config import, etc.).
type Hooks interface {
	// PowerState reports the current tunnel state: protocol.PowerOn or PowerOff.
	PowerState(ctx context.Context) (string, error)
	// Power applies an action ("on" | "off" | "toggle") and returns the resulting state.
	Power(ctx context.Context, action string) (string, error)
	// ImportSubscription imports a subscription by URL or inline payload.
	ImportSubscription(ctx context.Context, req protocol.SubscriptionRequest) error
}

// Confirmer optionally gates a controller's first connect on agent-screen confirmation
// (PROTOCOL.md §6.5). If an Agent has no Confirmer, confirmation is treated as granted.
type Confirmer interface {
	// ConfirmConnect returns true if the user confirms control for the device on the
	// agent's screen. It may block until the user responds.
	ConfirmConnect(ctx context.Context, deviceID, name string) bool
}
