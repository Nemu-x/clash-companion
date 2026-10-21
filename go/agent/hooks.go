// Package agent implements the clashctl gateway server — the only surface exposed
// on the LAN (PROTOCOL.md §1.1, §8). App-only operations are delegated to a
// consumer-provided Hooks implementation; whitelist core forwarding (P2) is handled
// by the forwarder package.
package agent

import (
	"context"
	"errors"

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

// Remote-control hooks (PROTOCOL.md §8.6–§8.19). Each interface is optional: the agent
// advertises the matching capability iff Config.Hooks implements it. Every state-changing
// method MUST run the same code path as the equivalent on-device control, so the change is
// persisted and shown in the consumer's own UI.
//
// Hooks report "no such group/node/profile/…" by returning an error wrapping ErrNotFound and
// a rejected value by wrapping ErrInvalid; any other error is reported as core_unavailable.
// The agent validates the documented request shape before calling a hook.

// ProxyLister lists policy groups (capability "proxies").
type ProxyLister interface {
	ProxyGroups(ctx context.Context) ([]protocol.ProxyGroup, error)
}

// ProxySelector selects a node in a group (capability "select"). It returns the group's
// resulting current node.
type ProxySelector interface {
	SelectProxy(ctx context.Context, group, node string) (now string, err error)
}

// ProxyUnfixer clears the pinned node of an automatic group (capability "unfix").
type ProxyUnfixer interface {
	UnfixProxy(ctx context.Context, group string) (now string, err error)
}

// DelayTester runs a delay test on one node or a whole group (capability "delay").
// req.Timeout is already resolved to a value in [MinDelayTimeout, MaxDelayTimeout].
type DelayTester interface {
	TestDelay(ctx context.Context, req protocol.DelayRequest) ([]protocol.Delay, error)
}

// ModeController reads and sets the tunnel mode (capability "mode").
type ModeController interface {
	Mode(ctx context.Context) (protocol.ModeState, error)
	SetMode(ctx context.Context, mode string) (string, error)
}

// ProfileLister lists and switches profiles (capability "profiles").
type ProfileLister interface {
	Profiles(ctx context.Context) (protocol.ProfileList, error)
	SelectProfile(ctx context.Context, id string) (active string, err error)
}

// ProfileUpdater refreshes a remote profile from its URL, or all when id is ""
// (capability "profile_update").
type ProfileUpdater interface {
	UpdateProfile(ctx context.Context, id string) error
}

// ProfileDeleter deletes a profile (capability "profile_delete").
type ProfileDeleter interface {
	DeleteProfile(ctx context.Context, id string) error
}

// ProviderController lists, updates and health-checks providers (capability "providers").
type ProviderController interface {
	Providers(ctx context.Context) ([]protocol.Provider, error)
	UpdateProvider(ctx context.Context, kind, name string) error
	HealthCheckProvider(ctx context.Context, name string) error
}

// ConnectionController lists and closes connections (capability "connections").
// CloseConnections closes one connection, or all when id is "", and returns how many closed.
type ConnectionController interface {
	Connections(ctx context.Context) (protocol.ConnectionList, error)
	CloseConnections(ctx context.Context, id string) (int, error)
}

// TrafficReporter reports a traffic snapshot (capability "traffic").
type TrafficReporter interface {
	Traffic(ctx context.Context) (protocol.Traffic, error)
}

// LogReader returns up to limit recent log lines at level or more severe, oldest first
// (capability "logs"). level is "" (all) or one of protocol.LogLevels.
type LogReader interface {
	Logs(ctx context.Context, level string, limit int) ([]protocol.LogLine, error)
}

// SettingsController lists and changes typed settings (capability "settings"). The agent
// checks value against the setting's type and options before calling SetSetting.
type SettingsController interface {
	Settings(ctx context.Context) ([]protocol.Setting, error)
	SetSetting(ctx context.Context, key string, value any) (protocol.Setting, error)
}

// ActionRunner lists and runs one-shot actions (capability "actions").
type ActionRunner interface {
	Actions(ctx context.Context) ([]protocol.Action, error)
	RunAction(ctx context.Context, id string) error
}

// Summarizer fills the optional summary in GET /v1/status (PROTOCOL.md §8.1). An error or
// an empty Summary just omits it.
type Summarizer interface {
	Summary(ctx context.Context) (protocol.Summary, error)
}

// Sentinel errors hooks wrap to select the reported error code.
var (
	ErrNotFound = errors.New("not found")       // → not_found (404)
	ErrInvalid  = errors.New("invalid request") // → bad_request (400)
)

// Confirmer optionally gates a controller's first connect on agent-screen confirmation
// (PROTOCOL.md §6.5). If an Agent has no Confirmer, confirmation is treated as granted.
type Confirmer interface {
	// ConfirmConnect returns true if the user confirms control for the device on the
	// agent's screen. It may block until the user responds.
	ConfirmConnect(ctx context.Context, deviceID, name string) bool
}
