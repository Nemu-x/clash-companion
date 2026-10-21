// Package protocol defines the clashctl v1 wire types and constants shared by the
// agent and controller, per PROTOCOL.md §5 and §8.
package protocol

// Major is the protocol major version (PROTOCOL.md §10).
const Major = 1

// Service is the mDNS service type (PROTOCOL.md §4.1).
const Service = "_clashctl._tcp"

// Capability tags advertised in GET /v1/status (PROTOCOL.md §8.3).
const (
	CapStatus       = "status"
	CapPower        = "power"
	CapSubscription = "subscription"
	CapRename       = "rename"
	CapUnpair       = "unpair" // POST /v1/unpair (§7.4)
	CapCore         = "core"   // P2: /v1/core/*
	CapEvents       = "events" // P2: GET /v1/events (§9.2)
)

// Power states.
const (
	PowerOn  = "on"
	PowerOff = "off"
)

// Error codes (PROTOCOL.md §5.5).
const (
	CodeBadRequest         = "bad_request"
	CodeUnauthorized       = "unauthorized"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeVersionUnsupported = "version_unsupported"
	CodePinInvalid         = "pin_invalid"
	CodePinRateLimited     = "pin_rate_limited"
	CodeCoreUnavailable    = "core_unavailable"
	CodeInternal           = "internal"
)

// Error is the uniform error envelope (PROTOCOL.md §5.4/§5.5).
type Error struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is the inner error object.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Status is the GET /v1/status response (PROTOCOL.md §8.1).
type Status struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	App          string   `json:"app"`
	Ver          int      `json:"ver"`
	Power        string   `json:"power"`
	Capabilities []string `json:"capabilities"`
	Summary      *Summary `json:"summary,omitempty"`
}

// Summary is the optional at-a-glance state in GET /v1/status (PROTOCOL.md §8.1), so a
// controller's home screen needs one call. Every field is optional and omitted when empty.
type Summary struct {
	Mode        string `json:"mode,omitempty"`        // tunnel mode (§8.10)
	Profile     string `json:"profile,omitempty"`     // active profile display name
	Proxy       string `json:"proxy,omitempty"`       // node currently carrying traffic, as the app shows it
	AppVersion  string `json:"appVersion,omitempty"`  // consumer app version
	CoreVersion string `json:"coreVersion,omitempty"` // core version, e.g. "v1.19.32"
}

// PowerRequest is the POST /v1/power body (PROTOCOL.md §8.2).
type PowerRequest struct {
	Action string `json:"action"` // "on" | "off" | "toggle"
}

// PowerResponse is the POST /v1/power response.
type PowerResponse struct {
	OK    bool   `json:"ok"`
	Power string `json:"power"`
}

// SubscriptionRequest is the POST /v1/subscription body (PROTOCOL.md §8.4).
// Exactly one of URL or Payload must be set.
type SubscriptionRequest struct {
	URL     string `json:"url,omitempty"`
	Payload string `json:"payload,omitempty"`
	Name    string `json:"name"`
}

// OKResponse is a minimal success envelope.
type OKResponse struct {
	OK bool `json:"ok"`
}

// RenameRequest is the POST /v1/rename body (PROTOCOL.md §8.5).
type RenameRequest struct {
	Name string `json:"name"`
}

// RenameResponse is the POST /v1/rename response.
type RenameResponse struct {
	OK   bool   `json:"ok"`
	Name string `json:"name"`
}

// PairRequest is the POST /v1/pair body for PIN-assisted pairing (PROTOCOL.md §6.4).
type PairRequest struct {
	PIN    string     `json:"pin"`
	Device PairDevice `json:"device"`
}

// PairDevice identifies the controller requesting a pairing.
type PairDevice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PairResponse is the POST /v1/pair response.
type PairResponse struct {
	OK    bool   `json:"ok"`
	Token string `json:"token"`
}
