package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// Config configures an Agent gateway.
type Config struct {
	App       string            // consumer app id (e.g. "slothclash")
	DeviceID  string            // stable deviceId (PROTOCOL.md §3.1)
	Name      string            // initial display name
	Identity  *pairing.Identity // pinned TLS identity (PROTOCOL.md §5.1)
	Store     *pairing.Store    // pairing store
	Hooks     Hooks             // consumer platform hooks (required)
	Confirmer Confirmer         // optional first-connect confirmation (PROTOCOL.md §6.5)
	PIN       *PINManager       // optional; enables POST /v1/pair (PROTOCOL.md §6.4)
	Forwarder http.Handler      // optional; mounts /v1/core/* (P2, PROTOCOL.md §9.1)
	Events    http.Handler      // optional; mounts WS /v1/events (P2, PROTOCOL.md §9.2)

	// RequireConfirmFirstConnect gates QR/paste pairings on agent-screen confirmation.
	// The PIN flow always confirms regardless of this setting.
	RequireConfirmFirstConnect bool

	// OnRename, if set, is called after a successful rename so the consumer can
	// re-announce over mDNS (PROTOCOL.md §8.5).
	OnRename func(name string)
}

// Agent is a clashctl gateway.
type Agent struct {
	cfg  Config
	mu   sync.RWMutex
	name string
}

// New validates cfg and returns an Agent.
func New(cfg Config) (*Agent, error) {
	if cfg.App == "" || cfg.DeviceID == "" || cfg.Identity == nil || cfg.Store == nil || cfg.Hooks == nil {
		return nil, errors.New("agent: App, DeviceID, Identity, Store and Hooks are required")
	}
	return &Agent{cfg: cfg, name: cfg.Name}, nil
}

// Capabilities returns the advertised capability set (PROTOCOL.md §8.3).
func (a *Agent) Capabilities() []string {
	caps := []string{protocol.CapStatus, protocol.CapPower, protocol.CapSubscription, protocol.CapRename}
	if a.cfg.Forwarder != nil {
		caps = append(caps, protocol.CapCore)
	}
	if a.cfg.Events != nil {
		caps = append(caps, protocol.CapEvents)
	}
	return caps
}

// Name returns the current display name.
func (a *Agent) Name() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.name
}

// TLSConfig returns a *tls.Config serving the agent's pinned certificate.
func (a *Agent) TLSConfig() (*tls.Config, error) {
	cert, err := a.cfg.Identity.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// Handler returns the gateway's HTTP handler (PROTOCOL.md §8, §9).
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pair", a.handlePair)
	mux.Handle("GET /v1/status", a.auth(a.handleStatus))
	mux.Handle("POST /v1/power", a.auth(a.handlePower))
	mux.Handle("POST /v1/subscription", a.auth(a.handleSubscription))
	mux.Handle("POST /v1/rename", a.auth(a.handleRename))
	if a.cfg.Forwarder != nil {
		mux.Handle("/v1/core/", a.auth(func(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
			a.cfg.Forwarder.ServeHTTP(w, r)
		}))
	}
	if a.cfg.Events != nil {
		mux.Handle("/v1/events", a.auth(func(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
			a.cfg.Events.ServeHTTP(w, r)
		}))
	}
	return mux
}

type authHandler func(w http.ResponseWriter, r *http.Request, e pairing.Entry)

// auth enforces bearer authorization and first-connect confirmation (PROTOCOL.md §5.2, §6.5).
func (a *Agent) auth(next authHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "missing bearer token")
			return
		}
		entry, ok := a.cfg.Store.Authenticate(token)
		if !ok {
			writeError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "invalid or revoked token")
			return
		}
		if a.cfg.RequireConfirmFirstConnect && !entry.Confirmed {
			if !a.confirm(r.Context(), entry) {
				writeError(w, http.StatusForbidden, protocol.CodeForbidden, "connection not confirmed on agent")
				return
			}
		}
		next(w, r, entry)
	})
}

func (a *Agent) confirm(ctx context.Context, e pairing.Entry) bool {
	if a.cfg.Confirmer != nil && !a.cfg.Confirmer.ConfirmConnect(ctx, e.DeviceID, e.Name) {
		return false
	}
	_ = a.cfg.Store.Confirm(e.DeviceID)
	return true
}

func (a *Agent) handleStatus(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	power, err := a.cfg.Hooks.PowerState(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.Status{
		ID:           a.cfg.DeviceID,
		Name:         a.Name(),
		App:          a.cfg.App,
		Ver:          protocol.Major,
		Power:        power,
		Capabilities: a.Capabilities(),
	})
}

func (a *Agent) handlePower(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.PowerRequest
	if !decode(w, r, &req) {
		return
	}
	switch req.Action {
	case "on", "off", "toggle":
	default:
		writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, "action must be on, off or toggle")
		return
	}
	state, err := a.cfg.Hooks.Power(r.Context(), req.Action)
	if err != nil {
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.PowerResponse{OK: true, Power: state})
}

func (a *Agent) handleSubscription(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.SubscriptionRequest
	if !decode(w, r, &req) {
		return
	}
	if (req.URL == "") == (req.Payload == "") {
		writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, "exactly one of url or payload is required")
		return
	}
	if err := a.cfg.Hooks.ImportSubscription(r.Context(), req); err != nil {
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.OKResponse{OK: true})
}

func (a *Agent) handleRename(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.RenameRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, "name must not be empty")
		return
	}
	a.mu.Lock()
	a.name = req.Name
	a.mu.Unlock()
	if a.cfg.OnRename != nil {
		a.cfg.OnRename(req.Name)
	}
	writeJSON(w, http.StatusOK, protocol.RenameResponse{OK: true, Name: req.Name})
}

// handlePair implements PIN-assisted pairing (PROTOCOL.md §6.4). It is unauthenticated
// (it issues the token) but PIN-protected, and confirmation is mandatory.
func (a *Agent) handlePair(w http.ResponseWriter, r *http.Request) {
	if a.cfg.PIN == nil {
		writeError(w, http.StatusNotFound, protocol.CodeNotFound, "pin pairing not supported")
		return
	}
	var req protocol.PairRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Device.ID == "" {
		writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, "device.id is required")
		return
	}
	switch a.cfg.PIN.Verify(req.PIN) {
	case PINRateLimited:
		writeError(w, http.StatusTooManyRequests, protocol.CodePinRateLimited, "too many attempts")
		return
	case PINWrong:
		writeError(w, http.StatusForbidden, protocol.CodePinInvalid, "incorrect pin")
		return
	}
	// Confirmation is mandatory for the PIN flow.
	if a.cfg.Confirmer != nil && !a.cfg.Confirmer.ConfirmConnect(r.Context(), req.Device.ID, req.Device.Name) {
		writeError(w, http.StatusForbidden, protocol.CodeForbidden, "connection not confirmed on agent")
		return
	}
	token, err := a.cfg.Store.Pair(req.Device.ID, req.Device.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, protocol.CodeInternal, err.Error())
		return
	}
	_ = a.cfg.Store.Confirm(req.Device.ID)
	writeJSON(w, http.StatusOK, protocol.PairResponse{OK: true, Token: token})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := canonjson.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, protocol.CodeInternal, "encode error")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	b, _ := canonjson.Marshal(protocol.Error{Error: protocol.ErrorBody{Code: code, Message: msg}})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
