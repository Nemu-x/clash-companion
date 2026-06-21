package agent_test

import (
	"context"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Nemu-x/clash-companion/go/agent"
	"github.com/Nemu-x/clash-companion/go/controller"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// fakeHooks is a test consumer implementation of agent.Hooks.
type fakeHooks struct {
	mu    sync.Mutex
	power string
	subs  []protocol.SubscriptionRequest
}

func (h *fakeHooks) PowerState(context.Context) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.power == "" {
		return protocol.PowerOff, nil
	}
	return h.power, nil
}

func (h *fakeHooks) Power(_ context.Context, action string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch action {
	case "on":
		h.power = protocol.PowerOn
	case "off":
		h.power = protocol.PowerOff
	case "toggle":
		if h.power == protocol.PowerOn {
			h.power = protocol.PowerOff
		} else {
			h.power = protocol.PowerOn
		}
	}
	return h.power, nil
}

func (h *fakeHooks) ImportSubscription(_ context.Context, req protocol.SubscriptionRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs = append(h.subs, req)
	return nil
}

// newTestAgent spins up an agent over real pinned TLS and returns the fingerprint,
// host, port, the pairing store, and the hooks.
func newTestAgent(t *testing.T, cfgMut func(*agent.Config)) (fp, host string, port int, store *pairing.Store, hooks *fakeHooks) {
	t.Helper()
	id, err := pairing.NewIdentity("clashctl-agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store = pairing.NewStore()
	hooks = &fakeHooks{}
	cfg := agent.Config{
		App: "slothclash", DeviceID: "dev-agent-1", Name: "Living Room TV",
		Identity: id, Store: store, Hooks: hooks,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	a, err := agent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(a.Handler())
	tlsCfg, err := a.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	u := srv.Listener.Addr().(*net.TCPAddr)
	return id.FP, "127.0.0.1", u.Port, store, hooks
}

func TestEndToEndP1(t *testing.T) {
	fp, host, port, store, hooks := newTestAgent(t, nil)
	token, err := store.Pair("dev-ctrl-1", "My Phone")
	if err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(host, port, fp, token)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// status
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != "dev-agent-1" || st.App != "slothclash" || st.Ver != protocol.Major {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Power != protocol.PowerOff {
		t.Fatalf("initial power = %q, want off", st.Power)
	}

	// power on
	pr, err := c.Power(ctx, "on")
	if err != nil {
		t.Fatal(err)
	}
	if !pr.OK || pr.Power != protocol.PowerOn {
		t.Fatalf("power on: %+v", pr)
	}

	// toggle -> off
	pr, _ = c.Power(ctx, "toggle")
	if pr.Power != protocol.PowerOff {
		t.Fatalf("toggle power = %q, want off", pr.Power)
	}

	// subscription
	if err := c.ImportSubscription(ctx, protocol.SubscriptionRequest{URL: "https://example/sub", Name: "Home"}); err != nil {
		t.Fatal(err)
	}
	if len(hooks.subs) != 1 || hooks.subs[0].URL != "https://example/sub" {
		t.Fatalf("subscription not imported: %+v", hooks.subs)
	}

	// rename
	rr, err := c.Rename(ctx, "Bedroom TV")
	if err != nil {
		t.Fatal(err)
	}
	if rr.Name != "Bedroom TV" {
		t.Fatalf("rename: %+v", rr)
	}
}

func TestInvalidPowerAction(t *testing.T) {
	fp, host, port, store, _ := newTestAgent(t, nil)
	token, _ := store.Pair("dev-ctrl-1", "Phone")
	c, _ := controller.New(host, port, fp, token)
	_, err := c.Power(context.Background(), "explode")
	assertAPIError(t, err, protocol.CodeBadRequest)
}

func TestSubscriptionValidation(t *testing.T) {
	fp, host, port, store, _ := newTestAgent(t, nil)
	token, _ := store.Pair("dev-ctrl-1", "Phone")
	c, _ := controller.New(host, port, fp, token)
	err := c.ImportSubscription(context.Background(), protocol.SubscriptionRequest{Name: "X"})
	assertAPIError(t, err, protocol.CodeBadRequest)
}

func TestUnauthorizedAndRevoked(t *testing.T) {
	fp, host, port, store, _ := newTestAgent(t, nil)
	token, _ := store.Pair("dev-ctrl-1", "Phone")

	// Wrong token -> unauthorized.
	bad, _ := controller.New(host, port, fp, "not-a-real-token")
	_, err := bad.Status(context.Background())
	assertAPIError(t, err, protocol.CodeUnauthorized)

	// Valid token works, then revoke -> unauthorized.
	good, _ := controller.New(host, port, fp, token)
	if _, err := good.Status(context.Background()); err != nil {
		t.Fatalf("valid token should work: %v", err)
	}
	if _, err := store.Revoke("dev-ctrl-1"); err != nil {
		t.Fatal(err)
	}
	_, err = good.Status(context.Background())
	assertAPIError(t, err, protocol.CodeUnauthorized)
}

func TestPinMismatchAborts(t *testing.T) {
	_, host, port, store, _ := newTestAgent(t, nil)
	token, _ := store.Pair("dev-ctrl-1", "Phone")
	// A fingerprint that does not match the served cert.
	wrongFP := "00000000000000000000000000000000000000000000000000000000000000ff"
	c, err := controller.New(host, port, wrongFP, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("expected pin mismatch to abort the connection")
	}
}

func TestPINPairingFlow(t *testing.T) {
	pin := agent.NewPINManager(time.Minute, 5)
	fp, host, port, store, _ := newTestAgent(t, func(c *agent.Config) { c.PIN = pin })

	code, err := pin.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Wrong PIN is refused.
	if _, err := controller.PairWithPIN(ctx, host, port, fp, "999999", "dev-ctrl-1", "Phone"); err == nil {
		t.Fatal("expected wrong pin to fail")
	}

	// Correct PIN issues a token usable for control.
	code, _ = pin.Generate()
	token, err := controller.PairWithPIN(ctx, host, port, fp, code, "dev-ctrl-1", "Phone")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if _, ok := store.Authenticate(token); !ok {
		t.Fatal("issued token must authenticate")
	}
	c, _ := controller.New(host, port, fp, token)
	if _, err := c.Status(ctx); err != nil {
		t.Fatalf("status after pin pairing: %v", err)
	}
	_ = code
}

func TestConfirmFirstConnect(t *testing.T) {
	var calls int
	conf := confirmerFunc(func(context.Context, string, string) bool { calls++; return true })
	fp, host, port, store, _ := newTestAgent(t, func(c *agent.Config) {
		c.RequireConfirmFirstConnect = true
		c.Confirmer = conf
	})
	token, _ := store.Pair("dev-ctrl-1", "Phone")
	c, _ := controller.New(host, port, fp, token)
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second call should not prompt again (already confirmed).
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("confirm called %d times, want 1", calls)
	}
}

func TestConfirmDenied(t *testing.T) {
	conf := confirmerFunc(func(context.Context, string, string) bool { return false })
	fp, host, port, store, _ := newTestAgent(t, func(c *agent.Config) {
		c.RequireConfirmFirstConnect = true
		c.Confirmer = conf
	})
	token, _ := store.Pair("dev-ctrl-1", "Phone")
	c, _ := controller.New(host, port, fp, token)
	_, err := c.Status(context.Background())
	assertAPIError(t, err, protocol.CodeForbidden)
}

type confirmerFunc func(ctx context.Context, deviceID, name string) bool

func (f confirmerFunc) ConfirmConnect(ctx context.Context, deviceID, name string) bool {
	return f(ctx, deviceID, name)
}

func assertAPIError(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", code)
	}
	apiErr, ok := err.(*controller.APIError)
	if !ok {
		t.Fatalf("expected *controller.APIError, got %T: %v", err, err)
	}
	if apiErr.Code != code {
		t.Fatalf("error code = %q, want %q", apiErr.Code, code)
	}
}
