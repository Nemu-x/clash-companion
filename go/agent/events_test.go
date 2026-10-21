package agent_test

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nemu-x/clash-companion/go/agent"
	"github.com/Nemu-x/clash-companion/go/controller"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// summaryHooks adds a Summarizer to fullHooks.
type summaryHooks struct {
	*fullHooks
	fail bool
}

func (h *summaryHooks) Summary(context.Context) (protocol.Summary, error) {
	if h.fail {
		return protocol.Summary{}, errors.New("no summary")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return protocol.Summary{Mode: h.mode, Proxy: h.groups[0].Now, AppVersion: "1.2.3"}, nil
}

func TestStatusSummary(t *testing.T) {
	ctx := context.Background()
	sh := &summaryHooks{fullHooks: newFullHooks()}
	c, _ := newFullClient(t, func(cfg *agent.Config) { cfg.Hooks = sh })

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Summary == nil || *st.Summary != (protocol.Summary{Mode: "rule", Proxy: "HK-01", AppVersion: "1.2.3"}) {
		t.Fatalf("summary = %+v", st.Summary)
	}

	// A failing summarizer drops the optional summary but never fails status.
	sh.fail = true
	st, err = c.Status(ctx)
	if err != nil || st.Summary != nil {
		t.Fatalf("failing summary: %+v %v", st.Summary, err)
	}

	// Without a Summarizer there is no summary at all.
	c2, _ := newFullClient(t, nil)
	if st, err := c2.Status(ctx); err != nil || st.Summary != nil {
		t.Fatalf("no summarizer: %+v %v", st, err)
	}
}

func TestUnpairSelf(t *testing.T) {
	ctx := context.Background()
	fp, host, port, store, _ := newTestAgent(t, func(c *agent.Config) {
		c.RequireConfirmFirstConnect = true
		c.Confirmer = denyAll{} // unpair must not need confirmation
	})
	tokA, _ := store.Pair("ctrl-a", "A")
	tokB, _ := store.Pair("ctrl-b", "B")
	_ = store.Confirm("ctrl-b")
	a, _ := controller.New(host, port, fp, tokA)
	b, _ := controller.New(host, port, fp, tokB)

	if err := a.Unpair(ctx); err != nil {
		t.Fatalf("unpair: %v", err)
	}
	_, err := a.Status(ctx)
	wantAPIError(t, err, 401, protocol.CodeUnauthorized)
	if _, err := b.Status(ctx); err != nil {
		t.Fatalf("other controller must keep working: %v", err)
	}
}

type denyAll struct{}

func (denyAll) ConfirmConnect(context.Context, string, string) bool { return false }

// collect runs c.Events in the background and returns a channel of events.
func collect(t *testing.T, c *controller.Client, opts controller.EventOptions) (<-chan controller.Event, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	evs := make(chan controller.Event, 64)
	done := make(chan error, 1)
	go func() { done <- c.Events(ctx, opts, func(e controller.Event) { evs <- e }) }()
	t.Cleanup(cancel)
	return evs, done, cancel
}

func next(t *testing.T, evs <-chan controller.Event, typ string) controller.Event {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-evs:
			if e.Type == typ {
				return e
			}
		case <-deadline:
			t.Fatalf("no %q event within 3s", typ)
		}
	}
}

func TestEventsStatusChangedTrafficLogs(t *testing.T) {
	ctx := context.Background()
	h := newFullHooks()
	var ag *agent.Agent
	fp, host, port, store, _ := newTestAgentCapture(t, h, &ag)
	tok1, _ := store.Pair("ctrl-1", "Watcher")
	tok2, _ := store.Pair("ctrl-2", "Actor")
	watcher, _ := controller.New(host, port, fp, tok1)
	actor, _ := controller.New(host, port, fp, tok2)

	evs, _, _ := collect(t, watcher, controller.EventOptions{Traffic: true, Logs: true, LogLevel: "warning"})

	// First frame is the full status.
	st, err := next(t, evs, protocol.EventStatus).Status()
	if err != nil || st.ID != "dev-agent-1" {
		t.Fatalf("initial status: %+v %v", st, err)
	}

	// A change made by another controller reaches the watcher.
	if _, err := actor.SelectProxy(ctx, "Proxy", "JP-01"); err != nil {
		t.Fatal(err)
	}
	ch, err := next(t, evs, protocol.EventChanged).Changed()
	if err != nil || ch.Resource != protocol.ResourceProxies {
		t.Fatalf("changed: %+v %v", ch, err)
	}

	// A change made on the device itself is pushed via Notify.
	ag.Notify(protocol.ResourceSettings)
	for {
		ch, _ := next(t, evs, protocol.EventChanged).Changed()
		if ch.Resource == protocol.ResourceSettings {
			break
		}
	}

	// Power change pushes a fresh status.
	if _, err := actor.Power(ctx, "on"); err != nil {
		t.Fatal(err)
	}
	for {
		st, _ := next(t, evs, protocol.EventStatus).Status()
		if st.Power == protocol.PowerOn {
			break
		}
	}

	// Traffic ticks about once a second.
	tr, err := next(t, evs, protocol.EventTraffic).Traffic()
	if err != nil || tr.Down != 20 {
		t.Fatalf("traffic: %+v %v", tr, err)
	}

	// Logs below the requested level are filtered.
	ag.PublishLog(protocol.LogLine{Time: 1, Level: "info", Msg: "skip me"})
	ag.PublishLog(protocol.LogLine{Time: 2, Level: "error", Msg: "boom"})
	l, err := next(t, evs, protocol.EventLog).Log()
	if err != nil || l.Msg != "boom" {
		t.Fatalf("log: %+v %v", l, err)
	}
}

func TestEventsEndOnUnpair(t *testing.T) {
	h := newFullHooks()
	var ag *agent.Agent
	fp, host, port, store, _ := newTestAgentCapture(t, h, &ag)
	tok, _ := store.Pair("ctrl-1", "Phone")
	c, _ := controller.New(host, port, fp, tok)

	evs, done, _ := collect(t, c, controller.EventOptions{})
	next(t, evs, protocol.EventStatus)
	if err := c.Unpair(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stream must end when its controller unpairs")
	}
}

func TestEventsBadLevelAndUnauthorized(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _ := newFullClient(t, nil)
	err := c.Events(ctx, controller.EventOptions{Logs: true, LogLevel: "trace"}, func(controller.Event) {})
	wantAPIError(t, err, 400, protocol.CodeBadRequest)

	fp, host, port, _, _ := newTestAgent(t, nil)
	bad, _ := controller.New(host, port, fp, "not-a-token")
	err = bad.Events(ctx, controller.EventOptions{}, func(controller.Event) {})
	wantAPIError(t, err, 401, protocol.CodeUnauthorized)
}

// newTestAgentCapture is newTestAgent with the given hooks, also returning the Agent so
// tests can call Notify/PublishLog.
func newTestAgentCapture(t *testing.T, hooks agent.Hooks, out **agent.Agent) (fp, host string, port int, store *pairing.Store, _ struct{}) {
	t.Helper()
	id, err := pairing.NewIdentity("clashctl-agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store = pairing.NewStore()
	a, err := agent.New(agent.Config{
		App: "slothclash", DeviceID: "dev-agent-1", Name: "Living Room TV",
		Identity: id, Store: store, Hooks: hooks,
	})
	if err != nil {
		t.Fatal(err)
	}
	*out = a
	srv := httptest.NewUnstartedServer(a.Handler())
	if srv.TLS, err = a.TLSConfig(); err != nil {
		t.Fatal(err)
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return id.FP, "127.0.0.1", srv.Listener.Addr().(*net.TCPAddr).Port, store, struct{}{}
}
