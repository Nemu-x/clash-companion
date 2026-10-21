package agent

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// Event stream tuning (PROTOCOL.md §9.2).
const (
	heartbeatInterval = 15 * time.Second // comment ping; also re-checks the token
	trafficInterval   = time.Second
	subscriberBuffer  = 64 // a subscriber this far behind is disconnected
	notifyTimeout     = 5 * time.Second
)

// sseFrame is one encoded server-sent event, ready to write.
type sseFrame struct {
	kind string // protocol.Event*
	line protocol.LogLine
	data []byte
}

func frame(kind string, v any) (sseFrame, error) {
	b, err := canonjson.Marshal(v)
	if err != nil {
		return sseFrame{}, err
	}
	return sseFrame{kind: kind, data: []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", kind, b))}, nil
}

type subscriber struct {
	deviceID string
	logLevel int // -1 = logs not requested; otherwise minimum severity index
	ch       chan sseFrame
	done     chan struct{}
	once     sync.Once
}

func (s *subscriber) drop() { s.once.Do(func() { close(s.done) }) }

// wants reports whether the subscriber asked for this frame.
func (s *subscriber) wants(f sseFrame) bool {
	if f.kind != protocol.EventLog {
		return true
	}
	return s.logLevel >= 0 && severity(f.line.Level) >= s.logLevel
}

// severity ranks a log level: error=3 … debug=0. Unknown levels rank as error so they
// are never filtered out.
func severity(level string) int {
	i := slices.Index(protocol.LogLevels, level) // error, warning, info, debug
	if i < 0 {
		return len(protocol.LogLevels) - 1
	}
	return len(protocol.LogLevels) - 1 - i
}

// hub fans events out to the connected /v1/events streams.
type hub struct {
	mu   sync.Mutex
	subs map[*subscriber]struct{}
}

func newHub() *hub { return &hub{subs: map[*subscriber]struct{}{}} }

func (h *hub) add(s *subscriber) {
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(s *subscriber) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

// broadcast never blocks: a subscriber whose buffer is full is disconnected and will
// reconnect and refetch.
func (h *hub) broadcast(f sseFrame) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if !s.wants(f) {
			continue
		}
		select {
		case s.ch <- f:
		default:
			s.drop()
		}
	}
}

// dropDevice ends every stream of an unpaired controller.
func (h *hub) dropDevice(deviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.deviceID == deviceID {
			s.drop()
		}
	}
}

// Notify tells connected controllers something changed (PROTOCOL.md §9.2). Pass
// protocol.EventStatus to push a fresh status, or protocol.Resource* names to make
// controllers refetch those resources. The agent already notifies after changes made
// through the gateway; consumers MUST call Notify for changes made on the device itself
// (e.g. the user picked a node on the TV), so every controller stays in sync.
func (a *Agent) Notify(what ...string) {
	for _, w := range what {
		var f sseFrame
		var err error
		if w == protocol.EventStatus {
			ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
			var st protocol.Status
			st, err = a.status(ctx)
			cancel()
			if err == nil {
				f, err = frame(protocol.EventStatus, st)
			}
		} else {
			f, err = frame(protocol.EventChanged, protocol.Changed{Resource: w})
		}
		if err == nil {
			a.events.broadcast(f)
		}
	}
}

// PublishLog streams one log line to controllers subscribed to the "logs" topic.
func (a *Agent) PublishLog(line protocol.LogLine) {
	f, err := frame(protocol.EventLog, line)
	if err != nil {
		return
	}
	f.line = line
	a.events.broadcast(f)
}

// handleEvents serves GET /v1/events as a server-sent event stream (PROTOCOL.md §9.2).
func (a *Agent) handleEvents(w http.ResponseWriter, r *http.Request, e pairing.Entry) {
	q := r.URL.Query()
	var traffic, logs bool
	for _, t := range strings.Split(q.Get("topics"), ",") {
		switch strings.TrimSpace(t) {
		case protocol.TopicTraffic:
			traffic = true
		case protocol.TopicLogs:
			logs = true
		}
	}
	level := q.Get("level")
	if level != "" && !slices.Contains(protocol.LogLevels, level) {
		badRequest(w, "level must be one of "+strings.Join(protocol.LogLevels, ", "))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, protocol.CodeInternal, "streaming unsupported")
		return
	}
	ctx := r.Context()
	st, err := a.status(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, err.Error())
		return
	}
	first, err := frame(protocol.EventStatus, st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, protocol.CodeInternal, "encode error")
		return
	}

	sub := &subscriber{deviceID: e.DeviceID, logLevel: -1, ch: make(chan sseFrame, subscriberBuffer), done: make(chan struct{})}
	if logs {
		sub.logLevel = 0
		if level != "" {
			sub.logLevel = severity(level)
		}
	}
	a.events.add(sub)
	defer a.events.remove(sub)

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	write := func(b []byte) bool {
		if _, err := w.Write(b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !write(first.data) {
		return
	}

	token, _ := bearer(r)
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	var trafficTick <-chan time.Time
	tr, hasTraffic := a.cfg.Hooks.(TrafficReporter)
	if traffic && hasTraffic && slices.Contains(a.remote, protocol.CapTraffic) {
		t := time.NewTicker(trafficInterval)
		defer t.Stop()
		trafficTick = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.done:
			return
		case f := <-sub.ch:
			if !write(f.data) {
				return
			}
		case <-heartbeat.C:
			if _, ok := a.cfg.Store.Authenticate(token); !ok {
				return // revoked on the agent while streaming
			}
			if !write([]byte(": ping\n\n")) {
				return
			}
		case <-trafficTick:
			t, err := tr.Traffic(ctx)
			if err != nil {
				continue
			}
			if f, err := frame(protocol.EventTraffic, t); err == nil && !write(f.data) {
				return
			}
		}
	}
}
