package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nemu-x/clash-companion/go/agent"
	"github.com/Nemu-x/clash-companion/go/controller"
	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/internal/testvectors"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// fullHooks implements every remote-control hook over a small in-memory model.
type fullHooks struct {
	fakeHooks

	mu        sync.Mutex
	groups    []protocol.ProxyGroup
	mode      string
	profiles  protocol.ProfileList
	updated   []string
	deleted   []string
	closed    []string
	settings  []protocol.Setting
	ran       []string
	lastDelay protocol.DelayRequest
	logLevel  string
	logLimit  int
}

func newFullHooks() *fullHooks {
	return &fullHooks{
		groups: []protocol.ProxyGroup{
			{Name: "Proxy", Type: "Selector", Now: "HK-01", Selectable: true, Nodes: []protocol.ProxyNode{
				{Name: "HK-01", Type: "Vless", Delay: 80}, {Name: "JP-01", Type: "Trojan", Delay: 120},
			}},
			{Name: "Auto", Type: "URLTest", Now: "HK-01", Fixed: "JP-01", Selectable: true}, // nil Nodes on purpose
		},
		mode: protocol.ModeRule,
		profiles: protocol.ProfileList{Active: "p-1", Profiles: []protocol.Profile{
			{ID: "p-1", Name: "Main", Type: "remote"}, {ID: "p-2", Name: "Spare", Type: "local"},
		}},
		settings: []protocol.Setting{
			{Key: protocol.SettingTUN, Type: protocol.SettingBool, Value: false},
			{Key: protocol.SettingLogLevel, Type: protocol.SettingEnum, Value: "info", Options: []string{"error", "info", "debug"}},
		},
	}
}

func (h *fullHooks) findGroup(name string) (*protocol.ProxyGroup, error) {
	for i := range h.groups {
		if h.groups[i].Name == name {
			return &h.groups[i], nil
		}
	}
	return nil, fmt.Errorf("group %q: %w", name, agent.ErrNotFound)
}

func (h *fullHooks) ProxyGroups(context.Context) ([]protocol.ProxyGroup, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.groups), nil
}

func (h *fullHooks) SelectProxy(_ context.Context, group, node string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g, err := h.findGroup(group)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(g.Nodes, func(n protocol.ProxyNode) bool { return n.Name == node }) {
		return "", fmt.Errorf("node %q: %w", node, agent.ErrNotFound)
	}
	g.Now = node
	return node, nil
}

func (h *fullHooks) UnfixProxy(_ context.Context, group string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g, err := h.findGroup(group)
	if err != nil {
		return "", err
	}
	if g.Type == "Selector" {
		return "", fmt.Errorf("selector cannot be unfixed: %w", agent.ErrInvalid)
	}
	g.Fixed = ""
	return g.Now, nil
}

func (h *fullHooks) TestDelay(_ context.Context, req protocol.DelayRequest) ([]protocol.Delay, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastDelay = req
	if req.Node != "" {
		return []protocol.Delay{{Name: req.Node, Delay: 42}}, nil
	}
	return nil, nil // nil must still encode as []
}

func (h *fullHooks) Mode(context.Context) (protocol.ModeState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return protocol.ModeState{Mode: h.mode, Modes: []string{protocol.ModeRule, protocol.ModeGlobal, protocol.ModeDirect}}, nil
}

func (h *fullHooks) SetMode(_ context.Context, mode string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mode = mode
	return mode, nil
}

func (h *fullHooks) Profiles(context.Context) (protocol.ProfileList, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.profiles, nil
}

func (h *fullHooks) SelectProfile(_ context.Context, id string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !slices.ContainsFunc(h.profiles.Profiles, func(p protocol.Profile) bool { return p.ID == id }) {
		return "", fmt.Errorf("profile %q: %w", id, agent.ErrNotFound)
	}
	h.profiles.Active = id
	return id, nil
}

func (h *fullHooks) UpdateProfile(_ context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.updated = append(h.updated, id)
	return nil
}

func (h *fullHooks) DeleteProfile(_ context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleted = append(h.deleted, id)
	return nil
}

func (h *fullHooks) Providers(context.Context) ([]protocol.Provider, error) {
	return []protocol.Provider{{Name: "sub1", Kind: protocol.ProviderProxy, Vehicle: "http", Count: 3}}, nil
}

func (h *fullHooks) UpdateProvider(_ context.Context, kind, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.updated = append(h.updated, kind+"/"+name)
	return nil
}

func (h *fullHooks) HealthCheckProvider(_ context.Context, name string) error {
	return errors.New("core down") // exercises core_unavailable mapping
}

func (h *fullHooks) Connections(context.Context) (protocol.ConnectionList, error) {
	return protocol.ConnectionList{UploadTotal: 1, DownloadTotal: 2, Connections: []protocol.Connection{{ID: "c1", Host: "a:443"}}}, nil
}

func (h *fullHooks) CloseConnections(_ context.Context, id string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = append(h.closed, id)
	if id == "" {
		return 5, nil
	}
	return 1, nil
}

func (h *fullHooks) Traffic(context.Context) (protocol.Traffic, error) {
	return protocol.Traffic{Up: 10, Down: 20, UpTotal: 30, DownTotal: 40}, nil
}

func (h *fullHooks) Logs(_ context.Context, level string, limit int) ([]protocol.LogLine, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logLevel, h.logLimit = level, limit
	// Return more than asked: the agent must trim to the newest `limit`.
	var out []protocol.LogLine
	for i := range limit + 2 {
		out = append(out, protocol.LogLine{Time: int64(i), Level: "info", Msg: fmt.Sprint(i)})
	}
	return out, nil
}

func (h *fullHooks) Settings(context.Context) ([]protocol.Setting, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.settings), nil
}

func (h *fullHooks) SetSetting(_ context.Context, key string, value any) (protocol.Setting, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.settings {
		if h.settings[i].Key == key {
			h.settings[i].Value = value
			return h.settings[i], nil
		}
	}
	return protocol.Setting{}, agent.ErrNotFound
}

func (h *fullHooks) Actions(context.Context) ([]protocol.Action, error) {
	return []protocol.Action{{ID: protocol.ActionFlushDNS}, {ID: "clear_cache", Label: "Clear cache"}}, nil
}

func (h *fullHooks) RunAction(_ context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ran = append(h.ran, id)
	return nil
}

// allRemoteCaps is every remote capability in advertisement order (PROTOCOL.md §8.3).
var allRemoteCaps = []string{
	protocol.CapProxies, protocol.CapSelect, protocol.CapUnfix, protocol.CapDelay, protocol.CapMode,
	protocol.CapProfiles, protocol.CapProfileUpdate, protocol.CapProfileDelete, protocol.CapProviders,
	protocol.CapConnections, protocol.CapTraffic, protocol.CapLogs, protocol.CapSettings, protocol.CapActions,
}

// newFullClient starts a TLS agent backed by fullHooks and returns a paired client.
func newFullClient(t *testing.T, mut func(*agent.Config)) (*controller.Client, *fullHooks) {
	t.Helper()
	h := newFullHooks()
	fp, host, port, store, _ := newTestAgent(t, func(c *agent.Config) {
		c.Hooks = h
		if mut != nil {
			mut(c)
		}
	})
	token, err := store.Pair("dev-ctrl-1", "My Phone")
	if err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(host, port, fp, token)
	if err != nil {
		t.Fatal(err)
	}
	return c, h
}

func wantAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *controller.APIError
	if !errors.As(err, &ae) || ae.Status != status || ae.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

func TestRemoteCapabilities(t *testing.T) {
	ctx := context.Background()

	c, _ := newFullClient(t, nil)
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{protocol.CapStatus, protocol.CapPower, protocol.CapSubscription, protocol.CapRename, protocol.CapUnpair}, allRemoteCaps...)
	want = append(want, protocol.CapEvents)
	if !slices.Equal(st.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", st.Capabilities, want)
	}

	// Disabled capabilities are neither advertised nor served.
	c2, _ := newFullClient(t, func(cfg *agent.Config) {
		cfg.DisableCapabilities = []string{protocol.CapProfileDelete, protocol.CapMode}
	})
	st2, err := c2.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(st2.Capabilities, protocol.CapMode) || slices.Contains(st2.Capabilities, protocol.CapProfileDelete) {
		t.Fatalf("disabled capability advertised: %v", st2.Capabilities)
	}
	_, err = c2.SetMode(ctx, protocol.ModeGlobal)
	wantAPIError(t, err, 404, protocol.CodeNotFound)
	if err := c2.DeleteProfile(ctx, "p-1"); err == nil {
		t.Fatal("disabled profile_delete must be refused")
	}
}

func TestRemoteProxies(t *testing.T) {
	ctx := context.Background()
	c, h := newFullClient(t, nil)

	list, err := c.Proxies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) != 2 || list.Groups[1].Nodes == nil || len(list.Groups[1].Nodes) != 0 {
		t.Fatalf("unexpected groups: %+v", list.Groups)
	}

	sel, err := c.SelectProxy(ctx, "Proxy", "JP-01")
	if err != nil || !sel.OK || sel.Now != "JP-01" || sel.Group != "Proxy" {
		t.Fatalf("select: %+v %v", sel, err)
	}
	_, err = c.SelectProxy(ctx, "Proxy", "nope")
	wantAPIError(t, err, 404, protocol.CodeNotFound)
	_, err = c.SelectProxy(ctx, "Proxy", "")
	wantAPIError(t, err, 400, protocol.CodeBadRequest)

	un, err := c.UnfixProxy(ctx, "Auto")
	if err != nil || un.Now != "HK-01" {
		t.Fatalf("unfix: %+v %v", un, err)
	}
	_, err = c.UnfixProxy(ctx, "Proxy")
	wantAPIError(t, err, 400, protocol.CodeBadRequest)

	d, err := c.TestDelay(ctx, protocol.DelayRequest{Group: "Proxy", Node: "HK-01"})
	if err != nil || len(d.Delays) != 1 || d.Delays[0].Delay != 42 {
		t.Fatalf("delay node: %+v %v", d, err)
	}
	if h.lastDelay.Timeout != protocol.DefaultDelayTimeout {
		t.Fatalf("timeout 0 must resolve to default, hook got %d", h.lastDelay.Timeout)
	}
	d, err = c.TestDelay(ctx, protocol.DelayRequest{Group: "Auto", Timeout: 2000})
	if err != nil || d.Delays == nil || h.lastDelay.Timeout != 2000 {
		t.Fatalf("delay group: %+v %v (hook timeout %d)", d, err, h.lastDelay.Timeout)
	}
}

func TestRemoteModeProfilesProviders(t *testing.T) {
	ctx := context.Background()
	c, h := newFullClient(t, nil)

	m, err := c.Mode(ctx)
	if err != nil || m.Mode != protocol.ModeRule || len(m.Modes) != 3 {
		t.Fatalf("mode: %+v %v", m, err)
	}
	mr, err := c.SetMode(ctx, protocol.ModeDirect)
	if err != nil || mr.Mode != protocol.ModeDirect || h.mode != protocol.ModeDirect {
		t.Fatalf("set mode: %+v %v", mr, err)
	}

	pl, err := c.Profiles(ctx)
	if err != nil || pl.Active != "p-1" || len(pl.Profiles) != 2 {
		t.Fatalf("profiles: %+v %v", pl, err)
	}
	ps, err := c.SelectProfile(ctx, "p-2")
	if err != nil || ps.Active != "p-2" {
		t.Fatalf("select profile: %+v %v", ps, err)
	}
	_, err = c.SelectProfile(ctx, "p-9")
	wantAPIError(t, err, 404, protocol.CodeNotFound)
	if err := c.UpdateProfile(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteProfile(ctx, "p-2"); err != nil {
		t.Fatal(err)
	}

	prov, err := c.Providers(ctx)
	if err != nil || len(prov.Providers) != 1 {
		t.Fatalf("providers: %+v %v", prov, err)
	}
	if err := c.UpdateProvider(ctx, protocol.ProviderRule, "ads"); err != nil {
		t.Fatal(err)
	}
	err = c.HealthCheckProvider(ctx, "sub1")
	wantAPIError(t, err, 502, protocol.CodeCoreUnavailable)

	if !slices.Equal(h.updated, []string{"", "rule/ads"}) || !slices.Equal(h.deleted, []string{"p-2"}) {
		t.Fatalf("hook calls: updated=%v deleted=%v", h.updated, h.deleted)
	}
}

func TestRemoteConnectionsTrafficLogs(t *testing.T) {
	ctx := context.Background()
	c, h := newFullClient(t, nil)

	cl, err := c.Connections(ctx)
	if err != nil || len(cl.Connections) != 1 || cl.Connections[0].Chains == nil {
		t.Fatalf("connections: %+v %v", cl, err)
	}
	cr, err := c.CloseConnections(ctx, "")
	if err != nil || cr.Closed != 5 {
		t.Fatalf("close all: %+v %v", cr, err)
	}
	cr, err = c.CloseConnections(ctx, "c1")
	if err != nil || cr.Closed != 1 || !slices.Equal(h.closed, []string{"", "c1"}) {
		t.Fatalf("close one: %+v %v %v", cr, err, h.closed)
	}

	tr, err := c.Traffic(ctx)
	if err != nil || *tr != (protocol.Traffic{Up: 10, Down: 20, UpTotal: 30, DownTotal: 40}) {
		t.Fatalf("traffic: %+v %v", tr, err)
	}

	lg, err := c.Logs(ctx, "warning", 3)
	if err != nil || len(lg.Lines) != 3 || lg.Lines[0].Msg != "2" || h.logLevel != "warning" || h.logLimit != 3 {
		t.Fatalf("logs: %+v %v (hook level=%q limit=%d)", lg, err, h.logLevel, h.logLimit)
	}
	if _, err := c.Logs(ctx, "", 0); err != nil || h.logLimit != protocol.DefaultLogLimit {
		t.Fatalf("default limit: %v %d", err, h.logLimit)
	}
}

func TestRemoteSettingsActions(t *testing.T) {
	ctx := context.Background()
	c, h := newFullClient(t, nil)

	sl, err := c.Settings(ctx)
	if err != nil || len(sl.Settings) != 2 {
		t.Fatalf("settings: %+v %v", sl, err)
	}
	sr, err := c.SetSetting(ctx, protocol.SettingTUN, true)
	if err != nil || sr.Setting.Value != true {
		t.Fatalf("set bool: %+v %v", sr, err)
	}
	sr, err = c.SetSetting(ctx, protocol.SettingLogLevel, "debug")
	if err != nil || sr.Setting.Value != "debug" {
		t.Fatalf("set enum: %+v %v", sr, err)
	}
	_, err = c.SetSetting(ctx, protocol.SettingTUN, "yes")
	wantAPIError(t, err, 400, protocol.CodeBadRequest)
	_, err = c.SetSetting(ctx, protocol.SettingLogLevel, "trace")
	wantAPIError(t, err, 400, protocol.CodeBadRequest)
	_, err = c.SetSetting(ctx, "nope", true)
	wantAPIError(t, err, 404, protocol.CodeNotFound)

	al, err := c.Actions(ctx)
	if err != nil || len(al.Actions) != 2 {
		t.Fatalf("actions: %+v %v", al, err)
	}
	if err := c.RunAction(ctx, "clear_cache"); err != nil {
		t.Fatal(err)
	}
	err = c.RunAction(ctx, "format_disk")
	wantAPIError(t, err, 404, protocol.CodeNotFound)
	if !slices.Equal(h.ran, []string{"clear_cache"}) {
		t.Fatalf("ran = %v", h.ran)
	}
}

// --- vectors/control.json ---

type controlVectors struct {
	Bodies []struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Canonical string `json:"canonical"`
	} `json:"bodies"`
	Events []struct {
		Type  string `json:"type"`
		Data  string `json:"data"`
		Frame string `json:"frame"`
	} `json:"events"`
	Errors []struct {
		Name   string `json:"name"`
		Agent  string `json:"agent"`
		Auth   bool   `json:"auth"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
		Status int    `json:"status"`
		Code   string `json:"code"`
	} `json:"errors"`
}

// controlModels maps a vector type name to a fresh value of the protocol model.
var controlModels = map[string]func() any{
	"ProxyList": func() any { return &protocol.ProxyList{} }, "SelectRequest": func() any { return &protocol.SelectRequest{} },
	"SelectResponse": func() any { return &protocol.SelectResponse{} }, "UnfixRequest": func() any { return &protocol.UnfixRequest{} },
	"DelayRequest": func() any { return &protocol.DelayRequest{} }, "DelayResponse": func() any { return &protocol.DelayResponse{} },
	"ModeState": func() any { return &protocol.ModeState{} }, "ModeRequest": func() any { return &protocol.ModeRequest{} },
	"ModeResponse": func() any { return &protocol.ModeResponse{} }, "ProfileList": func() any { return &protocol.ProfileList{} },
	"ProfileRequest": func() any { return &protocol.ProfileRequest{} }, "ProfileSelectResponse": func() any { return &protocol.ProfileSelectResponse{} },
	"OKResponse": func() any { return &protocol.OKResponse{} }, "ProviderList": func() any { return &protocol.ProviderList{} },
	"ProviderRequest": func() any { return &protocol.ProviderRequest{} }, "ConnectionList": func() any { return &protocol.ConnectionList{} },
	"CloseRequest": func() any { return &protocol.CloseRequest{} }, "CloseResponse": func() any { return &protocol.CloseResponse{} },
	"Traffic": func() any { return &protocol.Traffic{} }, "LogList": func() any { return &protocol.LogList{} },
	"SettingList": func() any { return &protocol.SettingList{} }, "SettingRequest": func() any { return &protocol.SettingRequest{} },
	"SettingResponse": func() any { return &protocol.SettingResponse{} }, "ActionList": func() any { return &protocol.ActionList{} },
	"ActionRequest": func() any { return &protocol.ActionRequest{} },
	"Status":        func() any { return &protocol.Status{} }, "Changed": func() any { return &protocol.Changed{} },
}

func TestControlBodyVectors(t *testing.T) {
	var vec controlVectors
	testvectors.Load(t, "control.json", &vec)
	if len(vec.Bodies) == 0 {
		t.Fatal("no control body vectors")
	}
	for _, b := range vec.Bodies {
		mk, ok := controlModels[b.Type]
		if !ok {
			t.Errorf("%s: unknown model %q", b.Name, b.Type)
			continue
		}
		v := mk()
		if err := json.Unmarshal([]byte(b.Canonical), v); err != nil {
			t.Errorf("%s: decode: %v", b.Name, err)
			continue
		}
		got, err := canonjson.MarshalString(v)
		if err != nil {
			t.Errorf("%s: encode: %v", b.Name, err)
			continue
		}
		if got != b.Canonical {
			t.Errorf("%s: round trip mismatch\n got  %s\n want %s", b.Name, got, b.Canonical)
		}
	}
}

func TestControlErrorVectors(t *testing.T) {
	var vec controlVectors
	testvectors.Load(t, "control.json", &vec)
	if len(vec.Errors) == 0 {
		t.Fatal("no control error vectors")
	}
	handlers := map[string]http.Handler{}
	tokens := map[string]string{}
	for name, hooks := range map[string]agent.Hooks{"full": newFullHooks(), "p1": &fakeHooks{}} {
		id, err := pairing.NewIdentity("clashctl-agent", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		store := pairing.NewStore()
		a, err := agent.New(agent.Config{App: "test", DeviceID: "dev", Identity: id, Store: store, Hooks: hooks})
		if err != nil {
			t.Fatal(err)
		}
		tokens[name], _ = store.Pair("ctrl", "Ctrl")
		handlers[name] = a.Handler()
	}
	for _, e := range vec.Errors {
		req := httptest.NewRequest(e.Method, e.Path, strings.NewReader(e.Body))
		if e.Auth {
			req.Header.Set("Authorization", "Bearer "+tokens[e.Agent])
		}
		rec := httptest.NewRecorder()
		handlers[e.Agent].ServeHTTP(rec, req)
		var env protocol.Error
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if rec.Code != e.Status || env.Error.Code != e.Code {
			t.Errorf("%s: got %d %q (%s), want %d %q", e.Name, rec.Code, env.Error.Code, rec.Body.String(), e.Status, e.Code)
		}
	}
}

// eventModels maps an SSE event type to its data model (PROTOCOL.md §9.2).
var eventModels = map[string]func() any{
	protocol.EventStatus:  func() any { return &protocol.Status{} },
	protocol.EventChanged: func() any { return &protocol.Changed{} },
	protocol.EventTraffic: func() any { return &protocol.Traffic{} },
	protocol.EventLog:     func() any { return &protocol.LogLine{} },
}

func TestControlEventVectors(t *testing.T) {
	var vec controlVectors
	testvectors.Load(t, "control.json", &vec)
	if len(vec.Events) == 0 {
		t.Fatal("no event vectors")
	}
	for _, e := range vec.Events {
		v := eventModels[e.Type]()
		if err := json.Unmarshal([]byte(e.Data), v); err != nil {
			t.Fatalf("%s: %v", e.Type, err)
		}
		if got, _ := canonjson.MarshalString(v); got != e.Data {
			t.Errorf("%s: data round trip %s, want %s", e.Type, got, e.Data)
		}
		if want := "event: " + e.Type + "\ndata: " + e.Data + "\n\n"; e.Frame != want {
			t.Errorf("%s: frame %q, want %q", e.Type, e.Frame, want)
		}
	}

	// The live agent emits exactly these bytes for changed and log frames.
	var ag *agent.Agent
	h := newFullHooks()
	fp, host, port, store, _ := newTestAgentCapture(t, h, &ag)
	tok, _ := store.Pair("ctrl", "Ctrl")
	c, _ := controller.New(host, port, fp, tok)
	evs, _, _ := collect(t, c, controller.EventOptions{Logs: true})
	next(t, evs, protocol.EventStatus)
	for _, e := range vec.Events {
		switch e.Type {
		case protocol.EventChanged:
			var ch protocol.Changed
			_ = json.Unmarshal([]byte(e.Data), &ch)
			ag.Notify(ch.Resource)
		case protocol.EventLog:
			var l protocol.LogLine
			_ = json.Unmarshal([]byte(e.Data), &l)
			ag.PublishLog(l)
		default:
			continue
		}
		if got := next(t, evs, e.Type); string(got.Data) != e.Data {
			t.Errorf("%s: live data %s, want %s", e.Type, got.Data, e.Data)
		}
	}
}
