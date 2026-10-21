package corehooks_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Nemu-x/clash-companion/go/agent"
	"github.com/Nemu-x/clash-companion/go/corehooks"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// fakeCore mimics the parts of mihomo's external-controller that corehooks uses, with the
// JSON shapes of mihomo v1.19.x.
type fakeCore struct {
	mu      sync.Mutex
	now     map[string]string
	fixed   string
	mode    string
	allow   bool
	calls   []string
	patches []map[string]any
}

func newFakeCore(t *testing.T) (*fakeCore, *corehooks.Core) {
	t.Helper()
	f := &fakeCore{now: map[string]string{"Proxy": "HK-01", "Auto": "JP-01", "GLOBAL": "Proxy"}, fixed: "JP-01", mode: "Rule"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxies", f.proxies)
	mux.HandleFunc("GET /proxies/{name}", f.proxy)
	mux.HandleFunc("PUT /proxies/{name}", f.selectProxy)
	mux.HandleFunc("DELETE /proxies/{name}", f.unfix)
	mux.HandleFunc("GET /proxies/{name}/delay", f.proxyDelay)
	mux.HandleFunc("GET /group/{name}/delay", f.groupDelay)
	mux.HandleFunc("GET /configs", f.configs)
	mux.HandleFunc("PATCH /configs", f.patchConfigs)
	mux.HandleFunc("GET /providers/proxies", f.proxyProviders)
	mux.HandleFunc("GET /providers/rules", f.ruleProviders)
	mux.HandleFunc("PUT /providers/{kind}/{name}", f.record)
	mux.HandleFunc("GET /providers/proxies/{name}/healthcheck", f.record)
	mux.HandleFunc("GET /connections", f.connections)
	mux.HandleFunc("DELETE /connections", f.record)
	mux.HandleFunc("DELETE /connections/{id}", f.record)
	mux.HandleFunc("GET /traffic", f.traffic)
	mux.HandleFunc("POST /cache/dns/flush", f.record)
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"meta": true, "version": "v1.19.32"})
	})
	mux.HandleFunc("GET /logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("level") != "warning" {
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, `{"type":"warning","payload":"dial failed"}`+"\nnot json\n"+`{"type":"error","payload":"boom"}`+"\n")
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, corehooks.New(srv.URL+"/", "s3cret")
}

func (f *fakeCore) record(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeCore) all() map[string]map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	hist := func(d int) []map[string]any {
		return []map[string]any{{"time": "x", "delay": 1}, {"time": "y", "delay": d}}
	}
	return map[string]map[string]any{
		"GLOBAL": {"name": "GLOBAL", "type": "Selector", "now": f.now["GLOBAL"], "all": []string{"Proxy", "Auto", "Hidden", "DIRECT"}, "hidden": false},
		"Proxy":  {"name": "Proxy", "type": "Selector", "now": f.now["Proxy"], "all": []string{"Auto", "HK-01", "JP-01"}},
		"Auto":   {"name": "Auto", "type": "URLTest", "now": f.now["Auto"], "fixed": f.fixed, "all": []string{"HK-01", "JP-01"}, "history": hist(77)},
		"Hidden": {"name": "Hidden", "type": "Selector", "now": "HK-01", "all": []string{"HK-01"}, "hidden": true},
		"Orphan": {"name": "Orphan", "type": "LoadBalance", "now": "", "all": []string{}},
		"HK-01":  {"name": "HK-01", "type": "Vless", "history": hist(80)},
		"JP-01":  {"name": "JP-01", "type": "Trojan", "history": []any{}},
		"DIRECT": {"name": "DIRECT", "type": "Direct", "history": []any{}},
	}
}

func (f *fakeCore) proxies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"proxies": f.all()})
}

func (f *fakeCore) proxy(w http.ResponseWriter, r *http.Request) {
	p, ok := f.all()[r.PathValue("name")]
	if !ok {
		writeJSON(w, 404, map[string]string{"message": "resource not found"})
		return
	}
	writeJSON(w, 200, p)
}

func (f *fakeCore) selectProxy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.now[r.PathValue("name")] = body.Name
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCore) unfix(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.fixed = ""
	f.now["Auto"] = "HK-01"
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCore) proxyDelay(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("timeout") != "3000" || r.URL.Query().Get("url") != corehooks.DefaultTestURL {
		writeJSON(w, 400, map[string]string{"message": "bad query " + r.URL.RawQuery})
		return
	}
	if r.PathValue("name") == "JP-01" {
		writeJSON(w, 504, map[string]string{"message": "Timeout"})
		return
	}
	writeJSON(w, 200, map[string]int{"delay": 64})
}

func (f *fakeCore) groupDelay(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]int{"HK-01": 55}) // JP-01 failed: absent
}

func (f *fakeCore) configs(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON(w, 200, map[string]any{"mode": f.mode, "log-level": "info", "allow-lan": f.allow, "ipv6": true, "sniffing": false, "tun": map[string]any{"enable": false}})
}

func (f *fakeCore) patchConfigs(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.patches = append(f.patches, body)
	if m, ok := body["mode"].(string); ok {
		f.mode = m
	}
	if a, ok := body["allow-lan"].(bool); ok {
		f.allow = a
	}
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCore) proxyProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"providers": map[string]any{
		"default": map[string]any{"name": "default", "type": "Proxy", "vehicleType": "Compatible", "proxies": []any{1, 2}},
		"sub1": map[string]any{"name": "sub1", "type": "Proxy", "vehicleType": "HTTP", "proxies": []any{1, 2, 3},
			"updatedAt": "2026-10-20T12:00:00Z", "subscriptionInfo": map[string]int64{"Upload": 1, "Download": 2, "Total": 3, "Expire": 4}},
	}})
}

func (f *fakeCore) ruleProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"providers": map[string]any{
		"ads": map[string]any{"name": "ads", "type": "Rule", "vehicleType": "File", "ruleCount": 99, "updatedAt": "0001-01-01T00:00:00Z"},
	}})
}

func (f *fakeCore) connections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"uploadTotal": 10, "downloadTotal": 20, "memory": 1, "connections": []any{
		map[string]any{"id": "c1", "upload": 5, "download": 6, "start": "2026-10-20T12:00:00.123Z", "chains": []string{"HK-01", "Proxy"},
			"rule": "DomainSuffix", "rulePayload": "youtube.com",
			"metadata": map[string]any{"network": "tcp", "host": "www.youtube.com", "destinationIP": "1.2.3.4", "destinationPort": "443", "process": "chrome"}},
		map[string]any{"id": "c2", "upload": 0, "download": 0, "start": "2026-10-20T12:00:01Z", "chains": []string{"DIRECT"},
			"rule": "Match", "rulePayload": "",
			"metadata": map[string]any{"network": "udp", "host": "", "destinationIP": "8.8.8.8", "destinationPort": "53", "process": ""}},
	}})
}

func (f *fakeCore) traffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	for i := 0; ; i++ {
		_, err := io.WriteString(w, `{"up":100,"down":200,"upTotal":300,"downTotal":400}`+"\n")
		if err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestProxies(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeCore(t)

	groups, err := c.ProxyGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range groups {
		names = append(names, g.Name)
	}
	// GLOBAL order, hidden dropped, GLOBAL last, unlisted groups after.
	if !slices.Equal(names, []string{"Proxy", "Auto", "GLOBAL", "Orphan"}) {
		t.Fatalf("group order = %v", names)
	}
	auto := groups[1]
	if auto.Fixed != "JP-01" || !auto.Selectable || auto.Nodes[0] != (protocol.ProxyNode{Name: "HK-01", Type: "Vless", Delay: 80}) || auto.Nodes[1].Delay != 0 {
		t.Fatalf("auto group = %+v", auto)
	}
	if groups[3].Selectable {
		t.Fatal("LoadBalance must not be selectable")
	}

	if now, err := c.SelectProxy(ctx, "Proxy", "JP-01"); err != nil || now != "JP-01" {
		t.Fatalf("select: %q %v", now, err)
	}
	if _, err := c.SelectProxy(ctx, "Proxy", "XX"); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("select unknown node: %v", err)
	}
	if _, err := c.SelectProxy(ctx, "Nope", "HK-01"); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("select unknown group: %v", err)
	}
	if _, err := c.SelectProxy(ctx, "HK-01", "x"); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("select on a non-group: %v", err)
	}
	if now, err := c.UnfixProxy(ctx, "Auto"); err != nil || now != "HK-01" {
		t.Fatalf("unfix: %q %v", now, err)
	}

	d, err := c.TestDelay(ctx, protocol.DelayRequest{Group: "Proxy", Node: "HK-01", Timeout: 3000})
	if err != nil || !slices.Equal(d, []protocol.Delay{{Name: "HK-01", Delay: 64}}) {
		t.Fatalf("node delay: %v %v", d, err)
	}
	d, err = c.TestDelay(ctx, protocol.DelayRequest{Group: "Proxy", Node: "JP-01", Timeout: 3000})
	if err != nil || d[0].Delay != 0 {
		t.Fatalf("timed-out node must report 0: %v %v", d, err)
	}
	d, err = c.TestDelay(ctx, protocol.DelayRequest{Group: "Auto", Timeout: 3000})
	if err != nil || !slices.Equal(d, []protocol.Delay{{Name: "HK-01", Delay: 55}, {Name: "JP-01", Delay: 0}}) {
		t.Fatalf("group delay: %v %v", d, err)
	}
}

func TestModeSettingsActions(t *testing.T) {
	ctx := context.Background()
	f, c := newFakeCore(t)

	m, err := c.Mode(ctx)
	if err != nil || m.Mode != "rule" || len(m.Modes) != 3 {
		t.Fatalf("mode: %+v %v", m, err)
	}
	if _, err := c.SetMode(ctx, protocol.ModeGlobal); err != nil || f.mode != "global" {
		t.Fatalf("set mode: %v (core mode %q)", err, f.mode)
	}

	s, err := c.SetSetting(ctx, protocol.SettingAllowLAN, true)
	if err != nil || s.Value != true {
		t.Fatalf("set allow_lan: %+v %v", s, err)
	}
	if _, err := c.SetSetting(ctx, protocol.SettingTUN, true); err != nil {
		t.Fatal(err)
	}
	tun, _ := json.Marshal(f.patches[len(f.patches)-1])
	if string(tun) != `{"tun":{"enable":true}}` {
		t.Fatalf("tun patch = %s", tun)
	}
	if _, err := c.SetSetting(ctx, "nope", true); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("unknown setting: %v", err)
	}

	if err := c.RunAction(ctx, protocol.ActionFlushDNS); err != nil {
		t.Fatal(err)
	}
	if err := c.RunAction(ctx, protocol.ActionRestartCore); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("restart_core must not be offered: %v", err)
	}
}

func TestProvidersConnectionsTraffic(t *testing.T) {
	ctx := context.Background()
	f, c := newFakeCore(t)

	prov, err := c.Providers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []protocol.Provider{
		{Name: "sub1", Kind: "proxy", Vehicle: "http", Count: 3, UpdatedAt: 1792497600, Usage: &protocol.Usage{Upload: 1, Download: 2, Total: 3, Expire: 4}},
		{Name: "ads", Kind: "rule", Vehicle: "file", Count: 99},
	}
	if len(prov) != 2 || prov[0].Name != want[0].Name || *prov[0].Usage != *want[0].Usage || prov[0].UpdatedAt != want[0].UpdatedAt || prov[1] != want[1] {
		t.Fatalf("providers = %+v", prov)
	}
	if err := c.UpdateProvider(ctx, protocol.ProviderRule, "ads"); err != nil {
		t.Fatal(err)
	}
	if err := c.HealthCheckProvider(ctx, "sub1"); err != nil {
		t.Fatal(err)
	}

	cl, err := c.Connections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c1 := cl.Connections[0]
	if cl.UploadTotal != 10 || c1.Host != "www.youtube.com:443" || c1.Rule != "DomainSuffix(youtube.com)" || c1.Process != "chrome" || c1.Start != 1792497600123 {
		t.Fatalf("connection = %+v", c1)
	}
	if cl.Connections[1].Host != "8.8.8.8:53" || cl.Connections[1].Rule != "Match" {
		t.Fatalf("connection 2 = %+v", cl.Connections[1])
	}
	if n, err := c.CloseConnections(ctx, ""); err != nil || n != 2 {
		t.Fatalf("close all: %d %v", n, err)
	}
	if n, err := c.CloseConnections(ctx, "c2"); err != nil || n != 1 {
		t.Fatalf("close one: %d %v", n, err)
	}
	if _, err := c.CloseConnections(ctx, "zz"); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("close unknown: %v", err)
	}

	tr, err := c.Traffic(ctx)
	if err != nil || tr != (protocol.Traffic{Up: 100, Down: 200, UpTotal: 300, DownTotal: 400}) {
		t.Fatalf("traffic: %+v %v", tr, err)
	}

	wantCalls := []string{"PUT /providers/rules/ads", "GET /providers/proxies/sub1/healthcheck", "DELETE /connections", "DELETE /connections/c2"}
	if !slices.Equal(f.calls, wantCalls) {
		t.Fatalf("core calls = %v", f.calls)
	}
}

// embedded shows the intended use: corehooks mixed into a consumer's hooks, with the
// app-owned selection overridden.
type embedded struct {
	*corehooks.Core
	selected []string
}

func (e *embedded) PowerState(context.Context) (string, error)    { return protocol.PowerOn, nil }
func (e *embedded) Power(context.Context, string) (string, error) { return protocol.PowerOn, nil }
func (e *embedded) ImportSubscription(context.Context, protocol.SubscriptionRequest) error {
	return nil
}
func (e *embedded) SelectProxy(_ context.Context, group, node string) (string, error) {
	e.selected = append(e.selected, group+"="+node)
	return node, nil
}

func TestEmbeddingAdvertisesCoreCapabilities(t *testing.T) {
	_, core := newFakeCore(t)
	id, err := pairing.NewIdentity("clashctl-agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := &embedded{Core: core}
	a, err := agent.New(agent.Config{
		App: "test", DeviceID: "dev", Identity: id, Store: pairing.NewStore(), Hooks: h,
		DisableCapabilities: []string{protocol.CapSettings},
	})
	if err != nil {
		t.Fatal(err)
	}
	caps := a.Capabilities()
	for _, want := range []string{protocol.CapProxies, protocol.CapSelect, protocol.CapUnfix, protocol.CapDelay, protocol.CapMode,
		protocol.CapProviders, protocol.CapConnections, protocol.CapTraffic, protocol.CapActions} {
		if !slices.Contains(caps, want) {
			t.Errorf("missing capability %q in %v", want, caps)
		}
	}
	for _, absent := range []string{protocol.CapProfiles, protocol.CapLogs, protocol.CapSettings} {
		if slices.Contains(caps, absent) {
			t.Errorf("unexpected capability %q", absent)
		}
	}
	if _, err := h.SelectProxy(context.Background(), "Proxy", "JP-01"); err != nil || h.selected[0] != "Proxy=JP-01" {
		t.Fatal("override must shadow corehooks.SelectProxy")
	}
}

func TestSummaryAndFollowLogs(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeCore(t)

	sum, err := c.Summary(ctx)
	if err != nil || sum != (protocol.Summary{Mode: "rule", CoreVersion: "v1.19.32"}) {
		t.Fatalf("summary: %+v %v", sum, err)
	}

	var lines []protocol.LogLine
	if err := c.FollowLogs(ctx, "warning", func(l protocol.LogLine) { lines = append(lines, l) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].Level != "warning" || lines[1].Msg != "boom" || lines[0].Time == 0 {
		t.Fatalf("lines = %+v", lines)
	}
}
