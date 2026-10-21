// Package corehooks implements the core-backed remote-control hooks (PROTOCOL.md §8.6–§8.19)
// against a localhost mihomo external-controller REST API.
//
// It is meant to be embedded in a consumer's hooks so most remote buttons work with no
// further code:
//
//	type myHooks struct {
//		*corehooks.Core
//		// ... Power, PowerState, ImportSubscription, and any overrides
//	}
//
// A consumer whose app owns some state (the selected node, the mode, TUN) MUST shadow the
// matching methods with its own implementation, so the change goes through the app and is
// persisted and shown in its UI; otherwise the app may revert it. Use
// agent.Config.DisableCapabilities to drop inherited buttons the consumer does not want.
//
// Core implements: ProxyLister, ProxySelector, ProxyUnfixer, DelayTester, ModeController,
// ProviderController, ConnectionController, TrafficReporter, SettingsController and
// ActionRunner and Summarizer. It does not implement power, import, profiles or logs (app
// concepts); FollowLogs streams core logs into agent.PublishLog.
//
// In mihomo's embed mode (e.g. Android builds) PATCH /configs and POST /configs/geo are not
// mounted, so SetMode, SetSetting and the update_geo action fail there.
package corehooks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nemu-x/clash-companion/go/agent"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

var (
	_ agent.ProxyLister          = (*Core)(nil)
	_ agent.ProxySelector        = (*Core)(nil)
	_ agent.ProxyUnfixer         = (*Core)(nil)
	_ agent.DelayTester          = (*Core)(nil)
	_ agent.ModeController       = (*Core)(nil)
	_ agent.ProviderController   = (*Core)(nil)
	_ agent.ConnectionController = (*Core)(nil)
	_ agent.TrafficReporter      = (*Core)(nil)
	_ agent.SettingsController   = (*Core)(nil)
	_ agent.ActionRunner         = (*Core)(nil)
	_ agent.Summarizer           = (*Core)(nil)
)

// DefaultTestURL is used for delay tests when the request names no URL.
const DefaultTestURL = "https://www.gstatic.com/generate_204"

// Core talks to one mihomo external-controller.
type Core struct {
	base   string
	secret string
	http   *http.Client

	// TestURL is the delay-test URL used when a request names none.
	TestURL string
}

// New returns a Core for the controller at coreURL (e.g. "http://127.0.0.1:9090"). A
// non-empty secret is sent as the controller's bearer token.
func New(coreURL, secret string) *Core {
	return &Core{
		base:    strings.TrimRight(coreURL, "/"),
		secret:  secret,
		http:    &http.Client{Timeout: 40 * time.Second}, // above protocol.MaxDelayTimeout
		TestURL: DefaultTestURL,
	}
}

// --- proxies ---

type rawProxy struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	All     []string `json:"all"`
	Fixed   string   `json:"fixed"`
	Hidden  bool     `json:"hidden"`
	History []struct {
		Delay int `json:"delay"`
	} `json:"history"`
}

func (p rawProxy) isGroup() bool { return p.All != nil }

func (p rawProxy) lastDelay() int {
	if len(p.History) == 0 {
		return 0
	}
	return p.History[len(p.History)-1].Delay
}

// selectableTypes are the group types mihomo lets PUT /proxies/{group} change.
var selectableTypes = []string{"Selector", "URLTest", "Fallback"}

// ProxyGroups lists visible groups in GLOBAL's order, with GLOBAL itself last.
func (c *Core) ProxyGroups(ctx context.Context) ([]protocol.ProxyGroup, error) {
	var resp struct {
		Proxies map[string]rawProxy `json:"proxies"`
	}
	if err := c.do(ctx, http.MethodGet, "/proxies", nil, &resp); err != nil {
		return nil, err
	}
	var order []string
	if g, ok := resp.Proxies["GLOBAL"]; ok {
		order = append(slices.Clone(g.All), "GLOBAL")
	}
	// Groups GLOBAL does not list (rare) follow, sorted for a stable order.
	var rest []string
	for name, p := range resp.Proxies {
		if p.isGroup() && !slices.Contains(order, name) {
			rest = append(rest, name)
		}
	}
	slices.Sort(rest)
	order = append(order, rest...)

	groups := []protocol.ProxyGroup{}
	for _, name := range order {
		p, ok := resp.Proxies[name]
		if !ok || !p.isGroup() || p.Hidden {
			continue
		}
		nodes := make([]protocol.ProxyNode, 0, len(p.All))
		for _, n := range p.All {
			m := resp.Proxies[n]
			nodes = append(nodes, protocol.ProxyNode{Name: n, Type: m.Type, Delay: m.lastDelay()})
		}
		groups = append(groups, protocol.ProxyGroup{
			Name:       name,
			Type:       p.Type,
			Now:        p.Now,
			Fixed:      p.Fixed,
			Selectable: slices.Contains(selectableTypes, p.Type),
			Nodes:      nodes,
		})
	}
	return groups, nil
}

func (c *Core) group(ctx context.Context, name string) (rawProxy, error) {
	var p rawProxy
	if err := c.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(name), nil, &p); err != nil {
		return p, err
	}
	if !p.isGroup() {
		return p, fmt.Errorf("%q is not a group: %w", name, agent.ErrNotFound)
	}
	return p, nil
}

// SelectProxy selects node in group via PUT /proxies/{group}. This persists in the core's
// cache file only; consumers with their own selection store MUST override it.
func (c *Core) SelectProxy(ctx context.Context, group, node string) (string, error) {
	g, err := c.group(ctx, group)
	if err != nil {
		return "", err
	}
	if !slices.Contains(g.All, node) {
		return "", fmt.Errorf("%q is not in group %q: %w", node, group, agent.ErrNotFound)
	}
	if !slices.Contains(selectableTypes, g.Type) {
		return "", fmt.Errorf("group %q (%s) is not selectable: %w", group, g.Type, agent.ErrInvalid)
	}
	body := map[string]string{"name": node}
	if err := c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), body, nil); err != nil {
		return "", err
	}
	return node, nil
}

// UnfixProxy clears the pinned node of a url-test/fallback group via DELETE /proxies/{group}.
func (c *Core) UnfixProxy(ctx context.Context, group string) (string, error) {
	if _, err := c.group(ctx, group); err != nil {
		return "", err
	}
	if err := c.do(ctx, http.MethodDelete, "/proxies/"+url.PathEscape(group), nil, nil); err != nil {
		return "", err
	}
	g, err := c.group(ctx, group)
	if err != nil {
		return "", err
	}
	return g.Now, nil
}

// TestDelay tests one node (GET /proxies/{node}/delay) or a whole group
// (GET /group/{group}/delay). A failed node reports delay 0. Note: mihomo's group delay
// test also clears the pinned node of a url-test/fallback group.
func (c *Core) TestDelay(ctx context.Context, req protocol.DelayRequest) ([]protocol.Delay, error) {
	g, err := c.group(ctx, req.Group)
	if err != nil {
		return nil, err
	}
	testURL := req.URL
	if testURL == "" {
		testURL = c.TestURL
	}
	q := url.Values{"url": {testURL}, "timeout": {strconv.Itoa(req.Timeout)}}.Encode()

	if req.Node != "" {
		if !slices.Contains(g.All, req.Node) {
			return nil, fmt.Errorf("%q is not in group %q: %w", req.Node, req.Group, agent.ErrNotFound)
		}
		var out struct {
			Delay int `json:"delay"`
		}
		err := c.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(req.Node)+"/delay?"+q, nil, &out)
		var se *statusError
		if errors.As(err, &se) && (se.code == http.StatusServiceUnavailable || se.code == http.StatusGatewayTimeout) {
			out.Delay, err = 0, nil
		}
		if err != nil {
			return nil, err
		}
		return []protocol.Delay{{Name: req.Node, Delay: out.Delay}}, nil
	}

	results := map[string]int{}
	err = c.do(ctx, http.MethodGet, "/group/"+url.PathEscape(req.Group)+"/delay?"+q, nil, &results)
	var se *statusError
	if errors.As(err, &se) && se.code == http.StatusGatewayTimeout {
		err = nil // every node timed out
	}
	if err != nil {
		return nil, err
	}
	delays := make([]protocol.Delay, 0, len(g.All))
	for _, n := range g.All {
		delays = append(delays, protocol.Delay{Name: n, Delay: results[n]})
	}
	return delays, nil
}

// --- mode ---

var allModes = []string{protocol.ModeRule, protocol.ModeGlobal, protocol.ModeDirect}

type rawConfigs struct {
	Mode     string `json:"mode"`
	LogLevel string `json:"log-level"`
	AllowLAN bool   `json:"allow-lan"`
	IPv6     bool   `json:"ipv6"`
	Sniffing bool   `json:"sniffing"`
	Tun      struct {
		Enable bool `json:"enable"`
	} `json:"tun"`
}

func (c *Core) configs(ctx context.Context) (rawConfigs, error) {
	var cfg rawConfigs
	err := c.do(ctx, http.MethodGet, "/configs", nil, &cfg)
	return cfg, err
}

// Mode reads the tunnel mode from GET /configs.
func (c *Core) Mode(ctx context.Context) (protocol.ModeState, error) {
	cfg, err := c.configs(ctx)
	if err != nil {
		return protocol.ModeState{}, err
	}
	return protocol.ModeState{Mode: strings.ToLower(cfg.Mode), Modes: slices.Clone(allModes)}, nil
}

// SetMode sets the tunnel mode via PATCH /configs.
func (c *Core) SetMode(ctx context.Context, mode string) (string, error) {
	if err := c.do(ctx, http.MethodPatch, "/configs", map[string]string{"mode": mode}, nil); err != nil {
		return "", err
	}
	return mode, nil
}

// --- providers ---

type rawProvider struct {
	Name        string    `json:"name"`
	VehicleType string    `json:"vehicleType"`
	Proxies     []any     `json:"proxies"`
	RuleCount   int       `json:"ruleCount"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Sub         *struct {
		Upload, Download, Total, Expire int64
	} `json:"subscriptionInfo"`
}

// providerPaths maps a provider kind to its mihomo collection path.
var providerPaths = map[string]string{
	protocol.ProviderProxy: "/providers/proxies",
	protocol.ProviderRule:  "/providers/rules",
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() || t.Unix() < 0 {
		return 0
	}
	return t.Unix()
}

// Providers lists proxy providers (except mihomo's implicit "Compatible" ones) then rule
// providers, each sorted by name.
func (c *Core) Providers(ctx context.Context) ([]protocol.Provider, error) {
	out := []protocol.Provider{}
	for _, kind := range []string{protocol.ProviderProxy, protocol.ProviderRule} {
		var resp struct {
			Providers map[string]rawProvider `json:"providers"`
		}
		if err := c.do(ctx, http.MethodGet, providerPaths[kind], nil, &resp); err != nil {
			return nil, err
		}
		var list []protocol.Provider
		for name, p := range resp.Providers {
			if p.VehicleType == "Compatible" {
				continue
			}
			pr := protocol.Provider{
				Name:      name,
				Kind:      kind,
				Vehicle:   strings.ToLower(p.VehicleType),
				Count:     p.RuleCount,
				UpdatedAt: unixOrZero(p.UpdatedAt),
			}
			if kind == protocol.ProviderProxy {
				pr.Count = len(p.Proxies)
			}
			if p.Sub != nil {
				pr.Usage = &protocol.Usage{Upload: p.Sub.Upload, Download: p.Sub.Download, Total: p.Sub.Total, Expire: p.Sub.Expire}
			}
			list = append(list, pr)
		}
		slices.SortFunc(list, func(a, b protocol.Provider) int { return strings.Compare(a.Name, b.Name) })
		out = append(out, list...)
	}
	return out, nil
}

// UpdateProvider refreshes a provider via PUT /providers/{proxies|rules}/{name}.
func (c *Core) UpdateProvider(ctx context.Context, kind, name string) error {
	p, ok := providerPaths[kind]
	if !ok {
		return fmt.Errorf("provider kind %q: %w", kind, agent.ErrInvalid)
	}
	return c.do(ctx, http.MethodPut, p+"/"+url.PathEscape(name), nil, nil)
}

// HealthCheckProvider health-checks a proxy provider via
// GET /providers/proxies/{name}/healthcheck.
func (c *Core) HealthCheckProvider(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodGet, "/providers/proxies/"+url.PathEscape(name)+"/healthcheck", nil, nil)
}

// --- connections & traffic ---

type rawConnections struct {
	UploadTotal   int64 `json:"uploadTotal"`
	DownloadTotal int64 `json:"downloadTotal"`
	Connections   []struct {
		ID       string `json:"id"`
		Metadata struct {
			Network string `json:"network"`
			Host    string `json:"host"`
			DstIP   string `json:"destinationIP"`
			DstPort string `json:"destinationPort"`
			Process string `json:"process"`
		} `json:"metadata"`
		Upload      int64     `json:"upload"`
		Download    int64     `json:"download"`
		Start       time.Time `json:"start"`
		Chains      []string  `json:"chains"`
		Rule        string    `json:"rule"`
		RulePayload string    `json:"rulePayload"`
	} `json:"connections"`
}

// Connections lists active connections via GET /connections.
func (c *Core) Connections(ctx context.Context) (protocol.ConnectionList, error) {
	var raw rawConnections
	if err := c.do(ctx, http.MethodGet, "/connections", nil, &raw); err != nil {
		return protocol.ConnectionList{}, err
	}
	out := protocol.ConnectionList{
		UploadTotal:   raw.UploadTotal,
		DownloadTotal: raw.DownloadTotal,
		Connections:   make([]protocol.Connection, 0, len(raw.Connections)),
	}
	for _, rc := range raw.Connections {
		host := rc.Metadata.Host
		if host == "" {
			host = rc.Metadata.DstIP
		}
		if rc.Metadata.DstPort != "" {
			host += ":" + rc.Metadata.DstPort
		}
		rule := rc.Rule
		if rc.RulePayload != "" {
			rule += "(" + rc.RulePayload + ")"
		}
		out.Connections = append(out.Connections, protocol.Connection{
			ID:       rc.ID,
			Host:     host,
			Network:  rc.Metadata.Network,
			Process:  rc.Metadata.Process,
			Rule:     rule,
			Chains:   rc.Chains,
			Upload:   rc.Upload,
			Download: rc.Download,
			Start:    rc.Start.UnixMilli(),
		})
	}
	return out, nil
}

// CloseConnections closes one connection, or all when id is "", and reports how many.
func (c *Core) CloseConnections(ctx context.Context, id string) (int, error) {
	list, err := c.Connections(ctx)
	if err != nil {
		return 0, err
	}
	if id == "" {
		if err := c.do(ctx, http.MethodDelete, "/connections", nil, nil); err != nil {
			return 0, err
		}
		return len(list.Connections), nil
	}
	if !slices.ContainsFunc(list.Connections, func(x protocol.Connection) bool { return x.ID == id }) {
		return 0, fmt.Errorf("connection %q: %w", id, agent.ErrNotFound)
	}
	if err := c.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil); err != nil {
		return 0, err
	}
	return 1, nil
}

// Traffic reads the first sample of the GET /traffic stream (emitted about once a second).
func (c *Core) Traffic(ctx context.Context) (protocol.Traffic, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := c.send(ctx, http.MethodGet, "/traffic", nil)
	if err != nil {
		return protocol.Traffic{}, err
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return protocol.Traffic{}, fmt.Errorf("core traffic stream: %w", err)
	}
	var t protocol.Traffic
	if err := json.Unmarshal(line, &t); err != nil {
		return protocol.Traffic{}, fmt.Errorf("core traffic stream: %w", err)
	}
	return t, nil
}

// --- settings ---

var logLevels = []string{"silent", "error", "warning", "info", "debug"}

// Settings reports allow_lan, ipv6, sniffing, tun and log_level from GET /configs.
func (c *Core) Settings(ctx context.Context) ([]protocol.Setting, error) {
	cfg, err := c.configs(ctx)
	if err != nil {
		return nil, err
	}
	b := func(key string, v bool) protocol.Setting {
		return protocol.Setting{Key: key, Type: protocol.SettingBool, Value: v}
	}
	return []protocol.Setting{
		b(protocol.SettingTUN, cfg.Tun.Enable),
		b(protocol.SettingAllowLAN, cfg.AllowLAN),
		b(protocol.SettingIPv6, cfg.IPv6),
		b(protocol.SettingSniffing, cfg.Sniffing),
		{Key: protocol.SettingLogLevel, Type: protocol.SettingEnum, Value: cfg.LogLevel, Options: slices.Clone(logLevels)},
	}, nil
}

// SetSetting applies one setting via PATCH /configs and returns its new state.
func (c *Core) SetSetting(ctx context.Context, key string, value any) (protocol.Setting, error) {
	var patch map[string]any
	switch key {
	case protocol.SettingTUN:
		patch = map[string]any{"tun": map[string]any{"enable": value}}
	case protocol.SettingAllowLAN:
		patch = map[string]any{"allow-lan": value}
	case protocol.SettingIPv6:
		patch = map[string]any{"ipv6": value}
	case protocol.SettingSniffing:
		patch = map[string]any{"sniffing": value}
	case protocol.SettingLogLevel:
		patch = map[string]any{"log-level": value}
	default:
		return protocol.Setting{}, fmt.Errorf("setting %q: %w", key, agent.ErrNotFound)
	}
	if err := c.do(ctx, http.MethodPatch, "/configs", patch, nil); err != nil {
		return protocol.Setting{}, err
	}
	list, err := c.Settings(ctx)
	if err != nil {
		return protocol.Setting{}, err
	}
	for _, s := range list {
		if s.Key == key {
			return s, nil
		}
	}
	return protocol.Setting{}, fmt.Errorf("setting %q: %w", key, agent.ErrNotFound)
}

// --- actions ---

var actionPaths = map[string]string{
	protocol.ActionFlushDNS:    "/cache/dns/flush",
	protocol.ActionFlushFakeIP: "/cache/fakeip/flush",
	protocol.ActionUpdateGeo:   "/configs/geo",
}

// Actions lists flush_dns, flush_fakeip and update_geo.
func (c *Core) Actions(context.Context) ([]protocol.Action, error) {
	return []protocol.Action{
		{ID: protocol.ActionFlushDNS},
		{ID: protocol.ActionFlushFakeIP},
		{ID: protocol.ActionUpdateGeo},
	}, nil
}

// RunAction runs one of the actions listed by Actions.
func (c *Core) RunAction(ctx context.Context, id string) error {
	p, ok := actionPaths[id]
	if !ok {
		return fmt.Errorf("action %q: %w", id, agent.ErrNotFound)
	}
	return c.do(ctx, http.MethodPost, p, nil, nil)
}

// --- summary & logs ---

// Summary reports the mode and core version (GET /configs, GET /version). Consumers
// usually wrap it to add the active profile, current node and app version.
func (c *Core) Summary(ctx context.Context) (protocol.Summary, error) {
	cfg, err := c.configs(ctx)
	if err != nil {
		return protocol.Summary{}, err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		return protocol.Summary{}, err
	}
	return protocol.Summary{Mode: strings.ToLower(cfg.Mode), CoreVersion: v.Version}, nil
}

// FollowLogs streams the core's GET /logs at level ("" = info, the core default) and
// calls fn for each line until ctx is cancelled or the stream ends. Feed it to
// agent.PublishLog to stream core logs to controllers:
//
//	go core.FollowLogs(ctx, "debug", a.PublishLog)
func (c *Core) FollowLogs(ctx context.Context, level string, fn func(protocol.LogLine)) error {
	path := "/logs"
	if level != "" {
		path += "?level=" + url.QueryEscape(level)
	}
	resp, err := c.send(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var l struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		fn(protocol.LogLine{Time: time.Now().UnixMilli(), Level: l.Type, Msg: l.Payload})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return sc.Err()
}

// --- transport ---

// statusError is a non-2xx core response.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return fmt.Sprintf("core: %d %s", e.code, e.msg) }

// Unwrap maps core 404/400 onto the agent sentinels so the gateway reports them correctly.
func (e *statusError) Unwrap() error {
	switch e.code {
	case http.StatusNotFound:
		return agent.ErrNotFound
	case http.StatusBadRequest:
		return agent.ErrInvalid
	}
	return nil
}

func (c *Core) send(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		var e struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		return nil, &statusError{code: resp.StatusCode, msg: msg}
	}
	return resp, nil
}

func (c *Core) do(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.send(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}
