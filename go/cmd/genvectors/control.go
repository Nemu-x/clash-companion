package main

import (
	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// --- control: remote-control bodies and gateway validation errors (PROTOCOL.md §8.6–§8.19) ---

// controlBody is one canonical request or response body. Type names the model in
// go/protocol so implementations know what to decode into.
type controlBody struct {
	Name       string `json:"name"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Capability string `json:"capability"`
	Direction  string `json:"direction"` // "request" | "response"
	Type       string `json:"type"`
	Canonical  string `json:"canonical"`
}

// controlError is a request the gateway itself MUST reject, before or without any hook
// returning an error. Agent "full" advertises every capability; "p1" advertises none.
type controlError struct {
	Name   string `json:"name"`
	Agent  string `json:"agent"`
	Auth   bool   `json:"auth"` // send a valid bearer token
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body,omitempty"`
	Status int    `json:"status"`
	Code   string `json:"code"`
}

func controlVectors() any {
	const jp = "🇯🇵 Japan"
	usage := &protocol.Usage{Upload: 1048576, Download: 52428800, Total: 107374182400, Expire: 1798761600}

	b := func(name, method, path, capability, dir, typ string, v any) controlBody {
		s, err := canonjson.MarshalString(v)
		must(err)
		return controlBody{name, method, path, capability, dir, typ, s}
	}
	bodies := []controlBody{
		b("proxies.response", "GET", "/v1/proxies", protocol.CapProxies, "response", "ProxyList", protocol.ProxyList{
			Groups: []protocol.ProxyGroup{
				{Name: "Proxy", Type: "Selector", Now: jp, Selectable: true, Nodes: []protocol.ProxyNode{
					{Name: "Auto", Type: "URLTest", Delay: 87},
					{Name: jp, Type: "Vless", Delay: 112},
					{Name: "DIRECT", Type: "Direct", Delay: 0},
				}},
				{Name: "Auto", Type: "URLTest", Now: jp, Fixed: jp, Selectable: true, Nodes: []protocol.ProxyNode{
					{Name: jp, Type: "Vless", Delay: 112},
				}},
				{Name: "Balance", Type: "LoadBalance", Now: "", Selectable: false, Nodes: []protocol.ProxyNode{}},
			},
		}),
		b("select.request", "POST", "/v1/proxies/select", protocol.CapSelect, "request", "SelectRequest",
			protocol.SelectRequest{Group: "Proxy", Node: jp}),
		b("select.response", "POST", "/v1/proxies/select", protocol.CapSelect, "response", "SelectResponse",
			protocol.SelectResponse{OK: true, Group: "Proxy", Now: jp}),
		b("unfix.request", "POST", "/v1/proxies/unfix", protocol.CapUnfix, "request", "UnfixRequest",
			protocol.UnfixRequest{Group: "Auto"}),
		b("unfix.response", "POST", "/v1/proxies/unfix", protocol.CapUnfix, "response", "SelectResponse",
			protocol.SelectResponse{OK: true, Group: "Auto", Now: "HK-01"}),
		b("delay.request.group", "POST", "/v1/proxies/delay", protocol.CapDelay, "request", "DelayRequest",
			protocol.DelayRequest{Group: "Auto"}),
		b("delay.request.node", "POST", "/v1/proxies/delay", protocol.CapDelay, "request", "DelayRequest",
			protocol.DelayRequest{Group: "Proxy", Node: jp, URL: "https://cp.cloudflare.com/generate_204", Timeout: 3000}),
		b("delay.response", "POST", "/v1/proxies/delay", protocol.CapDelay, "response", "DelayResponse",
			protocol.DelayResponse{OK: true, Delays: []protocol.Delay{{Name: "HK-01", Delay: 64}, {Name: jp, Delay: 0}}}),
		b("mode.get.response", "GET", "/v1/mode", protocol.CapMode, "response", "ModeState",
			protocol.ModeState{Mode: protocol.ModeRule, Modes: []string{protocol.ModeRule, protocol.ModeGlobal, protocol.ModeDirect}}),
		b("mode.set.request", "POST", "/v1/mode", protocol.CapMode, "request", "ModeRequest",
			protocol.ModeRequest{Mode: protocol.ModeGlobal}),
		b("mode.set.response", "POST", "/v1/mode", protocol.CapMode, "response", "ModeResponse",
			protocol.ModeResponse{OK: true, Mode: protocol.ModeGlobal}),
		b("profiles.response", "GET", "/v1/profiles", protocol.CapProfiles, "response", "ProfileList", protocol.ProfileList{
			Active: "p-1",
			Profiles: []protocol.Profile{
				{ID: "p-1", Name: "Мой VPN", Type: "remote", UpdatedAt: 1792540800, Usage: usage},
				{ID: "p-2", Name: "local.yaml", Type: "local"},
			},
		}),
		b("profiles.select.request", "POST", "/v1/profiles/select", protocol.CapProfiles, "request", "ProfileRequest",
			protocol.ProfileRequest{ID: "p-2"}),
		b("profiles.select.response", "POST", "/v1/profiles/select", protocol.CapProfiles, "response", "ProfileSelectResponse",
			protocol.ProfileSelectResponse{OK: true, Active: "p-2"}),
		b("profiles.update.request.all", "POST", "/v1/profiles/update", protocol.CapProfileUpdate, "request", "ProfileRequest",
			protocol.ProfileRequest{}),
		b("profiles.delete.request", "POST", "/v1/profiles/delete", protocol.CapProfileDelete, "request", "ProfileRequest",
			protocol.ProfileRequest{ID: "p-2"}),
		b("ok.response", "POST", "/v1/profiles/update", protocol.CapProfileUpdate, "response", "OKResponse",
			protocol.OKResponse{OK: true}),
		b("providers.response", "GET", "/v1/providers", protocol.CapProviders, "response", "ProviderList", protocol.ProviderList{
			Providers: []protocol.Provider{
				{Name: "sub1", Kind: protocol.ProviderProxy, Vehicle: "http", Count: 42, UpdatedAt: 1792540800, Usage: usage},
				{Name: "ads", Kind: protocol.ProviderRule, Vehicle: "http", Count: 120345, UpdatedAt: 1792454400},
			},
		}),
		b("providers.update.request", "POST", "/v1/providers/update", protocol.CapProviders, "request", "ProviderRequest",
			protocol.ProviderRequest{Kind: protocol.ProviderRule, Name: "ads"}),
		b("providers.healthcheck.request", "POST", "/v1/providers/healthcheck", protocol.CapProviders, "request", "ProviderRequest",
			protocol.ProviderRequest{Kind: protocol.ProviderProxy, Name: "sub1"}),
		b("connections.response", "GET", "/v1/connections", protocol.CapConnections, "response", "ConnectionList", protocol.ConnectionList{
			UploadTotal: 1048576, DownloadTotal: 734003200,
			Connections: []protocol.Connection{{
				ID: "1f2e3d4c-0000-4000-8000-000000000001", Host: "www.youtube.com:443", Network: "tcp", Process: "",
				Rule: "DomainSuffix(youtube.com)", Chains: []string{jp, "Proxy"}, Upload: 2048, Download: 1048576, Start: 1792540800123,
			}},
		}),
		b("connections.close.request.one", "POST", "/v1/connections/close", protocol.CapConnections, "request", "CloseRequest",
			protocol.CloseRequest{ID: "1f2e3d4c-0000-4000-8000-000000000001"}),
		b("connections.close.request.all", "POST", "/v1/connections/close", protocol.CapConnections, "request", "CloseRequest",
			protocol.CloseRequest{}),
		b("connections.close.response", "POST", "/v1/connections/close", protocol.CapConnections, "response", "CloseResponse",
			protocol.CloseResponse{OK: true, Closed: 17}),
		b("traffic.response", "GET", "/v1/traffic", protocol.CapTraffic, "response", "Traffic",
			protocol.Traffic{Up: 12800, Down: 3276800, UpTotal: 1048576, DownTotal: 734003200}),
		b("logs.response", "GET", "/v1/logs?level=warning&limit=2", protocol.CapLogs, "response", "LogList", protocol.LogList{
			Lines: []protocol.LogLine{
				{Time: 1792540800123, Level: "warning", Msg: "dial HK-01 failed: i/o timeout"},
				{Time: 1792540801456, Level: "error", Msg: `rule-set "ads" update failed`},
			},
		}),
		b("settings.response", "GET", "/v1/settings", protocol.CapSettings, "response", "SettingList", protocol.SettingList{
			Settings: []protocol.Setting{
				{Key: protocol.SettingTUN, Type: protocol.SettingBool, Value: true},
				{Key: protocol.SettingLogLevel, Type: protocol.SettingEnum, Value: "info", Options: []string{"silent", "error", "warning", "info", "debug"}},
				{Key: "bypass_lan_apps", Type: protocol.SettingBool, Value: false, Label: "Обход LAN-приложений"},
			},
		}),
		b("settings.set.request.bool", "POST", "/v1/settings", protocol.CapSettings, "request", "SettingRequest",
			protocol.SettingRequest{Key: protocol.SettingTUN, Value: false}),
		b("settings.set.request.enum", "POST", "/v1/settings", protocol.CapSettings, "request", "SettingRequest",
			protocol.SettingRequest{Key: protocol.SettingLogLevel, Value: "debug"}),
		b("settings.set.response", "POST", "/v1/settings", protocol.CapSettings, "response", "SettingResponse",
			protocol.SettingResponse{OK: true, Setting: protocol.Setting{Key: protocol.SettingTUN, Type: protocol.SettingBool, Value: false}}),
		b("actions.response", "GET", "/v1/actions", protocol.CapActions, "response", "ActionList", protocol.ActionList{
			Actions: []protocol.Action{{ID: protocol.ActionFlushDNS}, {ID: protocol.ActionUpdateGeo}, {ID: "clear_cache", Label: "Очистить кэш"}},
		}),
		b("actions.run.request", "POST", "/v1/actions", protocol.CapActions, "request", "ActionRequest",
			protocol.ActionRequest{Action: protocol.ActionFlushDNS}),
		b("status.response.summary", "GET", "/v1/status", protocol.CapStatus, "response", "Status", protocol.Status{
			ID: "AAECAwQFBgcICQoLDA0ODw", Name: "Living Room TV", App: "clashfest", Ver: protocol.Major, Power: protocol.PowerOn,
			Capabilities: []string{protocol.CapStatus, protocol.CapPower, protocol.CapSubscription, protocol.CapRename,
				protocol.CapUnpair, protocol.CapProxies, protocol.CapSelect, protocol.CapMode, protocol.CapEvents},
			Summary: &protocol.Summary{Mode: protocol.ModeRule, Profile: "Мой VPN", Proxy: jp, AppVersion: "2.4.0", CoreVersion: "v1.19.32"},
		}),
		b("status.response.no_summary", "GET", "/v1/status", protocol.CapStatus, "response", "Status", protocol.Status{
			ID: "AAECAwQFBgcICQoLDA0ODw", Name: "Living Room TV", App: "clashfest", Ver: protocol.Major, Power: protocol.PowerOff,
			Capabilities: []string{protocol.CapStatus, protocol.CapPower, protocol.CapSubscription, protocol.CapRename},
		}),
		b("unpair.response", "POST", "/v1/unpair", protocol.CapUnpair, "response", "OKResponse", protocol.OKResponse{OK: true}),
		b("events.changed", "GET", "/v1/events", protocol.CapEvents, "event", "Changed",
			protocol.Changed{Resource: protocol.ResourceProxies}),
	}

	// events: exact SSE frames (PROTOCOL.md §9.2) — "event: <type>\ndata: <canonical JSON>\n\n".
	type sseFrame struct {
		Type  string `json:"type"`
		Data  string `json:"data"`
		Frame string `json:"frame"`
	}
	f := func(typ string, v any) sseFrame {
		s, err := canonjson.MarshalString(v)
		must(err)
		return sseFrame{typ, s, "event: " + typ + "\ndata: " + s + "\n\n"}
	}
	frames := []sseFrame{
		f(protocol.EventChanged, protocol.Changed{Resource: protocol.ResourceMode}),
		f(protocol.EventTraffic, protocol.Traffic{Up: 12800, Down: 3276800, UpTotal: 1048576, DownTotal: 734003200}),
		f(protocol.EventLog, protocol.LogLine{Time: 1792540800123, Level: "error", Msg: "line1\nline2 «ü»"}),
	}

	e := func(name, agent string, auth bool, method, path, body string, status int, code string) controlError {
		return controlError{name, agent, auth, method, path, body, status, code}
	}
	const bad, nf = protocol.CodeBadRequest, protocol.CodeNotFound
	errs := []controlError{
		e("gated.unauthorized_first", "p1", false, "GET", "/v1/proxies", "", 401, protocol.CodeUnauthorized),
		e("gated.capability_absent", "p1", true, "GET", "/v1/proxies", "", 404, nf),
		e("gated.capability_absent_post", "p1", true, "POST", "/v1/mode", `{"mode":"rule"}`, 404, nf),
		e("body.invalid_json", "full", true, "POST", "/v1/proxies/select", `{"group":`, 400, bad),
		e("select.missing_node", "full", true, "POST", "/v1/proxies/select", `{"group":"Proxy"}`, 400, bad),
		e("unfix.missing_group", "full", true, "POST", "/v1/proxies/unfix", `{}`, 400, bad),
		e("delay.missing_group", "full", true, "POST", "/v1/proxies/delay", `{}`, 400, bad),
		e("delay.timeout_low", "full", true, "POST", "/v1/proxies/delay", `{"group":"Auto","timeout":99}`, 400, bad),
		e("delay.timeout_high", "full", true, "POST", "/v1/proxies/delay", `{"group":"Auto","timeout":30001}`, 400, bad),
		e("delay.url_not_http", "full", true, "POST", "/v1/proxies/delay", `{"group":"Auto","url":"file:///etc/passwd"}`, 400, bad),
		e("mode.invalid", "full", true, "POST", "/v1/mode", `{"mode":"Rule"}`, 400, bad),
		e("profiles.select.missing_id", "full", true, "POST", "/v1/profiles/select", `{}`, 400, bad),
		e("profiles.delete.missing_id", "full", true, "POST", "/v1/profiles/delete", `{}`, 400, bad),
		e("providers.update.bad_kind", "full", true, "POST", "/v1/providers/update", `{"kind":"proxies","name":"sub1"}`, 400, bad),
		e("providers.healthcheck.rule_kind", "full", true, "POST", "/v1/providers/healthcheck", `{"kind":"rule","name":"ads"}`, 400, bad),
		e("logs.bad_level", "full", true, "GET", "/v1/logs?level=trace", "", 400, bad),
		e("logs.limit_zero", "full", true, "GET", "/v1/logs?limit=0", "", 400, bad),
		e("logs.limit_high", "full", true, "GET", "/v1/logs?limit=1001", "", 400, bad),
		e("settings.missing_key", "full", true, "POST", "/v1/settings", `{"value":true}`, 400, bad),
		e("actions.missing_action", "full", true, "POST", "/v1/actions", `{}`, 400, bad),
		e("unpair.unauthorized", "full", false, "POST", "/v1/unpair", `{}`, 401, protocol.CodeUnauthorized),
		e("events.unauthorized", "full", false, "GET", "/v1/events", "", 401, protocol.CodeUnauthorized),
		e("events.bad_level", "full", true, "GET", "/v1/events?topics=logs&level=trace", "", 400, bad),
	}

	return map[string]any{
		"note":   "Remote-control bodies per PROTOCOL.md §8.6–§8.19. bodies: decode `canonical` into the named model and re-encode canonically (§3.4); bytes must match. events: exact SSE frames of GET /v1/events (§9.2). errors: requests the gateway itself must reject with `status`/`code`; agent \"full\" advertises every capability, \"p1\" none; auth=false sends no bearer token.",
		"bodies": bodies,
		"events": frames,
		"errors": errs,
	}
}
