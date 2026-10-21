package agent

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// remoteCaps maps each remote-control capability to the hook interface that provides it,
// in advertisement order (PROTOCOL.md §8.3).
var remoteCaps = []struct {
	tag string
	has func(Hooks) bool
}{
	{protocol.CapProxies, implements[ProxyLister]},
	{protocol.CapSelect, implements[ProxySelector]},
	{protocol.CapUnfix, implements[ProxyUnfixer]},
	{protocol.CapDelay, implements[DelayTester]},
	{protocol.CapMode, implements[ModeController]},
	{protocol.CapProfiles, implements[ProfileLister]},
	{protocol.CapProfileUpdate, implements[ProfileUpdater]},
	{protocol.CapProfileDelete, implements[ProfileDeleter]},
	{protocol.CapProviders, implements[ProviderController]},
	{protocol.CapConnections, implements[ConnectionController]},
	{protocol.CapTraffic, implements[TrafficReporter]},
	{protocol.CapLogs, implements[LogReader]},
	{protocol.CapSettings, implements[SettingsController]},
	{protocol.CapActions, implements[ActionRunner]},
}

func implements[T any](h Hooks) bool {
	_, ok := h.(T)
	return ok
}

// detectRemoteCaps returns the remote capabilities the hooks implement, minus disabled ones.
func detectRemoteCaps(h Hooks, disabled []string) []string {
	var caps []string
	for _, c := range remoteCaps {
		if c.has(h) && !slices.Contains(disabled, c.tag) {
			caps = append(caps, c.tag)
		}
	}
	return caps
}

// mountRemote registers the remote-control endpoints (PROTOCOL.md §8.6–§8.19).
func (a *Agent) mountRemote(mux *http.ServeMux) {
	routes := []struct {
		pattern string
		tag     string
		h       authHandler
	}{
		{"GET /v1/proxies", protocol.CapProxies, a.handleProxies},
		{"POST /v1/proxies/select", protocol.CapSelect, a.handleSelect},
		{"POST /v1/proxies/unfix", protocol.CapUnfix, a.handleUnfix},
		{"POST /v1/proxies/delay", protocol.CapDelay, a.handleDelay},
		{"GET /v1/mode", protocol.CapMode, a.handleGetMode},
		{"POST /v1/mode", protocol.CapMode, a.handleSetMode},
		{"GET /v1/profiles", protocol.CapProfiles, a.handleProfiles},
		{"POST /v1/profiles/select", protocol.CapProfiles, a.handleSelectProfile},
		{"POST /v1/profiles/update", protocol.CapProfileUpdate, a.handleUpdateProfile},
		{"POST /v1/profiles/delete", protocol.CapProfileDelete, a.handleDeleteProfile},
		{"GET /v1/providers", protocol.CapProviders, a.handleProviders},
		{"POST /v1/providers/update", protocol.CapProviders, a.handleUpdateProvider},
		{"POST /v1/providers/healthcheck", protocol.CapProviders, a.handleHealthCheckProvider},
		{"GET /v1/connections", protocol.CapConnections, a.handleConnections},
		{"POST /v1/connections/close", protocol.CapConnections, a.handleCloseConnections},
		{"GET /v1/traffic", protocol.CapTraffic, a.handleTraffic},
		{"GET /v1/logs", protocol.CapLogs, a.handleLogs},
		{"GET /v1/settings", protocol.CapSettings, a.handleSettings},
		{"POST /v1/settings", protocol.CapSettings, a.handleSetSetting},
		{"GET /v1/actions", protocol.CapActions, a.handleActions},
		{"POST /v1/actions", protocol.CapActions, a.handleRunAction},
	}
	for _, rt := range routes {
		mux.Handle(rt.pattern, a.gated(rt.tag, rt.h))
	}
}

// gated authenticates first, then refuses a capability the agent does not advertise
// with not_found, without invoking any hook (PROTOCOL.md §8.3).
func (a *Agent) gated(tag string, next authHandler) http.Handler {
	return a.auth(func(w http.ResponseWriter, r *http.Request, e pairing.Entry) {
		if !slices.Contains(a.remote, tag) {
			writeError(w, http.StatusNotFound, protocol.CodeNotFound, "capability not supported: "+tag)
			return
		}
		next(w, r, e)
	})
}

// hookError maps a hook error to the protocol error model (PROTOCOL.md §5.5).
func hookError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, protocol.CodeNotFound, err.Error())
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, err.Error())
	default:
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, err.Error())
	}
}

func badRequest(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusBadRequest, protocol.CodeBadRequest, msg)
}

// orEmpty keeps empty lists encoded as [] rather than null (PROTOCOL.md §8.3).
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// --- proxies ---

func (a *Agent) handleProxies(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	groups, err := a.cfg.Hooks.(ProxyLister).ProxyGroups(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	groups = orEmpty(groups)
	for i := range groups {
		groups[i].Nodes = orEmpty(groups[i].Nodes)
	}
	writeJSON(w, http.StatusOK, protocol.ProxyList{Groups: groups})
}

func (a *Agent) handleSelect(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.SelectRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Group == "" || req.Node == "" {
		badRequest(w, "group and node are required")
		return
	}
	now, err := a.cfg.Hooks.(ProxySelector).SelectProxy(r.Context(), req.Group, req.Node)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProxies, protocol.EventStatus)
	writeJSON(w, http.StatusOK, protocol.SelectResponse{OK: true, Group: req.Group, Now: now})
}

func (a *Agent) handleUnfix(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.UnfixRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Group == "" {
		badRequest(w, "group is required")
		return
	}
	now, err := a.cfg.Hooks.(ProxyUnfixer).UnfixProxy(r.Context(), req.Group)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProxies, protocol.EventStatus)
	writeJSON(w, http.StatusOK, protocol.SelectResponse{OK: true, Group: req.Group, Now: now})
}

func (a *Agent) handleDelay(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.DelayRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Group == "" {
		badRequest(w, "group is required")
		return
	}
	switch {
	case req.Timeout == 0:
		req.Timeout = protocol.DefaultDelayTimeout
	case req.Timeout < protocol.MinDelayTimeout || req.Timeout > protocol.MaxDelayTimeout:
		badRequest(w, "timeout must be 0 or within 100..30000 ms")
		return
	}
	if req.URL != "" {
		u, err := url.Parse(req.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			badRequest(w, "url must be an absolute http(s) URL")
			return
		}
	}
	delays, err := a.cfg.Hooks.(DelayTester).TestDelay(r.Context(), req)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProxies)
	writeJSON(w, http.StatusOK, protocol.DelayResponse{OK: true, Delays: orEmpty(delays)})
}

// --- mode ---

func validMode(m string) bool {
	return m == protocol.ModeRule || m == protocol.ModeGlobal || m == protocol.ModeDirect
}

func (a *Agent) handleGetMode(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	st, err := a.cfg.Hooks.(ModeController).Mode(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	st.Modes = orEmpty(st.Modes)
	writeJSON(w, http.StatusOK, st)
}

func (a *Agent) handleSetMode(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.ModeRequest
	if !decode(w, r, &req) {
		return
	}
	if !validMode(req.Mode) {
		badRequest(w, "mode must be rule, global or direct")
		return
	}
	mode, err := a.cfg.Hooks.(ModeController).SetMode(r.Context(), req.Mode)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceMode, protocol.EventStatus)
	writeJSON(w, http.StatusOK, protocol.ModeResponse{OK: true, Mode: mode})
}

// --- profiles ---

func (a *Agent) handleProfiles(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	list, err := a.cfg.Hooks.(ProfileLister).Profiles(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	list.Profiles = orEmpty(list.Profiles)
	writeJSON(w, http.StatusOK, list)
}

func (a *Agent) handleSelectProfile(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.ProfileRequest
	if !decode(w, r, &req) {
		return
	}
	if req.ID == "" {
		badRequest(w, "id is required")
		return
	}
	active, err := a.cfg.Hooks.(ProfileLister).SelectProfile(r.Context(), req.ID)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProfiles, protocol.ResourceProxies, protocol.ResourceProviders, protocol.EventStatus)
	writeJSON(w, http.StatusOK, protocol.ProfileSelectResponse{OK: true, Active: active})
}

func (a *Agent) handleUpdateProfile(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.ProfileRequest
	if !decode(w, r, &req) {
		return
	}
	if err := a.cfg.Hooks.(ProfileUpdater).UpdateProfile(r.Context(), req.ID); err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProfiles, protocol.ResourceProxies, protocol.ResourceProviders)
	writeJSON(w, http.StatusOK, protocol.OKResponse{OK: true})
}

func (a *Agent) handleDeleteProfile(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.ProfileRequest
	if !decode(w, r, &req) {
		return
	}
	if req.ID == "" {
		badRequest(w, "id is required")
		return
	}
	if err := a.cfg.Hooks.(ProfileDeleter).DeleteProfile(r.Context(), req.ID); err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProfiles)
	writeJSON(w, http.StatusOK, protocol.OKResponse{OK: true})
}

// --- providers ---

func (a *Agent) handleProviders(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	list, err := a.cfg.Hooks.(ProviderController).Providers(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.ProviderList{Providers: orEmpty(list)})
}

func decodeProvider(w http.ResponseWriter, r *http.Request, kinds ...string) (protocol.ProviderRequest, bool) {
	var req protocol.ProviderRequest
	if !decode(w, r, &req) {
		return req, false
	}
	if req.Name == "" || !slices.Contains(kinds, req.Kind) {
		badRequest(w, "name and kind ("+strings.Join(kinds, " or ")+") are required")
		return req, false
	}
	return req, true
}

func (a *Agent) handleUpdateProvider(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	req, ok := decodeProvider(w, r, protocol.ProviderProxy, protocol.ProviderRule)
	if !ok {
		return
	}
	if err := a.cfg.Hooks.(ProviderController).UpdateProvider(r.Context(), req.Kind, req.Name); err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProviders, protocol.ResourceProxies)
	writeJSON(w, http.StatusOK, protocol.OKResponse{OK: true})
}

func (a *Agent) handleHealthCheckProvider(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	req, ok := decodeProvider(w, r, protocol.ProviderProxy)
	if !ok {
		return
	}
	if err := a.cfg.Hooks.(ProviderController).HealthCheckProvider(r.Context(), req.Name); err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceProxies)
	writeJSON(w, http.StatusOK, protocol.OKResponse{OK: true})
}

// --- connections & traffic ---

func (a *Agent) handleConnections(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	list, err := a.cfg.Hooks.(ConnectionController).Connections(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	list.Connections = orEmpty(list.Connections)
	for i := range list.Connections {
		list.Connections[i].Chains = orEmpty(list.Connections[i].Chains)
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *Agent) handleCloseConnections(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.CloseRequest
	if !decode(w, r, &req) {
		return
	}
	n, err := a.cfg.Hooks.(ConnectionController).CloseConnections(r.Context(), req.ID)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceConnections)
	writeJSON(w, http.StatusOK, protocol.CloseResponse{OK: true, Closed: n})
}

func (a *Agent) handleTraffic(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	t, err := a.cfg.Hooks.(TrafficReporter).Traffic(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// --- logs ---

func (a *Agent) handleLogs(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	q := r.URL.Query()
	level := q.Get("level")
	if level != "" && !slices.Contains(protocol.LogLevels, level) {
		badRequest(w, "level must be one of "+strings.Join(protocol.LogLevels, ", "))
		return
	}
	limit := protocol.DefaultLogLimit
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > protocol.MaxLogLimit {
			badRequest(w, "limit must be within 1..1000")
			return
		}
		limit = n
	}
	lines, err := a.cfg.Hooks.(LogReader).Logs(r.Context(), level, limit)
	if err != nil {
		hookError(w, err)
		return
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	writeJSON(w, http.StatusOK, protocol.LogList{Lines: orEmpty(lines)})
}

// --- settings & actions ---

func (a *Agent) handleSettings(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	list, err := a.cfg.Hooks.(SettingsController).Settings(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.SettingList{Settings: orEmpty(list)})
}

func (a *Agent) handleSetSetting(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.SettingRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Key == "" {
		badRequest(w, "key is required")
		return
	}
	sc := a.cfg.Hooks.(SettingsController)
	list, err := sc.Settings(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	i := slices.IndexFunc(list, func(s protocol.Setting) bool { return s.Key == req.Key })
	if i < 0 {
		writeError(w, http.StatusNotFound, protocol.CodeNotFound, "unknown setting: "+req.Key)
		return
	}
	if msg := checkSettingValue(list[i], req.Value); msg != "" {
		badRequest(w, msg)
		return
	}
	s, err := sc.SetSetting(r.Context(), req.Key, req.Value)
	if err != nil {
		hookError(w, err)
		return
	}
	a.Notify(protocol.ResourceSettings)
	writeJSON(w, http.StatusOK, protocol.SettingResponse{OK: true, Setting: s})
}

// checkSettingValue validates value against the setting's type and options; it returns an
// error message, or "" when valid.
func checkSettingValue(s protocol.Setting, value any) string {
	switch s.Type {
	case protocol.SettingBool:
		if _, ok := value.(bool); !ok {
			return "value of " + s.Key + " must be a boolean"
		}
	case protocol.SettingEnum:
		v, ok := value.(string)
		if !ok || !slices.Contains(s.Options, v) {
			return "value of " + s.Key + " must be one of " + strings.Join(s.Options, ", ")
		}
	default:
		return "setting " + s.Key + " has an unknown type"
	}
	return ""
}

func (a *Agent) handleActions(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	list, err := a.cfg.Hooks.(ActionRunner).Actions(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.ActionList{Actions: orEmpty(list)})
}

func (a *Agent) handleRunAction(w http.ResponseWriter, r *http.Request, _ pairing.Entry) {
	var req protocol.ActionRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Action == "" {
		badRequest(w, "action is required")
		return
	}
	ar := a.cfg.Hooks.(ActionRunner)
	list, err := ar.Actions(r.Context())
	if err != nil {
		hookError(w, err)
		return
	}
	if !slices.ContainsFunc(list, func(x protocol.Action) bool { return x.ID == req.Action }) {
		writeError(w, http.StatusNotFound, protocol.CodeNotFound, "unknown action: "+req.Action)
		return
	}
	if err := ar.RunAction(r.Context(), req.Action); err != nil {
		hookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.OKResponse{OK: true})
}
