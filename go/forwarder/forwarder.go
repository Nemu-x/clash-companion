// Package forwarder implements the Phase-2 whitelist forward of /v1/core/* to the
// consumer's localhost mihomo external-controller (PROTOCOL.md §9.1). Only the
// explicitly whitelisted method+path pairs are relayed; everything else — notably
// /upgrade and arbitrary paths — is refused with forbidden, without contacting the core.
package forwarder

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// rule is one whitelist entry. The path is matched as an exact segment list where a
// "{}" segment is a single-segment wildcard (e.g. proxy/group name).
type rule struct {
	method string
	path   string // e.g. "/proxies/{}"
}

// whitelist is the fixed set of forwardable core calls (PROTOCOL.md §9.1). Every entry
// exists in mihomo's external-controller. Nothing that loads or patches configuration
// (PUT/PATCH /configs) is listed: a forged config could rebind external-controller onto
// the LAN and bypass the gateway. Mode and settings go through app capabilities instead.
var whitelist = []rule{
	{http.MethodGet, "/version"},
	{http.MethodGet, "/configs"},
	{http.MethodGet, "/memory"},
	{http.MethodGet, "/traffic"},
	{http.MethodGet, "/logs"},
	{http.MethodGet, "/rules"},
	{http.MethodGet, "/proxies"},
	{http.MethodGet, "/proxies/{}"},
	{http.MethodPut, "/proxies/{}"},
	{http.MethodDelete, "/proxies/{}"},
	{http.MethodGet, "/proxies/{}/delay"},
	{http.MethodGet, "/group"},
	{http.MethodGet, "/group/{}"},
	{http.MethodGet, "/group/{}/delay"},
	{http.MethodGet, "/providers/proxies"},
	{http.MethodGet, "/providers/proxies/{}"},
	{http.MethodPut, "/providers/proxies/{}"},
	{http.MethodGet, "/providers/proxies/{}/healthcheck"},
	{http.MethodGet, "/providers/rules"},
	{http.MethodPut, "/providers/rules/{}"},
	{http.MethodGet, "/connections"},
	{http.MethodDelete, "/connections"},
	{http.MethodDelete, "/connections/{}"},
}

// Option configures a Forwarder.
type Option func(*Forwarder)

// ReadOnly restricts forwarding to whitelisted GET calls, for consumers whose app owns
// core state and must apply writes through its own hooks (PROTOCOL.md §9.1).
func ReadOnly() Option {
	return func(f *Forwarder) { f.readOnly = true }
}

// Forwarder relays whitelisted /v1/core/* requests to the localhost core.
type Forwarder struct {
	proxy    *httputil.ReverseProxy
	readOnly bool
}

// New builds a Forwarder targeting the core at coreURL (e.g. "http://127.0.0.1:9090").
// An optional secret is sent to the core as its bearer token.
func New(coreURL, secret string, opts ...Option) (*Forwarder, error) {
	target, err := url.Parse(coreURL)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	base := rp.Director
	rp.Director = func(r *http.Request) {
		base(r)
		// Map /v1/core/<X> -> /<X> on the core.
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/v1/core")
		r.Host = target.Host
		if secret != "" {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
	}
	rp.FlushInterval = -1 // /traffic, /logs, /connections stream; relay each chunk at once
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, "core unavailable")
	}
	f := &Forwarder{proxy: rp}
	for _, o := range opts {
		o(f)
	}
	return f, nil
}

// ServeHTTP enforces the whitelist then reverse-proxies to the core.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	corePath := strings.TrimPrefix(r.URL.Path, "/v1/core")
	allowed := Allowed
	if f.readOnly {
		allowed = AllowedReadOnly
	}
	if !allowed(r.Method, corePath) {
		writeError(w, http.StatusForbidden, protocol.CodeForbidden, "core call not on whitelist")
		return
	}
	f.proxy.ServeHTTP(w, r)
}

// Allowed reports whether method+corePath is on the whitelist (PROTOCOL.md §9.1).
// corePath is the path on the core (without the /v1/core prefix).
func Allowed(method, corePath string) bool {
	got := splitPath(corePath)
	for _, ru := range whitelist {
		if ru.method != method {
			continue
		}
		if segMatch(splitPath(ru.path), got) {
			return true
		}
	}
	return false
}

// AllowedReadOnly reports whether method+corePath is forwarded in read-only mode: a
// whitelisted GET (PROTOCOL.md §9.1).
func AllowedReadOnly(method, corePath string) bool {
	return method == http.MethodGet && Allowed(method, corePath)
}

func segMatch(pat, got []string) bool {
	if len(pat) != len(got) {
		return false
	}
	for i := range pat {
		if pat[i] == "{}" {
			if got[i] == "" {
				return false
			}
			continue
		}
		if pat[i] != got[i] {
			return false
		}
	}
	return true
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	b, _ := canonjson.Marshal(protocol.Error{Error: protocol.ErrorBody{Code: code, Message: msg}})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.Writer(w).Write(b)
}
