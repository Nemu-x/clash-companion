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

// whitelist is the fixed set of forwardable core calls (PROTOCOL.md §9.1).
var whitelist = []rule{
	{http.MethodGet, "/configs"},
	{http.MethodPut, "/configs"},
	{http.MethodGet, "/proxies"},
	{http.MethodGet, "/proxies/{}"},
	{http.MethodPut, "/proxies/{}"},
	{http.MethodGet, "/group"},
	{http.MethodGet, "/group/{}"},
	{http.MethodPut, "/group/{}"},
	{http.MethodGet, "/traffic"},
	{http.MethodGet, "/connections"},
	{http.MethodGet, "/version"},
	{http.MethodGet, "/logs"},
}

// Forwarder relays whitelisted /v1/core/* requests to the localhost core.
type Forwarder struct {
	proxy *httputil.ReverseProxy
}

// New builds a Forwarder targeting the core at coreURL (e.g. "http://127.0.0.1:9090").
// An optional secret is sent to the core as its bearer token.
func New(coreURL, secret string) (*Forwarder, error) {
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
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		writeError(w, http.StatusBadGateway, protocol.CodeCoreUnavailable, "core unavailable")
	}
	return &Forwarder{proxy: rp}, nil
}

// ServeHTTP enforces the whitelist then reverse-proxies to the core.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	corePath := strings.TrimPrefix(r.URL.Path, "/v1/core")
	if !Allowed(r.Method, corePath) {
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
