package forwarder_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nemu-x/clash-companion/go/forwarder"
	"github.com/Nemu-x/clash-companion/go/internal/testvectors"
)

func TestWhitelistVectors(t *testing.T) {
	var vec struct {
		Cases []struct {
			Method          string `json:"method"`
			Path            string `json:"path"`
			Allowed         bool   `json:"allowed"`
			AllowedReadOnly bool   `json:"allowedReadOnly"`
		} `json:"cases"`
	}
	testvectors.Load(t, "whitelist.json", &vec)
	if len(vec.Cases) == 0 {
		t.Fatal("no whitelist vectors")
	}
	for _, c := range vec.Cases {
		if got := forwarder.Allowed(c.Method, c.Path); got != c.Allowed {
			t.Errorf("Allowed(%s, %s) = %v, want %v", c.Method, c.Path, got, c.Allowed)
		}
		if got := forwarder.AllowedReadOnly(c.Method, c.Path); got != c.AllowedReadOnly {
			t.Errorf("AllowedReadOnly(%s, %s) = %v, want %v", c.Method, c.Path, got, c.AllowedReadOnly)
		}
	}
}

func TestForwardAndRefuse(t *testing.T) {
	// Fake core records the path it received.
	var gotPath, gotAuth string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "core-ok")
	}))
	defer core.Close()

	fwd, err := forwarder.New(core.URL, "core-secret")
	if err != nil {
		t.Fatal(err)
	}

	// Whitelisted call is forwarded with the core secret and path mapping.
	req := httptest.NewRequest(http.MethodPut, "/v1/core/proxies/GroupA", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	fwd.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "core-ok" {
		t.Fatalf("forward failed: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotPath != "/proxies/GroupA" {
		t.Fatalf("core path = %q, want /proxies/GroupA", gotPath)
	}
	if gotAuth != "Bearer core-secret" {
		t.Fatalf("core auth = %q", gotAuth)
	}

	// Non-whitelisted call is refused without contacting the core.
	gotPath = ""
	req2 := httptest.NewRequest(http.MethodGet, "/v1/core/upgrade", nil)
	rec2 := httptest.NewRecorder()
	fwd.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for /upgrade, got %d", rec2.Code)
	}
	if gotPath != "" {
		t.Fatal("core must not be contacted for a non-whitelisted call")
	}
}

func TestReadOnlyAndConfigInjection(t *testing.T) {
	var hits int
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "core-ok")
	}))
	defer core.Close()

	full, err := forwarder.New(core.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	ro, err := forwarder.New(core.URL, "", forwarder.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	serve := func(f *forwarder.Forwarder, method, path string) int {
		rec := httptest.NewRecorder()
		f.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return rec.Code
	}

	// Config load/patch is never forwarded: it could rebind external-controller onto the LAN.
	for _, m := range []string{http.MethodPut, http.MethodPatch} {
		if code := serve(full, m, "/v1/core/configs"); code != http.StatusForbidden {
			t.Fatalf("%s /configs: got %d, want 403", m, code)
		}
	}
	// Read-only refuses writes but forwards reads.
	if code := serve(ro, http.MethodPut, "/v1/core/proxies/GroupA"); code != http.StatusForbidden {
		t.Fatalf("read-only PUT: got %d, want 403", code)
	}
	if hits != 0 {
		t.Fatalf("core contacted %d times for refused calls", hits)
	}
	if code := serve(ro, http.MethodGet, "/v1/core/proxies"); code != http.StatusOK || hits != 1 {
		t.Fatalf("read-only GET: got %d (hits %d)", code, hits)
	}
}
