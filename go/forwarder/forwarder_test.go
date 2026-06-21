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
			Method  string `json:"method"`
			Path    string `json:"path"`
			Allowed bool   `json:"allowed"`
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
