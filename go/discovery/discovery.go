// Package discovery implements clashctl mDNS/DNS-SD discovery (PROTOCOL.md §4):
// advertising and browsing the _clashctl._tcp service with the TXT contract
// {app, id, name, ver, fp}. The mDNS transport (mdns.go) is isolated behind this
// package so it is swappable; the TXT codec here is pure and unit-testable.
package discovery

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Nemu-x/clash-companion/go/protocol"
)

// TXT carries the discovery record fields (PROTOCOL.md §4.3).
type TXT struct {
	App  string // consumer app id
	ID   string // deviceId
	Name string // display name
	Ver  int    // protocol major version
	FP   string // TLS fingerprint
}

// txtKeyOrder is the canonical key order when emitting the TXT record.
var txtKeyOrder = []string{"app", "id", "name", "ver", "fp"}

// Encode renders the TXT record as a slice of "key=value" strings in canonical order.
func (t TXT) Encode() []string {
	vals := map[string]string{
		"app": t.App, "id": t.ID, "name": t.Name,
		"ver": strconv.Itoa(t.Ver), "fp": t.FP,
	}
	out := make([]string, 0, len(txtKeyOrder))
	for _, k := range txtKeyOrder {
		out = append(out, k+"="+vals[k])
	}
	return out
}

// DecodeTXT parses "key=value" TXT entries into a TXT. Keys may appear in any order.
// It errors if any required key (app, id, name, ver, fp) is missing.
func DecodeTXT(entries []string) (TXT, error) {
	m := map[string]string{}
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	for _, k := range txtKeyOrder {
		if _, ok := m[k]; !ok {
			return TXT{}, fmt.Errorf("discovery: TXT missing %q", k)
		}
	}
	ver, err := strconv.Atoi(m["ver"])
	if err != nil {
		return TXT{}, fmt.Errorf("discovery: TXT ver %q not an integer", m["ver"])
	}
	return TXT{App: m["app"], ID: m["id"], Name: m["name"], Ver: ver, FP: m["fp"]}, nil
}

// Entry is a discovered agent (TXT fields plus network location).
type Entry struct {
	TXT
	Host  string   // advertised hostname
	Port  int      // gateway port
	Addrs []string // resolved IP addresses
}

// ErrServiceMismatch is returned when an advertisement is not a _clashctl._tcp service.
var ErrServiceMismatch = errors.New("discovery: not a clashctl service")

// MajorMismatch reports whether the entry's protocol major version differs from ours
// (PROTOCOL.md §10).
func (e Entry) MajorMismatch() bool { return e.Ver != protocol.Major }
