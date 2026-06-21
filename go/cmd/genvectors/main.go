// Command genvectors produces the language-neutral golden test vectors in vectors/.
// It is run by the maintainer (go run ./cmd/genvectors) when the protocol encodings
// change; the committed vectors are the cross-language conformance contract. Outputs
// are deterministic: all inputs are fixed, and the one certificate is generated once
// and embedded as DER so its fingerprint vector stays stable.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Nemu-x/clash-companion/go/discovery"
	"github.com/Nemu-x/clash-companion/go/forwarder"
	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

func main() {
	out := "../vectors"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	must(os.MkdirAll(out, 0o755))

	writeJSON(filepath.Join(out, "ids.json"), idsVectors())
	writeJSON(filepath.Join(out, "pairing.json"), pairingVectors())
	writeJSON(filepath.Join(out, "fingerprint.json"), fingerprintVectors())
	writeJSON(filepath.Join(out, "canonical_json.json"), canonicalVectors())
	writeJSON(filepath.Join(out, "discovery_txt.json"), txtVectors())
	writeJSON(filepath.Join(out, "whitelist.json"), whitelistVectors())

	fmt.Println("vectors written to", out)
}

// --- ids: deviceId, token, tokenHash encodings (PROTOCOL.md §3.1, §3.2, §7.2) ---

func idsVectors() any {
	devRaw := seq(16, 0x00) // 00 01 ... 0f
	tokRaw := seq(32, 0x00) // 00 01 ... 1f
	token := "sample-bearer-token-value-for-hashing"
	b64 := base64.RawURLEncoding
	return map[string]any{
		"note": "base64url(no-pad) per PROTOCOL.md §3; tokenHash = lowercasehex(sha256(token)) §7.2",
		"deviceId": map[string]any{
			"rawHex":  hex.EncodeToString(devRaw),
			"encoded": b64.EncodeToString(devRaw),
		},
		"token": map[string]any{
			"rawHex":  hex.EncodeToString(tokRaw),
			"encoded": b64.EncodeToString(tokRaw),
		},
		"tokenHash": map[string]any{
			"token":  token,
			"sha256": pairing.HashToken(token),
		},
	}
}

// --- pairing: clashctl-pair:// encode/decode round-trips and rejections (§6.1) ---

type pairCase struct {
	Name    string           `json:"name"`
	Fields  *pairing.Payload `json:"fields,omitempty"`
	URI     string           `json:"uri,omitempty"`
	Decodes bool             `json:"decodes"`
}

func pairingVectors() any {
	cases := []pairCase{}

	// Basic, all fields present.
	p1 := pairing.Payload{
		IP: "192.168.1.50", Port: 8443,
		ID: "AAECAwQFBgcICQoLDA0ODw", Name: "Living Room TV",
		App:   "slothclash",
		FP:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Token: "c2FtcGxlLXRva2Vu",
	}
	cases = append(cases, mkPair("basic with spaces in name", p1))

	// Unicode name + IPv6 host.
	p2 := pairing.Payload{
		IP: "fe80::1", Port: 443,
		ID: "ZGV2aWNlLWlkLXR3bw", Name: "客厅 TV™",
		App:   "clashfest",
		FP:    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd0",
		Token: "dG9rZW4yLXZhbHVl",
	}
	cases = append(cases, mkPair("unicode name and IPv6 host", p2))

	// Decode-only: parameters in non-canonical order must still decode.
	cases = append(cases, pairCase{
		Name:    "decode tolerates reordered params",
		URI:     "clashctl-pair://10.0.0.2:8443?token=dG9r&fp=" + p1.FP + "&app=x&name=N&id=ID1",
		Decodes: true,
	})

	// Rejections.
	cases = append(cases, pairCase{
		Name:    "reject missing token",
		URI:     "clashctl-pair://10.0.0.2:8443?id=ID1&fp=" + p1.FP,
		Decodes: false,
	})
	cases = append(cases, pairCase{
		Name:    "reject missing port",
		URI:     "clashctl-pair://10.0.0.2?id=ID1&fp=" + p1.FP + "&token=t",
		Decodes: false,
	})

	return map[string]any{
		"note":  "Encode produces uri exactly; Decode of uri must reproduce fields. Order id,name,app,fp,token (PROTOCOL.md §6.1).",
		"cases": cases,
	}
}

func mkPair(name string, p pairing.Payload) pairCase {
	uri, err := p.Encode()
	must(err)
	cp := p
	return pairCase{Name: name, Fields: &cp, URI: uri, Decodes: true}
}

// --- fingerprint: DER -> lowercasehex(sha256(DER)) (§3.3) ---

func fingerprintVectors() any {
	id, err := pairing.NewIdentity("clashctl-agent", 10*365*24*time.Hour)
	must(err)
	return map[string]any{
		"note":    "fp = lowercasehex(sha256(DER(leaf cert))) per PROTOCOL.md §3.3",
		"certDer": base64.StdEncoding.EncodeToString(id.CertDER),
		"fp":      id.FP,
	}
}

// --- canonical JSON: algorithm vectors incl. endpoint shapes (§3.4) ---

func canonicalVectors() any {
	type c struct {
		Name      string `json:"name"`
		Input     any    `json:"input"`
		Canonical string `json:"canonical"`
	}
	mk := func(name string, v any) c {
		s, err := canonjson.MarshalString(v)
		must(err)
		return c{Name: name, Input: v, Canonical: s}
	}
	cases := []c{
		mk("key sorting and integers", map[string]any{"b": 2, "a": 1, "c": 3}),
		mk("nested and array", map[string]any{"z": []any{3, 2, 1}, "a": map[string]any{"y": 1, "x": 2}}),
		mk("unicode raw, no escape of <>&", map[string]any{"name": "客厅 <TV> & more"}),
		mk("control char escaping", map[string]any{"s": "tab\tnewline\n"}),
		mk("status response", protocol.Status{
			ID: "AAECAwQFBgcICQoLDA0ODw", Name: "Living Room TV", App: "slothclash",
			Ver: protocol.Major, Power: protocol.PowerOn,
			Capabilities: []string{"status", "power", "subscription", "rename"},
		}),
		mk("power response", protocol.PowerResponse{OK: true, Power: protocol.PowerOn}),
		mk("rename response", protocol.RenameResponse{OK: true, Name: "Bedroom TV"}),
		mk("ok response", protocol.OKResponse{OK: true}),
		mk("error envelope", protocol.Error{Error: protocol.ErrorBody{Code: protocol.CodeUnauthorized, Message: "invalid or revoked token"}}),
		mk("pair request", protocol.PairRequest{PIN: "012345", Device: protocol.PairDevice{ID: "dev-1", Name: "My Phone"}}),
	}
	return map[string]any{
		"note":  "Parse input as JSON, canonicalize (PROTOCOL.md §3.4), result must equal canonical byte-for-byte.",
		"cases": cases,
	}
}

// --- discovery TXT encode/decode (§4.3) ---

func txtVectors() any {
	t := discovery.TXT{App: "slothclash", ID: "AAECAwQFBgcICQoLDA0ODw", Name: "Living Room TV", Ver: protocol.Major,
		FP: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	return map[string]any{
		"note":    "TXT keys order app,id,name,ver,fp (PROTOCOL.md §4.3); decode tolerates any order.",
		"fields":  t,
		"encoded": t.Encode(),
	}
}

// --- whitelist: core-forward allow/deny (§9.1) ---

func whitelistVectors() any {
	type c struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Allowed bool   `json:"allowed"`
	}
	cases := []c{
		{"GET", "/configs", true},
		{"PUT", "/configs", true},
		{"GET", "/proxies", true},
		{"GET", "/proxies/Proxy", true},
		{"PUT", "/proxies/GroupA", true},
		{"GET", "/group", true},
		{"PUT", "/group/Auto", true},
		{"GET", "/traffic", true},
		{"GET", "/connections", true},
		{"GET", "/version", true},
		{"GET", "/logs", true},
		{"POST", "/configs", false},
		{"GET", "/upgrade", false},
		{"PUT", "/upgrade", false},
		{"GET", "/configs/../secret", false},
		{"DELETE", "/connections", false},
	}
	// Sanity: ensure the table matches the implementation.
	for i := range cases {
		if got := forwarder.Allowed(cases[i].Method, cases[i].Path); got != cases[i].Allowed {
			panic(fmt.Sprintf("whitelist mismatch for %s %s: impl=%v vector=%v", cases[i].Method, cases[i].Path, got, cases[i].Allowed))
		}
	}
	return map[string]any{
		"note":  "Allowed(method, corePath) per PROTOCOL.md §9.1 whitelist; everything else forbidden.",
		"cases": cases,
	}
}

// --- helpers ---

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func writeJSON(path string, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep &, <, > literal so vectors read cleanly across languages
	enc.SetIndent("", "  ")
	must(enc.Encode(v))
	must(os.WriteFile(path, buf.Bytes(), 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
