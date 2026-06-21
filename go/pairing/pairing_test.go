package pairing_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Nemu-x/clash-companion/go/internal/testvectors"
	"github.com/Nemu-x/clash-companion/go/pairing"
)

func TestIDsAndTokenLengths(t *testing.T) {
	id, err := pairing.NewDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 22 {
		t.Fatalf("deviceId length = %d, want 22", len(id))
	}
	tok, err := pairing.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 43 {
		t.Fatalf("token length = %d, want 43", len(tok))
	}
}

func TestIDsVectors(t *testing.T) {
	var v struct {
		DeviceID  struct{ Encoded, RawHex string } `json:"deviceId"`
		Token     struct{ Encoded, RawHex string } `json:"token"`
		TokenHash struct {
			Token  string `json:"token"`
			SHA256 string `json:"sha256"`
		} `json:"tokenHash"`
	}
	testvectors.Load(t, "ids.json", &v)

	check := func(name, rawHex, encoded string) {
		raw, err := hex.DecodeString(rawHex)
		if err != nil {
			t.Fatal(err)
		}
		if got := base64.RawURLEncoding.EncodeToString(raw); got != encoded {
			t.Fatalf("%s: encoded %q want %q", name, got, encoded)
		}
	}
	check("deviceId", v.DeviceID.RawHex, v.DeviceID.Encoded)
	check("token", v.Token.RawHex, v.Token.Encoded)

	if got := pairing.HashToken(v.TokenHash.Token); got != v.TokenHash.SHA256 {
		t.Fatalf("tokenHash %q want %q", got, v.TokenHash.SHA256)
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	p := pairing.Payload{
		IP: "192.168.1.50", Port: 8443, ID: "dev1", Name: "Living Room TV",
		App: "slothclash", FP: "ab", Token: "tok",
	}
	uri, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := pairing.Decode(uri)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("round trip mismatch: %+v != %+v", got, p)
	}
}

func TestPayloadVectors(t *testing.T) {
	var vec struct {
		Cases []struct {
			Name    string           `json:"name"`
			Fields  *pairing.Payload `json:"fields"`
			URI     string           `json:"uri"`
			Decodes bool             `json:"decodes"`
		} `json:"cases"`
	}
	testvectors.Load(t, "pairing.json", &vec)
	if len(vec.Cases) == 0 {
		t.Fatal("no pairing vectors")
	}
	for _, c := range vec.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Fields != nil {
				// Encode must reproduce the URI byte-for-byte.
				got, err := c.Fields.Encode()
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				if got != c.URI {
					t.Fatalf("encode mismatch\n got: %s\nwant: %s", got, c.URI)
				}
			}
			dec, err := pairing.Decode(c.URI)
			if c.Decodes {
				if err != nil {
					t.Fatalf("expected decode success: %v", err)
				}
				if c.Fields != nil && dec != *c.Fields {
					t.Fatalf("decode mismatch: %+v != %+v", dec, *c.Fields)
				}
			} else if err == nil {
				t.Fatalf("expected decode failure for %q", c.URI)
			}
		})
	}
}

func TestFingerprintVector(t *testing.T) {
	var v struct {
		CertDer string `json:"certDer"`
		FP      string `json:"fp"`
	}
	testvectors.Load(t, "fingerprint.json", &v)
	der, err := base64.StdEncoding.DecodeString(v.CertDer)
	if err != nil {
		t.Fatal(err)
	}
	if got := pairing.Fingerprint(der); got != v.FP {
		t.Fatalf("fingerprint %q want %q", got, v.FP)
	}
}

func TestIdentityAndFingerprint(t *testing.T) {
	id, err := pairing.NewIdentity("agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.FP) != 64 {
		t.Fatalf("fp length = %d, want 64", len(id.FP))
	}
	if pairing.Fingerprint(id.CertDER) != id.FP {
		t.Fatal("fingerprint mismatch with identity")
	}
	if _, err := id.TLSCertificate(); err != nil {
		t.Fatalf("tls cert: %v", err)
	}
}

func TestStoreLifecycle(t *testing.T) {
	s := pairing.NewStore()
	tok, err := s.Pair("dev1", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate(tok); !ok {
		t.Fatal("expected authenticate to succeed")
	}
	if _, ok := s.Authenticate("wrong"); ok {
		t.Fatal("expected authenticate to fail for wrong token")
	}
	// Second device unaffected by revoking the first.
	tok2, _ := s.Pair("dev2", "Laptop")
	removed, err := s.Revoke("dev1")
	if err != nil || !removed {
		t.Fatalf("revoke: removed=%v err=%v", removed, err)
	}
	if _, ok := s.Authenticate(tok); ok {
		t.Fatal("revoked token must be rejected")
	}
	if _, ok := s.Authenticate(tok2); !ok {
		t.Fatal("other token must still work")
	}
}

func TestStorePersistence(t *testing.T) {
	path := t.TempDir() + "/pairings.json"
	s, err := pairing.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.Pair("dev1", "Phone")
	s2, err := pairing.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate(tok); !ok {
		t.Fatal("expected persisted pairing to authenticate")
	}
}
