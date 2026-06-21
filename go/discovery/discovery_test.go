package discovery_test

import (
	"reflect"
	"testing"

	"github.com/Nemu-x/clash-companion/go/discovery"
	"github.com/Nemu-x/clash-companion/go/internal/testvectors"
)

func TestTXTRoundTrip(t *testing.T) {
	in := discovery.TXT{App: "slothclash", ID: "dev1", Name: "Living Room TV", Ver: 1, FP: "ab"}
	out, err := discovery.DecodeTXT(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip: %+v != %+v", out, in)
	}
}

func TestTXTDecodeAnyOrderAndMissing(t *testing.T) {
	if _, err := discovery.DecodeTXT([]string{"ver=1", "id=x", "app=a", "fp=f"}); err == nil {
		t.Fatal("expected error for missing name")
	}
	ok := []string{"fp=f", "name=N", "ver=1", "id=x", "app=a"}
	if _, err := discovery.DecodeTXT(ok); err != nil {
		t.Fatalf("expected reordered decode to succeed: %v", err)
	}
}

func TestTXTVectors(t *testing.T) {
	var v struct {
		Fields  discovery.TXT `json:"fields"`
		Encoded []string      `json:"encoded"`
	}
	testvectors.Load(t, "discovery_txt.json", &v)
	if got := v.Fields.Encode(); !reflect.DeepEqual(got, v.Encoded) {
		t.Fatalf("encode mismatch\n got: %v\nwant: %v", got, v.Encoded)
	}
	dec, err := discovery.DecodeTXT(v.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if dec != v.Fields {
		t.Fatalf("decode mismatch: %+v != %+v", dec, v.Fields)
	}
}
