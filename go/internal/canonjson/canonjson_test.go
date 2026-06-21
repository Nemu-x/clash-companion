package canonjson_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Nemu-x/clash-companion/go/internal/canonjson"
	"github.com/Nemu-x/clash-companion/go/internal/testvectors"
)

func TestMarshalUnit(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"sorts keys", map[string]any{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"compact", map[string]any{"x": []any{1, 2}}, `{"x":[1,2]}`},
		{"raw unicode and no html escape", map[string]any{"k": "<a>&é"}, `{"k":"<a>&é"}`},
		{"control escapes", map[string]any{"k": "a\tb\nc"}, `{"k":"a\tb\nc"}`},
		{"bool null", map[string]any{"a": true, "b": nil}, `{"a":true,"b":null}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := canonjson.MarshalString(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestMarshalRejectsFloat(t *testing.T) {
	if _, err := canonjson.Marshal(map[string]any{"x": 1.5}); err == nil {
		t.Fatal("expected error for non-integer number")
	}
}

func TestCanonicalVectors(t *testing.T) {
	var vec struct {
		Cases []struct {
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			Canonical string          `json:"canonical"`
		} `json:"cases"`
	}
	testvectors.Load(t, "canonical_json.json", &vec)
	if len(vec.Cases) == 0 {
		t.Fatal("no canonical vectors loaded")
	}
	for _, c := range vec.Cases {
		t.Run(c.Name, func(t *testing.T) {
			// Parse input as a generic JSON value, preserving integers via json.Number.
			dec := json.NewDecoder(bytes.NewReader(c.Input))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
			got, err := canonjson.MarshalString(v)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.Canonical {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, c.Canonical)
			}
		})
	}
}
