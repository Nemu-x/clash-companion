// Package canonjson implements the canonical JSON encoding defined in PROTOCOL.md §3.4.
//
// The encoding is RFC 8785 (JCS) constrained to this protocol's value space:
//   - UTF-8 output.
//   - Object keys sorted ascending by Unicode code point.
//   - Compact separators ("," and ":"), no insignificant whitespace, no trailing newline.
//   - Minimal string escaping; non-ASCII emitted as raw UTF-8.
//   - All numbers are integers (the protocol uses no fractional numbers).
//
// Two conforming implementations MUST produce byte-identical output for the same logical value.
package canonjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Marshal encodes v into canonical JSON. v is first marshalled with encoding/json
// (honouring struct tags) and then re-emitted canonically.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := encode(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalString is Marshal returning a string.
func MarshalString(v any) (string, error) {
	b, err := Marshal(v)
	return string(b), err
}

func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encodeString(buf, t)
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("canonjson: non-integer number %q not allowed", s)
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Sort by UTF-8 bytes, which equals Unicode code-point order.
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return errors.New("canonjson: unsupported value type")
	}
	return nil
}

const hexdigits = "0123456789abcdef"

// encodeString writes a JSON string with minimal escaping (RFC 8785).
// Only ", \, and control characters U+0000–U+001F are escaped; everything else,
// including non-ASCII, is emitted as raw UTF-8.
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexdigits[(r>>4)&0xf])
				buf.WriteByte(hexdigits[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
