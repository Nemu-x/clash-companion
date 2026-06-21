package pairing

import (
	"errors"
	"fmt"
	"strings"
)

// Scheme is the URI scheme of the canonical pairing payload (PROTOCOL.md §6.1).
const Scheme = "clashctl-pair"

// Payload is the trust material exchanged at pairing time (PROTOCOL.md §6.1).
type Payload struct {
	IP    string `json:"ip"`    // agent gateway host (IPv4, IPv6, or hostname)
	Port  int    `json:"port"`  // agent gateway port
	ID    string `json:"id"`    // deviceId
	Name  string `json:"name"`  // display name
	App   string `json:"app"`   // consumer app id
	FP    string `json:"fp"`    // TLS fingerprint (PROTOCOL.md §3.3)
	Token string `json:"token"` // bearer token
}

// canonicalParamOrder is the fixed query-parameter order for encoding (PROTOCOL.md §6.1).
var canonicalParamOrder = []string{"id", "name", "app", "fp", "token"}

// Encode renders p as the canonical clashctl-pair:// URI (PROTOCOL.md §6.1).
// Required fields (IP, Port, ID, FP, Token) must be non-empty.
func (p Payload) Encode() (string, error) {
	if p.IP == "" || p.Port == 0 || p.ID == "" || p.FP == "" || p.Token == "" {
		return "", errors.New("pairing: missing required field (ip, port, id, fp, token)")
	}
	host := p.IP
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]" // bracket IPv6 literals
	}
	vals := map[string]string{
		"id": p.ID, "name": p.Name, "app": p.App, "fp": p.FP, "token": p.Token,
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s://%s:%d?", Scheme, host, p.Port)
	for i, k := range canonicalParamOrder {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(encodeComponent(vals[k]))
	}
	return b.String(), nil
}

// Decode parses a clashctl-pair:// URI into a Payload. Parameters may appear in any
// order; the payload is rejected if ip, port, id, fp, or token is missing or empty
// (PROTOCOL.md §6.1).
func Decode(s string) (Payload, error) {
	var p Payload
	rest, ok := strings.CutPrefix(s, Scheme+"://")
	if !ok {
		return p, fmt.Errorf("pairing: not a %s:// URI", Scheme)
	}
	authority, query, _ := strings.Cut(rest, "?")
	host, portStr, err := splitHostPort(authority)
	if err != nil {
		return p, err
	}
	p.IP = host
	if _, err := fmt.Sscanf(portStr, "%d", &p.Port); err != nil || p.Port == 0 {
		return p, fmt.Errorf("pairing: invalid port %q", portStr)
	}
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			k, v, _ := strings.Cut(kv, "=")
			dv, err := decodeComponent(v)
			if err != nil {
				return p, fmt.Errorf("pairing: bad value for %q: %w", k, err)
			}
			switch k {
			case "id":
				p.ID = dv
			case "name":
				p.Name = dv
			case "app":
				p.App = dv
			case "fp":
				p.FP = dv
			case "token":
				p.Token = dv
			}
		}
	}
	if p.ID == "" || p.FP == "" || p.Token == "" {
		return p, errors.New("pairing: missing required field (id, fp, token)")
	}
	return p, nil
}

func splitHostPort(authority string) (host, port string, err error) {
	if strings.HasPrefix(authority, "[") { // [IPv6]:port
		end := strings.LastIndex(authority, "]")
		if end < 0 {
			return "", "", errors.New("pairing: unterminated IPv6 authority")
		}
		host = authority[1:end]
		rest := authority[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", errors.New("pairing: missing port")
		}
		return host, rest[1:], nil
	}
	i := strings.LastIndex(authority, ":")
	if i < 0 {
		return "", "", errors.New("pairing: missing port")
	}
	return authority[:i], authority[i+1:], nil
}

const upperhex = "0123456789ABCDEF"

// encodeComponent percent-encodes per RFC 3986, encoding any byte outside the
// unreserved set (A-Z a-z 0-9 - . _ ~) as an uppercase %XX triplet (PROTOCOL.md §6.1).
func encodeComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0xf])
		}
	}
	return b.String()
}

func decodeComponent(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return "", errors.New("truncated percent-encoding")
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				return "", errors.New("invalid percent-encoding")
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		} else {
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
