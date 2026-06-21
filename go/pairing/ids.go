// Package pairing implements clashctl pairing per PROTOCOL.md §3 and §6:
// identifier/secret encodings, the self-signed pinned TLS certificate, the
// clashctl-pair:// payload codec, and the agent pairing store.
package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// b64 is RFC 4648 base64url with no padding (PROTOCOL.md §3).
var b64 = base64.RawURLEncoding

// NewDeviceID returns a fresh deviceId: base64url(no-pad) of 16 random bytes (22 chars).
func NewDeviceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// NewToken returns a fresh bearer token: base64url(no-pad) of 32 random bytes (43 chars).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// HashToken returns the lowercase-hex SHA-256 of a token, as stored by the agent (PROTOCOL.md §7.2).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
