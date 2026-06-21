package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"math/big"
	"sync"
	"time"
)

// PINManager issues and verifies single-use, expiring, rate-limited PINs for the
// PIN-assisted pairing flow (PROTOCOL.md §6.4).
type PINManager struct {
	ttl         time.Duration
	maxAttempts int

	mu       sync.Mutex
	pin      string
	expires  time.Time
	attempts int
	now      func() time.Time // injectable clock for tests
}

// NewPINManager returns a manager with the given PIN lifetime and attempt cap.
func NewPINManager(ttl time.Duration, maxAttempts int) *PINManager {
	return &PINManager{ttl: ttl, maxAttempts: maxAttempts, now: time.Now}
}

// Generate creates a fresh 6-digit PIN, replacing any prior one, and returns it for
// display on the agent screen.
func (m *PINManager) Generate() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	pin := pad6(n.Int64())
	m.mu.Lock()
	m.pin = pin
	m.expires = m.now().Add(m.ttl)
	m.attempts = 0
	m.mu.Unlock()
	return pin, nil
}

// VerifyResult is the outcome of a PIN verification attempt.
type VerifyResult int

const (
	// PINOK means the PIN matched and was consumed (single-use).
	PINOK VerifyResult = iota
	// PINWrong means the PIN did not match (or none is active/expired).
	PINWrong
	// PINRateLimited means too many attempts were made.
	PINRateLimited
)

// Verify checks a presented PIN. A correct PIN is consumed (single-use). Attempts are
// rate-limited and PINs expire.
func (m *PINManager) Verify(pin string) VerifyResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pin == "" || m.now().After(m.expires) {
		m.pin = ""
		return PINWrong
	}
	if m.attempts >= m.maxAttempts {
		return PINRateLimited
	}
	m.attempts++
	if subtle.ConstantTimeCompare([]byte(m.pin), []byte(pin)) == 1 {
		m.pin = "" // consume
		return PINOK
	}
	return PINWrong
}

func pad6(n int64) string {
	b := []byte("000000")
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b)
}
