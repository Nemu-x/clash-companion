package pairing

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// Entry is one paired controller as persisted by the agent (PROTOCOL.md §7.2).
// The raw token is never stored — only TokenHash.
type Entry struct {
	DeviceID  string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"tokenHash"` // lowercase-hex SHA-256 of the token
	PairedAt  time.Time `json:"pairedAt"`
	Confirmed bool      `json:"confirmed"` // first-connect confirmation satisfied
}

// Store is the agent's set of pairings, keyed by deviceId. It is safe for
// concurrent use. With a non-empty path it persists to a JSON file.
type Store struct {
	mu      sync.RWMutex
	path    string
	entries map[string]Entry
}

// NewStore returns an empty in-memory store.
func NewStore() *Store {
	return &Store{entries: map[string]Entry{}}
}

// OpenStore loads (or creates) a file-backed store at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, entries: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Entry
	if len(b) > 0 {
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, err
		}
	}
	for _, e := range list {
		s.entries[e.DeviceID] = e
	}
	return s, nil
}

// Pair records a new pairing for deviceId with the given display name and issues a
// fresh token, returning the raw token (shown once, never stored).
func (s *Store) Pair(deviceID, name string) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.entries[deviceID] = Entry{
		DeviceID:  deviceID,
		Name:      name,
		TokenHash: HashToken(token),
		PairedAt:  time.Now().UTC(),
	}
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		return "", err
	}
	return token, nil
}

// Authenticate returns the matching entry for a presented bearer token, or false.
// Comparison is constant-time over the token hash.
func (s *Store) Authenticate(token string) (Entry, bool) {
	want := HashToken(token)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if subtle.ConstantTimeCompare([]byte(e.TokenHash), []byte(want)) == 1 {
			return e, true
		}
	}
	return Entry{}, false
}

// Revoke removes a pairing (un-pair). Returns true if an entry was removed.
func (s *Store) Revoke(deviceID string) (bool, error) {
	s.mu.Lock()
	_, ok := s.entries[deviceID]
	delete(s.entries, deviceID)
	s.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, s.persist()
}

// Confirm marks a device's first-connect confirmation as satisfied.
func (s *Store) Confirm(deviceID string) error {
	s.mu.Lock()
	e, ok := s.entries[deviceID]
	if ok {
		e.Confirmed = true
		s.entries[deviceID] = e
	}
	s.mu.Unlock()
	if !ok {
		return errors.New("pairing: unknown device")
	}
	return s.persist()
}

// List returns a snapshot of all entries.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	list := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		list = append(list, e)
	}
	s.mu.RUnlock()
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
