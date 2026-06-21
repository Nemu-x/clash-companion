// Package controller implements the clashctl controller-side client: a pinned-TLS
// HTTP client (PROTOCOL.md §5.2) with typed calls for the v1 endpoints (§8) and the
// PIN-assisted pairing flow (§6.4).
package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Nemu-x/clash-companion/go/pairing"
	"github.com/Nemu-x/clash-companion/go/protocol"
)

// Client controls a single paired agent over pinned TLS.
type Client struct {
	base  string // https://host:port
	token string
	http  *http.Client
}

// New builds a Client for an agent at host:port, pinning the certificate fingerprint
// fp (PROTOCOL.md §3.3) and authorizing with token. A controller MUST validate the
// connection solely by fingerprint — no CA chain, no hostname check (PROTOCOL.md §5.2).
func New(host string, port int, fp, token string) (*Client, error) {
	tc, err := pinnedTLS(fp)
	if err != nil {
		return nil, err
	}
	return &Client{
		base:  fmt.Sprintf("https://%s", net.JoinHostPort(host, fmt.Sprint(port))),
		token: token,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tc},
		},
	}, nil
}

// FromPayload builds a Client from a parsed pairing payload (PROTOCOL.md §6.1).
func FromPayload(p pairing.Payload) (*Client, error) {
	return New(p.IP, p.Port, p.FP, p.Token)
}

// pinnedTLS returns a tls.Config that accepts a peer iff its leaf certificate's
// SHA-256 fingerprint equals fp.
func pinnedTLS(fp string) (*tls.Config, error) {
	want, err := hex.DecodeString(fp)
	if err != nil || len(want) != 32 {
		return nil, errors.New("controller: invalid fingerprint")
	}
	return &tls.Config{
		InsecureSkipVerify: true, // we pin manually below; CA/hostname checks are intentionally skipped
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("controller: no peer certificate")
			}
			got := pairing.Fingerprint(rawCerts[0])
			if got != fp {
				return fmt.Errorf("controller: certificate pin mismatch (got %s)", got)
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
	}, nil
}

// Status calls GET /v1/status (PROTOCOL.md §8.1).
func (c *Client) Status(ctx context.Context) (*protocol.Status, error) {
	var out protocol.Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Power calls POST /v1/power (PROTOCOL.md §8.2).
func (c *Client) Power(ctx context.Context, action string) (*protocol.PowerResponse, error) {
	var out protocol.PowerResponse
	if err := c.do(ctx, http.MethodPost, "/v1/power", protocol.PowerRequest{Action: action}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImportSubscription calls POST /v1/subscription (PROTOCOL.md §8.4).
func (c *Client) ImportSubscription(ctx context.Context, req protocol.SubscriptionRequest) error {
	var out protocol.OKResponse
	return c.do(ctx, http.MethodPost, "/v1/subscription", req, &out)
}

// Rename calls POST /v1/rename (PROTOCOL.md §8.5).
func (c *Client) Rename(ctx context.Context, name string) (*protocol.RenameResponse, error) {
	var out protocol.RenameResponse
	if err := c.do(ctx, http.MethodPost, "/v1/rename", protocol.RenameRequest{Name: name}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PairWithPIN performs PIN-assisted pairing against an agent discovered over mDNS
// (PROTOCOL.md §6.4). It connects over pinned TLS using the discovered fp and returns
// the issued token. No prior token is required.
func PairWithPIN(ctx context.Context, host string, port int, fp, pin, deviceID, name string) (string, error) {
	tc, err := pinnedTLS(fp)
	if err != nil {
		return "", err
	}
	c := &Client{
		base: fmt.Sprintf("https://%s", net.JoinHostPort(host, fmt.Sprint(port))),
		http: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
	}
	var out protocol.PairResponse
	req := protocol.PairRequest{PIN: pin, Device: protocol.PairDevice{ID: deviceID, Name: name}}
	if err := c.do(ctx, http.MethodPost, "/v1/pair", req, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e protocol.Error
		if json.Unmarshal(data, &e) == nil && e.Error.Code != "" {
			return &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
		}
		return &APIError{Status: resp.StatusCode, Code: protocol.CodeInternal, Message: string(data)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// APIError is a structured gateway error (PROTOCOL.md §5.5).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("clashctl: %d %s: %s", e.Status, e.Code, e.Message)
}
