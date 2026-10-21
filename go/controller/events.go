package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Nemu-x/clash-companion/go/protocol"
)

// Unpair calls POST /v1/unpair (PROTOCOL.md §7.4): the agent revokes this controller's
// token. Forget the stored token and fp afterwards.
func (c *Client) Unpair(ctx context.Context) error {
	_, err := call[protocol.OKResponse](ctx, c, http.MethodPost, "/v1/unpair", struct{}{})
	return err
}

// Event is one server-sent event from GET /v1/events. Data is the canonical JSON payload;
// decode it according to Type with the helpers below.
type Event struct {
	Type string
	Data json.RawMessage
}

// Status decodes a protocol.EventStatus payload.
func (e Event) Status() (protocol.Status, error) { return decodeAs[protocol.Status](e.Data) }

// Changed decodes a protocol.EventChanged payload.
func (e Event) Changed() (protocol.Changed, error) { return decodeAs[protocol.Changed](e.Data) }

// Traffic decodes a protocol.EventTraffic payload.
func (e Event) Traffic() (protocol.Traffic, error) { return decodeAs[protocol.Traffic](e.Data) }

// Log decodes a protocol.EventLog payload.
func (e Event) Log() (protocol.LogLine, error) { return decodeAs[protocol.LogLine](e.Data) }

func decodeAs[T any](b []byte) (T, error) {
	var v T
	err := json.Unmarshal(b, &v)
	return v, err
}

// EventOptions selects the optional event topics (PROTOCOL.md §9.2).
type EventOptions struct {
	Traffic  bool   // traffic events about once a second
	Logs     bool   // log events
	LogLevel string // minimum log level; "" = all
}

// Events streams GET /v1/events, calling fn for each event until ctx is cancelled or the
// stream ends; it then returns the cause (io.EOF when the agent closed the stream).
// Reconnect on return and refetch what you show: events missed while disconnected are
// not replayed.
func (c *Client) Events(ctx context.Context, opts EventOptions, fn func(Event)) error {
	q := url.Values{}
	var topics []string
	if opts.Traffic {
		topics = append(topics, protocol.TopicTraffic)
	}
	if opts.Logs {
		topics = append(topics, protocol.TopicLogs)
	}
	if len(topics) > 0 {
		q.Set("topics", strings.Join(topics, ","))
	}
	if opts.LogLevel != "" {
		q.Set("level", opts.LogLevel)
	}
	path := "/v1/events"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	// Same pinned transport, but no overall timeout: the stream is long-lived.
	resp, err := (&http.Client{Transport: c.http.Transport}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var typ string
	var data []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if typ != "" || len(data) > 0 {
				if typ == "" {
					typ = "message"
				}
				fn(Event{Type: typ, Data: json.RawMessage(strings.Join(data, "\n"))})
			}
			typ, data = "", nil
		case strings.HasPrefix(line, ":"):
			// comment / heartbeat
		case strings.HasPrefix(line, "event:"):
			typ = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
}
