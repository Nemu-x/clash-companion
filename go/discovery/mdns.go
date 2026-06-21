package discovery

import (
	"context"
	"strings"

	"github.com/Nemu-x/clash-companion/go/protocol"
	"github.com/libp2p/zeroconf/v2"
)

const domain = "local."

// Publisher is an active mDNS advertisement of a clashctl agent (PROTOCOL.md §4.1).
type Publisher struct {
	server *zeroconf.Server
}

// Publish advertises the agent over mDNS. The instance name is txt.Name (the display
// name); port is the gateway HTTPS port. Call Shutdown to stop advertising — which the
// agent MUST do when its on-device toggle is turned off (PROTOCOL.md §4.1).
func Publish(txt TXT, port int) (*Publisher, error) {
	srv, err := zeroconf.Register(txt.Name, protocol.Service, domain, port, txt.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return &Publisher{server: srv}, nil
}

// Shutdown stops the advertisement.
func (p *Publisher) Shutdown() {
	if p.server != nil {
		p.server.Shutdown()
	}
}

// Browse scans the LAN for clashctl agents until ctx is cancelled or its deadline is
// reached, returning the collected entries (PROTOCOL.md §4). Malformed advertisements
// are skipped.
func Browse(ctx context.Context) ([]Entry, error) {
	results := make(chan *zeroconf.ServiceEntry, 16)
	var entries []Entry
	done := make(chan struct{})
	go func() {
		defer close(done)
		for se := range results {
			txt, err := DecodeTXT(se.Text)
			if err != nil {
				continue
			}
			entries = append(entries, Entry{
				TXT:   txt,
				Host:  strings.TrimSuffix(se.HostName, "."),
				Port:  se.Port,
				Addrs: ips(se),
			})
		}
	}()
	if err := zeroconf.Browse(ctx, protocol.Service, domain, results); err != nil {
		return nil, err
	}
	<-done
	return entries, nil
}

// FindByDeviceID browses and returns the entry whose TXT id matches deviceID, enabling
// reconnect-by-deviceId after an address change (PROTOCOL.md §4.4).
func FindByDeviceID(ctx context.Context, deviceID string) (Entry, bool, error) {
	entries, err := Browse(ctx)
	if err != nil {
		return Entry{}, false, err
	}
	for _, e := range entries {
		if e.ID == deviceID {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

func ips(se *zeroconf.ServiceEntry) []string {
	var out []string
	for _, ip := range se.AddrIPv4 {
		out = append(out, ip.String())
	}
	for _, ip := range se.AddrIPv6 {
		out = append(out, ip.String())
	}
	return out
}
