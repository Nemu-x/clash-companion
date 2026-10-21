package controller

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Nemu-x/clash-companion/go/protocol"
)

// Remote-control calls (PROTOCOL.md §8.6–§8.19). Check Status().Capabilities before
// calling: an unadvertised capability fails with an APIError whose Code is not_found.

// Proxies calls GET /v1/proxies (capability "proxies").
func (c *Client) Proxies(ctx context.Context) (*protocol.ProxyList, error) {
	return call[protocol.ProxyList](ctx, c, http.MethodGet, "/v1/proxies", nil)
}

// SelectProxy calls POST /v1/proxies/select (capability "select").
func (c *Client) SelectProxy(ctx context.Context, group, node string) (*protocol.SelectResponse, error) {
	return call[protocol.SelectResponse](ctx, c, http.MethodPost, "/v1/proxies/select", protocol.SelectRequest{Group: group, Node: node})
}

// UnfixProxy calls POST /v1/proxies/unfix (capability "unfix").
func (c *Client) UnfixProxy(ctx context.Context, group string) (*protocol.SelectResponse, error) {
	return call[protocol.SelectResponse](ctx, c, http.MethodPost, "/v1/proxies/unfix", protocol.UnfixRequest{Group: group})
}

// TestDelay calls POST /v1/proxies/delay (capability "delay").
func (c *Client) TestDelay(ctx context.Context, req protocol.DelayRequest) (*protocol.DelayResponse, error) {
	return call[protocol.DelayResponse](ctx, c, http.MethodPost, "/v1/proxies/delay", req)
}

// Mode calls GET /v1/mode (capability "mode").
func (c *Client) Mode(ctx context.Context) (*protocol.ModeState, error) {
	return call[protocol.ModeState](ctx, c, http.MethodGet, "/v1/mode", nil)
}

// SetMode calls POST /v1/mode (capability "mode").
func (c *Client) SetMode(ctx context.Context, mode string) (*protocol.ModeResponse, error) {
	return call[protocol.ModeResponse](ctx, c, http.MethodPost, "/v1/mode", protocol.ModeRequest{Mode: mode})
}

// Profiles calls GET /v1/profiles (capability "profiles").
func (c *Client) Profiles(ctx context.Context) (*protocol.ProfileList, error) {
	return call[protocol.ProfileList](ctx, c, http.MethodGet, "/v1/profiles", nil)
}

// SelectProfile calls POST /v1/profiles/select (capability "profiles").
func (c *Client) SelectProfile(ctx context.Context, id string) (*protocol.ProfileSelectResponse, error) {
	return call[protocol.ProfileSelectResponse](ctx, c, http.MethodPost, "/v1/profiles/select", protocol.ProfileRequest{ID: id})
}

// UpdateProfile calls POST /v1/profiles/update (capability "profile_update"). An empty id
// updates all remote profiles.
func (c *Client) UpdateProfile(ctx context.Context, id string) error {
	_, err := call[protocol.OKResponse](ctx, c, http.MethodPost, "/v1/profiles/update", protocol.ProfileRequest{ID: id})
	return err
}

// DeleteProfile calls POST /v1/profiles/delete (capability "profile_delete").
func (c *Client) DeleteProfile(ctx context.Context, id string) error {
	_, err := call[protocol.OKResponse](ctx, c, http.MethodPost, "/v1/profiles/delete", protocol.ProfileRequest{ID: id})
	return err
}

// Providers calls GET /v1/providers (capability "providers").
func (c *Client) Providers(ctx context.Context) (*protocol.ProviderList, error) {
	return call[protocol.ProviderList](ctx, c, http.MethodGet, "/v1/providers", nil)
}

// UpdateProvider calls POST /v1/providers/update (capability "providers").
func (c *Client) UpdateProvider(ctx context.Context, kind, name string) error {
	_, err := call[protocol.OKResponse](ctx, c, http.MethodPost, "/v1/providers/update", protocol.ProviderRequest{Kind: kind, Name: name})
	return err
}

// HealthCheckProvider calls POST /v1/providers/healthcheck for a proxy provider
// (capability "providers").
func (c *Client) HealthCheckProvider(ctx context.Context, name string) error {
	req := protocol.ProviderRequest{Kind: protocol.ProviderProxy, Name: name}
	_, err := call[protocol.OKResponse](ctx, c, http.MethodPost, "/v1/providers/healthcheck", req)
	return err
}

// Connections calls GET /v1/connections (capability "connections").
func (c *Client) Connections(ctx context.Context) (*protocol.ConnectionList, error) {
	return call[protocol.ConnectionList](ctx, c, http.MethodGet, "/v1/connections", nil)
}

// CloseConnections calls POST /v1/connections/close (capability "connections"). An empty
// id closes all connections.
func (c *Client) CloseConnections(ctx context.Context, id string) (*protocol.CloseResponse, error) {
	return call[protocol.CloseResponse](ctx, c, http.MethodPost, "/v1/connections/close", protocol.CloseRequest{ID: id})
}

// Traffic calls GET /v1/traffic (capability "traffic").
func (c *Client) Traffic(ctx context.Context) (*protocol.Traffic, error) {
	return call[protocol.Traffic](ctx, c, http.MethodGet, "/v1/traffic", nil)
}

// Logs calls GET /v1/logs (capability "logs"). level "" means all; limit 0 means the default.
func (c *Client) Logs(ctx context.Context, level string, limit int) (*protocol.LogList, error) {
	q := url.Values{}
	if level != "" {
		q.Set("level", level)
	}
	if limit != 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/logs"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return call[protocol.LogList](ctx, c, http.MethodGet, path, nil)
}

// Settings calls GET /v1/settings (capability "settings").
func (c *Client) Settings(ctx context.Context) (*protocol.SettingList, error) {
	return call[protocol.SettingList](ctx, c, http.MethodGet, "/v1/settings", nil)
}

// SetSetting calls POST /v1/settings (capability "settings"). value is a bool for bool
// settings and a string for enum settings.
func (c *Client) SetSetting(ctx context.Context, key string, value any) (*protocol.SettingResponse, error) {
	return call[protocol.SettingResponse](ctx, c, http.MethodPost, "/v1/settings", protocol.SettingRequest{Key: key, Value: value})
}

// Actions calls GET /v1/actions (capability "actions").
func (c *Client) Actions(ctx context.Context) (*protocol.ActionList, error) {
	return call[protocol.ActionList](ctx, c, http.MethodGet, "/v1/actions", nil)
}

// RunAction calls POST /v1/actions (capability "actions").
func (c *Client) RunAction(ctx context.Context, id string) error {
	_, err := call[protocol.OKResponse](ctx, c, http.MethodPost, "/v1/actions", protocol.ActionRequest{Action: id})
	return err
}

// call performs one request and decodes the success body into a fresh T.
func call[T any](ctx context.Context, c *Client, method, path string, body any) (*T, error) {
	var out T
	if err := c.do(ctx, method, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
