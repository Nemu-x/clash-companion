package protocol

// Remote-control capability tags (PROTOCOL.md §8.3). Each is advertised only when the
// consumer implements the matching hook; controllers MUST hide the button otherwise.
const (
	CapProxies       = "proxies"        // GET  /v1/proxies
	CapSelect        = "select"         // POST /v1/proxies/select
	CapUnfix         = "unfix"          // POST /v1/proxies/unfix
	CapDelay         = "delay"          // POST /v1/proxies/delay
	CapMode          = "mode"           // GET/POST /v1/mode
	CapProfiles      = "profiles"       // GET /v1/profiles, POST /v1/profiles/select
	CapProfileUpdate = "profile_update" // POST /v1/profiles/update
	CapProfileDelete = "profile_delete" // POST /v1/profiles/delete
	CapProviders     = "providers"      // GET /v1/providers, POST /v1/providers/{update,healthcheck}
	CapConnections   = "connections"    // GET /v1/connections, POST /v1/connections/close
	CapTraffic       = "traffic"        // GET /v1/traffic
	CapLogs          = "logs"           // GET /v1/logs
	CapSettings      = "settings"       // GET/POST /v1/settings
	CapActions       = "actions"        // GET/POST /v1/actions
)

// Tunnel modes (PROTOCOL.md §8.10).
const (
	ModeRule   = "rule"
	ModeGlobal = "global"
	ModeDirect = "direct"
)

// Provider kinds (PROTOCOL.md §8.14).
const (
	ProviderProxy = "proxy"
	ProviderRule  = "rule"
)

// Setting types (PROTOCOL.md §8.18).
const (
	SettingBool = "bool"
	SettingEnum = "enum"
)

// Well-known setting keys (PROTOCOL.md §8.18). Consumers MAY expose others.
const (
	SettingTUN         = "tun"          // bool
	SettingSystemProxy = "system_proxy" // bool
	SettingAllowLAN    = "allow_lan"    // bool
	SettingIPv6        = "ipv6"         // bool
	SettingSniffing    = "sniffing"     // bool
	SettingLogLevel    = "log_level"    // enum: silent|error|warning|info|debug
)

// Well-known action ids (PROTOCOL.md §8.19). Consumers MAY expose others.
const (
	ActionFlushDNS       = "flush_dns"
	ActionFlushFakeIP    = "flush_fakeip"
	ActionUpdateGeo      = "update_geo"
	ActionRestartCore    = "restart_core"
	ActionHealthCheckAll = "healthcheck_all"
)

// Log levels, most to least severe (PROTOCOL.md §8.17).
var LogLevels = []string{"error", "warning", "info", "debug"}

// Delay-test bounds in milliseconds (PROTOCOL.md §8.9). A timeout of 0 means DefaultDelayTimeout.
const (
	DefaultDelayTimeout = 5000
	MinDelayTimeout     = 100
	MaxDelayTimeout     = 30000
)

// Log listing bounds (PROTOCOL.md §8.17). A limit of 0 means DefaultLogLimit.
const (
	DefaultLogLimit = 100
	MaxLogLimit     = 1000
)

// --- proxies (§8.6–§8.9) ---

// ProxyList is the GET /v1/proxies response.
type ProxyList struct {
	Groups []ProxyGroup `json:"groups"`
}

// ProxyGroup is one policy group as the consumer presents it.
type ProxyGroup struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"`  // core group type, passed through (e.g. "Selector", "URLTest")
	Now        string      `json:"now"`   // currently used node
	Fixed      string      `json:"fixed"` // pinned node of an auto group; "" when none
	Selectable bool        `json:"selectable"`
	Nodes      []ProxyNode `json:"nodes"`
}

// ProxyNode is one member of a group (a proxy or a nested group).
type ProxyNode struct {
	Name  string `json:"name"`
	Type  string `json:"type"`  // core proxy type, passed through (e.g. "Vless", "Selector")
	Delay int    `json:"delay"` // last measured delay in ms; 0 = unknown or failed
}

// SelectRequest is the POST /v1/proxies/select body.
type SelectRequest struct {
	Group string `json:"group"`
	Node  string `json:"node"`
}

// UnfixRequest is the POST /v1/proxies/unfix body.
type UnfixRequest struct {
	Group string `json:"group"`
}

// SelectResponse is the POST /v1/proxies/{select,unfix} response.
type SelectResponse struct {
	OK    bool   `json:"ok"`
	Group string `json:"group"`
	Now   string `json:"now"`
}

// DelayRequest is the POST /v1/proxies/delay body. An empty Node tests the whole group;
// an empty URL uses the consumer's default test URL; Timeout is in ms (0 = default).
type DelayRequest struct {
	Group   string `json:"group"`
	Node    string `json:"node,omitempty"`
	URL     string `json:"url,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

// Delay is one delay-test result. Delay 0 means the node failed or timed out.
type Delay struct {
	Name  string `json:"name"`
	Delay int    `json:"delay"`
}

// DelayResponse is the POST /v1/proxies/delay response.
type DelayResponse struct {
	OK     bool    `json:"ok"`
	Delays []Delay `json:"delays"`
}

// --- mode (§8.10) ---

// ModeState is the GET /v1/mode response.
type ModeState struct {
	Mode  string   `json:"mode"`
	Modes []string `json:"modes"` // modes the agent accepts
}

// ModeRequest is the POST /v1/mode body.
type ModeRequest struct {
	Mode string `json:"mode"`
}

// ModeResponse is the POST /v1/mode response.
type ModeResponse struct {
	OK   bool   `json:"ok"`
	Mode string `json:"mode"`
}

// --- profiles (§8.11–§8.13) ---

// ProfileList is the GET /v1/profiles response.
type ProfileList struct {
	Active   string    `json:"active"` // id of the active profile; "" when none
	Profiles []Profile `json:"profiles"`
}

// Profile is one configuration profile / subscription on the agent.
type Profile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`      // "remote" (has an update URL) or "local"
	UpdatedAt int64  `json:"updatedAt"` // unix seconds; 0 = unknown
	Usage     *Usage `json:"usage,omitempty"`
}

// Usage is subscription traffic/expiry info (subscription-userinfo). Bytes; Expire is unix
// seconds, 0 = never/unknown.
type Usage struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

// ProfileRequest is the POST /v1/profiles/{select,update,delete} body. For update an empty
// ID means all remote profiles.
type ProfileRequest struct {
	ID string `json:"id,omitempty"`
}

// ProfileSelectResponse is the POST /v1/profiles/select response.
type ProfileSelectResponse struct {
	OK     bool   `json:"ok"`
	Active string `json:"active"`
}

// --- providers (§8.14) ---

// ProviderList is the GET /v1/providers response.
type ProviderList struct {
	Providers []Provider `json:"providers"`
}

// Provider is one proxy or rule provider.
type Provider struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`      // ProviderProxy | ProviderRule
	Vehicle   string `json:"vehicle"`   // "http" | "file" | "inline"
	Count     int    `json:"count"`     // proxies or rules it holds
	UpdatedAt int64  `json:"updatedAt"` // unix seconds; 0 = unknown
	Usage     *Usage `json:"usage,omitempty"`
}

// ProviderRequest is the POST /v1/providers/{update,healthcheck} body. Healthcheck applies
// to proxy providers only.
type ProviderRequest struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// --- connections & traffic (§8.15–§8.16) ---

// ConnectionList is the GET /v1/connections response.
type ConnectionList struct {
	UploadTotal   int64        `json:"uploadTotal"`
	DownloadTotal int64        `json:"downloadTotal"`
	Connections   []Connection `json:"connections"`
}

// Connection is one active connection.
type Connection struct {
	ID       string   `json:"id"`
	Host     string   `json:"host"`    // "host:port" (or "ip:port" without a sniffed host)
	Network  string   `json:"network"` // "tcp" | "udp"
	Process  string   `json:"process"` // "" when unknown
	Rule     string   `json:"rule"`    // matched rule, e.g. "DomainSuffix(example.com)"
	Chains   []string `json:"chains"`  // outbound chain, last hop first (core order)
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Start    int64    `json:"start"` // unix ms
}

// CloseRequest is the POST /v1/connections/close body. An empty ID closes all.
type CloseRequest struct {
	ID string `json:"id,omitempty"`
}

// CloseResponse is the POST /v1/connections/close response.
type CloseResponse struct {
	OK     bool `json:"ok"`
	Closed int  `json:"closed"`
}

// Traffic is the GET /v1/traffic response: current rates (bytes/s) and totals (bytes).
type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

// --- logs (§8.17) ---

// LogList is the GET /v1/logs response, oldest first.
type LogList struct {
	Lines []LogLine `json:"lines"`
}

// LogLine is one log entry.
type LogLine struct {
	Time  int64  `json:"time"` // unix ms
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// --- settings & actions (§8.18–§8.19) ---

// SettingList is the GET /v1/settings response.
type SettingList struct {
	Settings []Setting `json:"settings"`
}

// Setting is one typed toggle. Value is a bool for SettingBool and a string (one of
// Options) for SettingEnum. Label is a display name for consumer-defined keys.
type Setting struct {
	Key     string   `json:"key"`
	Type    string   `json:"type"`
	Value   any      `json:"value"`
	Options []string `json:"options,omitempty"`
	Label   string   `json:"label,omitempty"`
}

// SettingRequest is the POST /v1/settings body.
type SettingRequest struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// SettingResponse is the POST /v1/settings response.
type SettingResponse struct {
	OK      bool    `json:"ok"`
	Setting Setting `json:"setting"`
}

// ActionList is the GET /v1/actions response.
type ActionList struct {
	Actions []Action `json:"actions"`
}

// Action is one runnable one-shot action. Label is a display name for consumer-defined ids.
type Action struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// ActionRequest is the POST /v1/actions body.
type ActionRequest struct {
	Action string `json:"action"`
}
