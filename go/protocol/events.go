package protocol

// Event types sent on GET /v1/events (PROTOCOL.md §9.2).
const (
	EventStatus  = "status"  // data: Status — on connect and whenever it changes
	EventChanged = "changed" // data: Changed — a resource changed; refetch it
	EventTraffic = "traffic" // data: Traffic — about once a second, topic "traffic"
	EventLog     = "log"     // data: LogLine — topic "logs"
)

// Event topics a controller may opt into with ?topics= (PROTOCOL.md §9.2). status and
// changed events are always sent.
const (
	TopicTraffic = "traffic"
	TopicLogs    = "logs"
)

// Resources named by a changed event (PROTOCOL.md §9.2). Each maps to the GET endpoint a
// controller refetches.
const (
	ResourceProxies     = "proxies"     // GET /v1/proxies
	ResourceMode        = "mode"        // GET /v1/mode
	ResourceProfiles    = "profiles"    // GET /v1/profiles
	ResourceProviders   = "providers"   // GET /v1/providers
	ResourceConnections = "connections" // GET /v1/connections
	ResourceSettings    = "settings"    // GET /v1/settings
)

// Changed is the data of a changed event.
type Changed struct {
	Resource string `json:"resource"`
}
