# clash-companion

A **LAN-only, security-first** companion remote-control protocol for
[mihomo / Clash.Meta](https://github.com/MetaCubeX/mihomo). A *controller* (phone or PC) discovers
and controls multiple *agent* instances (e.g. a TV) on the same local network: discover by name,
pair via QR (or pasted string / PIN), share a subscription, toggle the VPN on/off, view status,
rename.

> **No cloud. No accounts. No relay.** Everything stays on the LAN.

This repository is the **foundation**: the protocol contract, a Go reference implementation, and
language-neutral golden test vectors. It contains **no app/platform code** — the
[ClashFest](https://github.com/Nemu-x) (Android/Kotlin) and SlothClash (Wails+Go desktop) apps
consume it.

## What's here

| Path | What |
|------|------|
| [`PROTOCOL.md`](PROTOCOL.md) | The **normative spec** — the single source of truth: discovery, pairing, transport, endpoints, security, errors, versioning. Precise enough that two independent implementations interoperate. |
| [`go/`](go/) | The Go reference implementation: `discovery`, `pairing`, `agent`, `controller`, `forwarder`. Idiomatic and `go get`-able. |
| [`vectors/`](vectors/) | Language-neutral golden test vectors. The Go impl and other-language consumers run the **same** vectors to prove byte-for-byte interop. |
| [`openspec/`](openspec/) | The OpenSpec change that designed this work (proposal, design, specs, tasks). |

## Architecture

A thin **agent gateway** is the only thing exposed on the LAN. It:

1. **Forwards a whitelist** of native Clash-API calls to the consumer's **localhost** mihomo
   `external-controller` (so it speaks mihomo's own dialect: `PUT /configs`, `GET/PUT /proxies`,
   `/group`, `GET /traffic /connections /version /logs`) — Phase 2.
2. Defines **app-only ops** the core can't do (VPN on/off, subscription import, rename, status),
   which each consumer fulfils with its own platform hooks.

The core `external-controller` is **never** on the LAN directly.

```
Controller ──mDNS discover──▶ Agent gateway (pinned TLS + Bearer) ──localhost──▶ mihomo core
```

## Security model (no compromises)

- **Default OFF** — the consumer exposes an explicit on-device toggle; nothing is advertised or
  listening until it's on.
- **Pinned self-signed TLS** — validated *only* by SHA-256 certificate fingerprint (no CA, no
  hostname check). The `fp` is delivered out-of-band in the pairing payload, so it's MITM-proof.
- **Per-device bearer token** — revocable by un-pairing; stored hashed (`sha256`), never raw.
- **Strict whitelist** — only the documented endpoints and core calls; `/upgrade` and arbitrary
  config paths are always refused.
- **Confirm-on-agent-screen** — optional for QR/paste, mandatory for the PIN flow.

See [PROTOCOL.md §2](PROTOCOL.md) for the full threat model.

## Protocol v1 at a glance

- **Discovery:** mDNS `_clashctl._tcp`, TXT `{app, id, name, ver, fp}`.
- **Pairing:** `clashctl-pair://<ip>:<port>?id=&name=&app=&fp=&token=` (QR / paste / PIN).
- **Transport:** HTTPS (pinned) + `Authorization: Bearer`.
- **Endpoints (P1):** `GET /v1/status`, `POST /v1/power {on|off|toggle}`,
  `POST /v1/subscription {url,name | payload}`, `POST /v1/rename {name}`.
- **Phase 2:** `ANY /v1/core/*` whitelist forward + `WS /v1/events` (live status/traffic).

Phasing: **P1** = discovery + pair + status + power + share-sub + rename + reconnect-by-deviceId.
**P2** = core forward + events. **P3** = cross-app control + optional agent-served web UI.

## Using the Go reference

```sh
go get github.com/Nemu-x/clash-companion/go@latest
```

```go
// Agent side (the device being controlled).
id, _ := pairing.NewIdentity("clashctl-agent", 10*365*24*time.Hour) // self-signed pinned cert
store, _ := pairing.OpenStore("pairings.json")                       // hashed tokens at rest

a, _ := agent.New(agent.Config{
    App: "slothclash", DeviceID: deviceID, Name: "Living Room TV",
    Identity: id, Store: store,
    Hooks: myHooks, // implement Power/PowerState/ImportSubscription against your platform
})
// Advertise over mDNS and serve the gateway over pinned TLS.
pub, _ := discovery.Publish(discovery.TXT{App: "slothclash", ID: deviceID, Name: "Living Room TV", Ver: protocol.Major, FP: id.FP}, port)
defer pub.Shutdown()
tlsCfg, _ := a.TLSConfig()
http.Serve(tlsListenerWith(tlsCfg), a.Handler())

// Build a pairing payload to show as a QR.
uri, _ := pairing.Payload{IP: ip, Port: port, ID: deviceID, Name: "Living Room TV", App: "slothclash", FP: id.FP, Token: token}.Encode()
```

```go
// Controller side (the phone/PC).
p, _ := pairing.Decode(scannedURI)         // parse QR / pasted string
c, _ := controller.FromPayload(p)          // pinned-TLS client bound to fp + token
st, _ := c.Status(ctx)                     // GET /v1/status
c.Power(ctx, "toggle")                     // POST /v1/power
```

See [`go/agent/integration_test.go`](go/agent/integration_test.go) for a full end-to-end example
over real pinned TLS.

## Consumer integration

- **SlothClash (Wails+Go):** `go get` this module → use `controller` (and optionally `agent`); the
  UI is TS/React. App-only hooks call its own VPN/import logic.
- **ClashFest (Android, Kotlin):** implements agent + controller **natively in Kotlin** (Ktor +
  `NsdManager` + Conscrypt/Java TLS) against `PROTOCOL.md`, running [`vectors/`](vectors/) in unit
  tests for interop. App-only ops wire to its `ACTION_START_CLASH/STOP_CLASH/TOGGLE_CLASH` intents
  and `clash://install-config?url=&name=` deeplink. No gomobile.

## Development

```sh
cd go
go test ./...               # unit, vector, and pinned-TLS integration tests
go run ./cmd/genvectors ../vectors   # regenerate golden vectors (rarely needed)
```

## License

[GPL-3.0](LICENSE).
