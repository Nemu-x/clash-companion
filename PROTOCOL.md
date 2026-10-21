# clashctl — LAN companion remote-control protocol

**Version:** 1 (major) · **Status:** normative · **License:** GPL-3.0

This document is the single source of truth for the *clashctl* protocol: a **LAN-only,
security-first** remote-control contract between a **controller** (phone or PC) and one or more
**agents** (e.g. a TV) running [mihomo / Clash.Meta](https://github.com/MetaCubeX/mihomo). It is
precise enough that two independent implementations interoperate byte-for-byte. The Go reference
implementation lives in [`go/`](go/) and the language-neutral conformance vectors in
[`vectors/`](vectors/).

> **No cloud. No accounts. No relay.** Everything stays on the local network.

The key words **MUST**, **MUST NOT**, **SHALL**, **SHALL NOT**, **SHOULD**, **MAY**, and
**REQUIRED** are to be interpreted as in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) /
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

---

## 1. Overview & terminology

| Term | Meaning |
|------|---------|
| **Agent** | A device running a Clash core that exposes the clashctl *gateway* on the LAN. |
| **Controller** | A device that discovers, pairs with, and controls agents. |
| **Gateway** | The agent's clashctl HTTPS server — the **only** thing exposed on the LAN. |
| **Core** | The mihomo `external-controller` HTTP API, bound to `localhost` on the agent. |
| **Consumer** | An application embedding this protocol (ClashFest, SlothClash). |
| **Hooks** | Consumer-provided platform actions the core cannot do (VPN on/off, import, etc.). |
| **`deviceId`** | Stable per-device identifier. Survives rename and IP change. |
| **`fp`** | The agent's pinned TLS certificate fingerprint (§3.3). |
| **`token`** | A per-paired-controller bearer secret (§3.2). |

### 1.1 Architecture

```
   Controller (phone / PC)                 Agent (e.g. TV)
   ┌───────────────────┐                   ┌──────────────────────────────────┐
   │ discovery (mDNS)  │  _clashctl._tcp   │ discovery (mDNS advertise)        │
   │ pinned-TLS client │ ◄──────────────►  │ ┌──────────────────────────────┐ │
   │ bearer token      │   HTTPS + Bearer  │ │ clashctl GATEWAY (LAN)        │ │
   └───────────────────┘ ◄══════════════►  │ │  /v1/status power sub rename  │ │
                                           │ │  remote buttons (caps, §8.6)  │ │
                                           │ │  /v1/core/*  (whitelist, P2)  │ │
                                           │ └──────────────┬───────────────┘ │
                                           │   app Hooks    │ localhost only   │
                                           │ ┌──────────────▼───────────────┐ │
                                           │ │ mihomo external-controller    │ │
                                           │ │ 127.0.0.1:<coreport>          │ │
                                           │ └──────────────────────────────┘ │
                                           └──────────────────────────────────┘
```

The gateway does two kinds of work:

1. **App operations**, fulfilled by the consumer's **Hooks**: what the core cannot do at all
   (VPN/tunnel on/off, subscription import, rename, status), and the **remote buttons** (§8.6):
   node selection, mode, profiles, settings and so on. Those change state the consumer app owns, so
   they MUST run through the app's own code path, exactly as if pressed on the agent's screen.
2. **Whitelist forwarding** (Phase 2) of a fixed set of native Clash-API calls to the **localhost**
   core, so controllers speak mihomo's own dialect.

The core `external-controller` is **never** exposed on the LAN directly. It is reachable from the
LAN only through the gateway's `/v1/core/*` whitelist (§9).

### 1.2 Phasing

| Phase | Scope |
|-------|-------|
| **P1** | discovery · QR/paste/PIN pairing (TLS + token) · `/v1/status` · `/v1/power` · `/v1/subscription` · `/v1/rename` · reconnect-by-deviceId |
| **P2** | remote buttons (§8.6–§8.19) · `ANY /v1/core/*` whitelist forward · `GET /v1/events` (live updates, SSE) |
| **P3** | cross-app control · optional agent-served web UI |

P2/P3 endpoints are specified here but gated behind capability advertisement (§8.3); a P1-only
agent is fully conformant.

---

## 2. Threat model & security summary

clashctl gives remote control over a VPN/proxy. The security posture is **no compromises** on the
LAN surface.

- **Default OFF.** The consumer MUST expose an explicit on-device toggle. While OFF, the agent
  MUST NOT advertise over mDNS and MUST NOT listen on the gateway port (§4.1).
- **Pinned self-signed TLS.** All traffic is HTTPS using the agent's self-signed certificate,
  validated **only** by SHA-256 fingerprint pinning — no CA, no hostname check. This defeats
  on-path MITM because the `fp` is delivered out-of-band in the pairing payload (§3.3, §6).
- **Per-device bearer token.** Every request carries `Authorization: Bearer <token>`. Tokens are
  per paired controller and **revocable** by un-pairing (§3.2, §7).
- **Strict whitelist.** Only the endpoints in this document are served; only the core calls in §9
  are forwarded. `/upgrade`, loading or patching core configuration, and unlisted methods are
  always refused.
- **Confirm-on-agent-screen.** An optional first-connect confirmation; **mandatory** for the
  PIN-assisted pairing flow (§6.4).
- **Secrets at rest.** The agent stores only `SHA-256(token)`, never the raw token (§7.2).

Out of scope: WAN exposure, cloud relay, and account systems are explicitly **not** part of this
protocol and MUST NOT be added by a conforming implementation.

---

## 3. Identifiers, secrets & encodings

All multi-byte values use the encodings below **exactly**; the vectors in [`vectors/`](vectors/)
pin them.

> **`base64url(no-pad)`** = RFC 4648 §5 base64url alphabet `A–Z a–z 0–9 - _`, with **no `=`
> padding**.

### 3.1 `deviceId`

- Generation: 16 cryptographically-random bytes.
- Encoding: `base64url(no-pad)` → **22 characters**.
- Stable for the device's lifetime; unchanged by rename (§8.5) or IP change (§4.4).

### 3.2 `token`

- Generation: 32 cryptographically-random bytes (256-bit).
- Encoding: `base64url(no-pad)` → **43 characters**.
- One distinct token per paired controller, bound to that controller's `deviceId`.
- The agent stores `SHA-256(token)` (lowercase hex), never the raw value (§7.2).
- Presented on every request as `Authorization: Bearer <token>` (§5.2).

### 3.3 `fp` — TLS certificate fingerprint

- The agent generates one self-signed certificate (§5.1) on first enable.
- `fp = lowercasehex( SHA-256( DER(leaf certificate) ) )` → **64 hex characters**, no colons,
  no `0x`.
- `fp` is published identically in the discovery TXT record (§4.3) and the pairing payload (§6.1),
  and MUST equal the fingerprint of the certificate the gateway actually serves.

### 3.4 Canonical JSON

The **canonical JSON** form is used for all request/response bodies that appear in vectors. It is
[RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) constrained to this protocol's value
space:

1. Encoding is UTF-8.
2. Object keys are sorted in ascending order by Unicode code point.
3. Separators are `,` and `:` with **no** insignificant whitespace; there is **no** trailing
   newline.
4. Strings use minimal JSON escaping (`"`, `\`, and control characters `< U+0020`); non-ASCII is
   emitted as raw UTF-8, not `\u` escapes.
5. **All numbers are integers.** This protocol uses no fractional numbers, avoiding JCS
   number-formatting edge cases.

Two conforming implementations MUST emit byte-identical canonical JSON for the same logical value.

---

## 4. Discovery

### 4.1 Service

Agents advertise via mDNS / DNS-SD ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) /
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)):

- **Service type:** `_clashctl._tcp`
- **Port (SRV):** the gateway HTTPS port.
- **Instance name:** the agent's user-facing display `name`.

The agent MUST advertise **only** while the consumer toggle is ON, and MUST stop advertising and
close the gateway port when OFF.

### 4.2 Instance naming

The instance name is the human-readable display `name` (e.g. `Living Room TV`). It MAY change on
rename; the `deviceId` (TXT `id`) MUST NOT.

### 4.3 TXT record

The TXT record MUST contain exactly these keys (UTF-8 values):

| Key | Value |
|-----|-------|
| `app` | Consumer application id (e.g. `clashfest`, `slothclash`). |
| `id` | The agent `deviceId` (§3.1). |
| `name` | Display name (same as the instance name). |
| `ver` | Protocol **major** version as a decimal string — `1` for this document. |
| `fp` | TLS fingerprint (§3.3). |

A controller MUST be able to display `name` before any pairing. On connect, the served
certificate's fingerprint MUST equal the TXT `fp` (and the pinned value, §5.3).

### 4.4 Reconnect by deviceId

When a paired agent's IP/port changes and it re-announces, the controller MUST relocate it by
matching the advertised TXT `id` to the stored `deviceId`, and reuse the stored `token` and pinned
`fp` — **without** re-pairing.

---

## 5. Transport & security

### 5.1 TLS certificate

- Self-signed, key type **ECDSA P-256**.
- Long validity (pinning, not expiry, is the trust anchor; e.g. 10 years).
- The private key MUST NOT leave the agent.
- The certificate is the pinning identity; `fp` is computed per §3.3.

### 5.2 Connection rules

- The gateway MUST serve **only** HTTPS, presenting the certificate from §5.1.
- The controller MUST validate the connection **solely** by comparing the leaf certificate's
  SHA-256 fingerprint to the pinned `fp`. It MUST NOT perform CA-chain validation and MUST NOT
  perform hostname verification.
- A fingerprint mismatch MUST abort the connection **before** any request is sent, surfaced as a
  pin-mismatch error.
- Every request MUST carry `Authorization: Bearer <token>`. A missing, unknown, or revoked token
  MUST be rejected with `unauthorized` (§5.5) and MUST NOT reach a hook or the core.

### 5.3 Pinning

The pinned `fp` is obtained from the pairing payload (§6.1) at pairing time and stored alongside
the `deviceId` and `token`. The TXT `fp` (§4.3) is a convenience/sanity value and MUST match, but
the **pairing-time** `fp` is authoritative.

### 5.4 Request/response envelope

- All bodies are UTF-8 JSON in canonical form (§3.4).
- **App** success responses (§8) return `200`. A `POST` response contains `"ok": true` plus any
  result fields; a `GET` response is the resource itself, without `ok`.
- Lists are always encoded as arrays (`[]` when empty), never `null`. Fields marked *optional*
  are omitted when empty; all others are always present.
- **Forwarded core** success responses (§9) return the core's status/body verbatim after the edge
  checks pass.
- **Errors** use the uniform envelope:

```json
{"error":{"code":"<machine_code>","message":"<human readable>"}}
```

### 5.5 Error model

| `code` | HTTP | Meaning |
|--------|------|---------|
| `bad_request` | 400 | Malformed body or invalid field value. |
| `unauthorized` | 401 | Missing/invalid/revoked bearer token. |
| `forbidden` | 403 | Whitelist violation or confirmation required/denied. |
| `not_found` | 404 | Unknown endpoint or resource. |
| `version_unsupported` | 409 | Major version the agent does not implement. |
| `pin_invalid` | 403 | PIN-assisted pairing: wrong PIN. |
| `pin_rate_limited` | 429 | PIN-assisted pairing: too many attempts. |
| `core_unavailable` | 502 | The localhost core could not be reached. |
| `internal` | 500 | Unexpected agent error. |

A consumer hook reports a missing group/node/profile/etc. as `not_found` and a value it rejects
as `bad_request`; any other hook failure is reported as `core_unavailable`.

---

## 6. Pairing

### 6.1 Pairing payload (canonical URI)

The canonical pairing payload is the URI:

```
clashctl-pair://<ip>:<port>?id=<id>&name=<name>&app=<app>&fp=<fp>&token=<token>
```

- The authority is the agent's reachable `ip:port` (the gateway).
- Query parameters appear in the **fixed canonical order** `id, name, app, fp, token`.
- Every value is percent-encoded per [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) (so `name`
  may contain spaces/Unicode). Encoders MUST percent-encode any character outside the RFC 3986
  *unreserved* set (`A–Z a–z 0–9 - . _ ~`); the canonical encoder uppercase-hex `%XX` triplets.
- Decoders MUST accept the parameters in any order and MUST reject the payload if any of `ip`,
  `port`, `id`, `fp`, or `token` is missing or empty. (`name`/`app` are RECOMMENDED but a decoder
  MAY accept their absence.)

### 6.2 QR code

The QR encodes the **exact UTF-8 bytes** of the canonical URI (§6.1). Scanning and pasting the
string MUST yield identical trust material.

### 6.3 Paste

A user MAY paste the canonical URI string directly (preferred on PCs). It is parsed identically to
a scanned QR.

### 6.4 PIN-assisted pairing (PC convenience)

For devices that cannot scan a QR and where pasting is impractical:

1. The controller discovers the agent over mDNS, obtaining `ip, port, id, name, app, fp`.
2. The controller connects over **pinned** TLS (using the discovered `fp`) and sends
   `POST /v1/pair` with body `{"pin":"<code>","device":{"id":"<deviceId>","name":"<name>"}}`.
3. The `pin` is a short numeric code shown on the agent screen; it MUST be **single-use**,
   **rate-limited**, and **expiring** (RECOMMENDED ≤ 60 s, ≤ 5 attempts).
4. On success the agent issues and returns `{"ok":true,"token":"<token>"}`, binding the token to
   the supplied `deviceId`.
5. **Confirm-on-agent-screen is mandatory** for this flow (the genuine agent prompts the real
   user) to defeat a spoofed-mDNS relay. Wrong PIN → `pin_invalid`; too many → `pin_rate_limited`.

> QR/paste (§6.1–6.3) carries `fp` out-of-band and is the **recommended, strongest** method.
> See `design.md` for the SPAKE2 hardening note tracked for a later phase.

### 6.5 Confirm-on-first-connect

The agent SHALL support an optional mode that refuses control requests from a newly paired
controller until the user confirms on the agent device. When the mode is off, QR/paste pairings
connect without prompting; the PIN flow always prompts (§6.4).

---

## 7. Pairing lifecycle & token management

### 7.1 Issuance

A token (§3.2) is issued per paired controller and bound to that controller's `deviceId`.

### 7.2 Storage

The agent stores per pairing: `deviceId`, `name`, `SHA-256(token)` (lowercase hex), and
`pairedAt`. The **raw token is never stored**. On each request the agent hashes the presented
bearer token and compares.

### 7.3 Revocation (un-pair)

Un-pairing a controller MUST delete its entry. The next request bearing its token MUST be rejected
with `unauthorized`. Other controllers' tokens MUST continue to work. Any open event stream (§9.2)
of that controller MUST be closed.

### 7.4 `POST /v1/unpair` — self-revocation (capability `unpair`)

A controller that "forgets" an agent MUST call `POST /v1/unpair` (body `{}`) before deleting its
stored token, so the token does not stay valid on the agent. The agent revokes the **calling**
controller's pairing exactly as in §7.3 and responds `{"ok":true}`. The request requires a valid
bearer token but MUST NOT require first-connect confirmation (§6.5): giving up control never needs
approval. If the agent is unreachable, the controller deletes its token anyway and the user can
un-pair on the agent screen.

---

## 8. v1 endpoints (app operations)

§8.1–§8.5 are the P1 core every agent serves; §8.6–§8.19 are optional, capability-gated remote
buttons. All endpoints are under `/v1`, require a valid bearer token (§5.2), and use canonical JSON (§3.4).

### 8.1 `GET /v1/status`

Returns agent identity, capabilities, and run state. **No request body.**

Response (example, canonical):

```json
{"app":"slothclash","capabilities":["status","power","subscription","rename"],"id":"<deviceId>","name":"Living Room TV","power":"on","ver":1}
```

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | `deviceId`. |
| `name` | string | Display name. |
| `app` | string | Consumer app id. |
| `ver` | integer | Protocol major version. |
| `power` | string | `on` or `off` — current tunnel state, sourced from the consumer hook. |
| `capabilities` | string[] | Supported capability tags (§8.3). |
| `summary` | object | *Optional* at-a-glance state, so a controller's home screen needs one call. |

`summary` fields are each *optional* (omitted when unknown); the whole object is omitted when
empty. A failure to compute it MUST NOT fail the status call.

| `summary` field | Meaning |
|-----------------|---------|
| `mode` | Tunnel mode (§8.10). |
| `profile` | Active profile display name. |
| `proxy` | Node currently carrying traffic, as the app shows it. |
| `appVersion` | Consumer app version. |
| `coreVersion` | Core version, e.g. `v1.19.32`. |

```json
{"app":"clashfest","capabilities":["status","power","subscription","rename","unpair","proxies","select","mode","events"],"id":"<deviceId>","name":"Living Room TV","power":"on","summary":{"appVersion":"2.4.0","coreVersion":"v1.19.32","mode":"rule","profile":"Main","proxy":"🇯🇵 Japan"},"ver":1}
```

### 8.2 `POST /v1/power`

Body: `{"action":"on"|"off"|"toggle"}`. Invokes the consumer power hook. An `action` outside the
three values → `bad_request`.

Response: `{"ok":true,"power":"on"}` (the resulting state).

### 8.3 Capability advertisement

`capabilities` enumerates the features the agent implements, in this order:

| Capability | Endpoints | § |
|------------|-----------|---|
| `status` · `power` · `subscription` · `rename` | P1, always present | 8.1–8.5 |
| `unpair` | `POST /v1/unpair` | 7.4 |
| `proxies` | `GET /v1/proxies` | 8.7 |
| `select` | `POST /v1/proxies/select` | 8.8 |
| `unfix` | `POST /v1/proxies/unfix` | 8.8 |
| `delay` | `POST /v1/proxies/delay` | 8.9 |
| `mode` | `GET /v1/mode` · `POST /v1/mode` | 8.10 |
| `profiles` | `GET /v1/profiles` · `POST /v1/profiles/select` | 8.11 |
| `profile_update` | `POST /v1/profiles/update` | 8.12 |
| `profile_delete` | `POST /v1/profiles/delete` | 8.13 |
| `providers` | `GET /v1/providers` · `POST /v1/providers/update` · `POST /v1/providers/healthcheck` | 8.14 |
| `connections` | `GET /v1/connections` · `POST /v1/connections/close` | 8.15 |
| `traffic` | `GET /v1/traffic` | 8.16 |
| `logs` | `GET /v1/logs` | 8.17 |
| `settings` | `GET /v1/settings` · `POST /v1/settings` | 8.18 |
| `actions` | `GET /v1/actions` · `POST /v1/actions` | 8.19 |
| `core` | `ANY /v1/core/*` | 9.1 |
| `events` | `GET /v1/events` (server-sent events) | 9.2 |

Controllers MUST hide features whose capability is absent and MUST ignore capability tags they do
not know.

### 8.4 `POST /v1/subscription`

Body is **either** `{"url":"<https url>","name":"<name>"}` **or**
`{"payload":"<inline config>","name":"<name>"}`. Exactly one of `url`/`payload` MUST be present;
neither → `bad_request`. The gateway hands it to the consumer import hook; it MUST NOT write
arbitrary core config paths directly.

Response: `{"ok":true}`.

### 8.5 `POST /v1/rename`

Body: `{"name":"<new name>"}`. Persists the new display name, re-announces over mDNS (§4.2), and
leaves `deviceId`, `token`, and `fp` unchanged. Empty `name` → `bad_request`.

Response: `{"name":"Bedroom TV","ok":true}`.

### 8.6 Remote buttons — common rules

The endpoints in §8.7–§8.19 let a controller press the agent app's own buttons. Each belongs to a
capability (§8.3) and is OPTIONAL: a consumer implements the ones its app has.

- An agent MUST advertise a capability if and only if it serves its endpoints.
- A request to an endpoint whose capability is not advertised MUST be answered with `not_found`
  **after** bearer authentication (§5.2), without side effects.
- Every state-changing button MUST apply the change through the same code path as the equivalent
  on-device control, so it is persisted and reflected in the agent's own UI (e.g. a selected node
  survives a tunnel restart). Writing to the core behind the app's back is not conformant.
- The gateway validates the request shapes below before invoking any hook; violations are
  `bad_request`. Unknown group/node/profile/provider/connection/setting/action → `not_found`.
- Times are integers: `updatedAt`/`expire` in unix **seconds** (0 = unknown/never); connection
  `start` and log `time` in unix **milliseconds**.

### 8.7 `GET /v1/proxies` (capability `proxies`)

Returns policy groups in display order, as the agent app presents them (an app MAY omit groups it
hides).

```json
{"groups":[{"fixed":"","name":"Proxy","nodes":[{"delay":87,"name":"Auto","type":"URLTest"},{"delay":0,"name":"DIRECT","type":"Direct"}],"now":"Auto","selectable":true,"type":"Selector"}]}
```

| Field | Type | Meaning |
|-------|------|---------|
| `name` | string | Group name. |
| `type` | string | Core group type, passed through (`Selector`, `URLTest`, `Fallback`, `LoadBalance`, …). |
| `now` | string | Node currently in use (`""` if none). |
| `fixed` | string | Node pinned in an automatic group (`""` if none). |
| `selectable` | bool | Whether `select` (§8.8) may target this group. |
| `nodes[].name` / `.type` | string | Member name and core type (a member may itself be a group). |
| `nodes[].delay` | integer | Last measured delay in ms; `0` = unknown or failed. |

### 8.8 `POST /v1/proxies/select` (`select`) · `POST /v1/proxies/unfix` (`unfix`)

- **select** body `{"group":"<group>","node":"<node>"}`, both REQUIRED. Selects `node` in `group`.
  For automatic groups (`URLTest`/`Fallback`) this pins the node.
- **unfix** body `{"group":"<group>"}`, REQUIRED. Clears the pinned node of an automatic group.

Response (both): `{"group":"Proxy","now":"<node now in use>","ok":true}`.

### 8.9 `POST /v1/proxies/delay` (capability `delay`)

Body `{"group":"<group>","node":"<node>","url":"<test url>","timeout":<ms>}`. `group` is REQUIRED;
`node`, `url` and `timeout` are *optional*. Without `node` the whole group is tested. `url` MUST be
an absolute `http`/`https` URL; when absent the agent's default test URL is used. `timeout` is
`0`/absent (= 5000) or within **100–30000** ms.

Response: `{"delays":[{"delay":64,"name":"HK-01"},{"delay":0,"name":"JP-01"}],"ok":true}`, where
`delay` `0` means the node failed or timed out.

### 8.10 `GET /v1/mode` · `POST /v1/mode` (capability `mode`)

`GET` → `{"mode":"rule","modes":["rule","global","direct"]}` (`modes` = values the agent accepts).
`POST` body `{"mode":"rule"|"global"|"direct"}` (lowercase; anything else → `bad_request`) →
`{"mode":"global","ok":true}`.

### 8.11 `GET /v1/profiles` · `POST /v1/profiles/select` (capability `profiles`)

`GET` →

```json
{"active":"p-1","profiles":[{"id":"p-1","name":"Main","type":"remote","updatedAt":1792540800,"usage":{"download":52428800,"expire":1798761600,"total":107374182400,"upload":1048576}}]}
```

`id` is an agent-chosen opaque string; `type` is `remote` (has an update URL) or `local`;
`usage` is *optional* subscription info (bytes; `expire` unix seconds, 0 = never). `active` is
`""` when no profile is active.

`POST /v1/profiles/select` body `{"id":"<id>"}` (REQUIRED) activates a profile →
`{"active":"<id>","ok":true}`.

### 8.12 `POST /v1/profiles/update` (capability `profile_update`)

Body `{"id":"<id>"}` refreshes one remote profile from its URL; `{}` refreshes all remote profiles.
Response `{"ok":true}`.

### 8.13 `POST /v1/profiles/delete` (capability `profile_delete`)

Body `{"id":"<id>"}` (REQUIRED). The agent MAY refuse to delete the active profile with
`bad_request`. Response `{"ok":true}`.

### 8.14 Providers (capability `providers`)

`GET /v1/providers` →

```json
{"providers":[{"count":42,"kind":"proxy","name":"sub1","updatedAt":1792540800,"vehicle":"http"},{"count":120345,"kind":"rule","name":"ads","updatedAt":0,"vehicle":"file"}]}
```

`kind` is `proxy` or `rule`; `vehicle` is `http`, `file` or `inline`; `count` is the number of
proxies or rules; `usage` (§8.11) is *optional*.

- `POST /v1/providers/update` body `{"kind":"proxy"|"rule","name":"<name>"}` refreshes a provider.
- `POST /v1/providers/healthcheck` body `{"kind":"proxy","name":"<name>"}` health-checks a proxy
  provider; `kind` other than `proxy` → `bad_request`.

Both respond `{"ok":true}`.

### 8.15 Connections (capability `connections`)

`GET /v1/connections` →

```json
{"connections":[{"chains":["HK-01","Proxy"],"download":1048576,"host":"www.youtube.com:443","id":"c1","network":"tcp","process":"","rule":"DomainSuffix(youtube.com)","start":1792540800123,"upload":2048}],"downloadTotal":734003200,"uploadTotal":1048576}
```

`host` is `host:port` (or `ip:port`); `process` is `""` when unknown; `chains` lists the outbound
chain in core order (last hop first).

`POST /v1/connections/close` body `{"id":"<id>"}` closes one connection; `{}` closes all →
`{"closed":17,"ok":true}`.

### 8.16 `GET /v1/traffic` (capability `traffic`)

A snapshot: `{"down":3276800,"downTotal":734003200,"up":12800,"upTotal":1048576}`, with current
rates in bytes/s and totals in bytes. Controllers poll it (RECOMMENDED ≥ 1 s apart); live
streaming is `events` (§9.2).

### 8.17 `GET /v1/logs` (capability `logs`)

Query `level` (*optional*: `error`, `warning`, `info` or `debug`, meaning that level and more
severe) and `limit` (*optional*, 1–1000, default 100). Returns up to `limit` most recent lines,
oldest first: `{"lines":[{"level":"warning","msg":"…","time":1792540800123}]}`.

### 8.18 Settings (capability `settings`)

`GET /v1/settings` →

```json
{"settings":[{"key":"tun","type":"bool","value":true},{"key":"log_level","options":["silent","error","warning","info","debug"],"type":"enum","value":"info"},{"key":"bypass_lan_apps","label":"Bypass LAN apps","type":"bool","value":false}]}
```

`type` is `bool` (`value` is a JSON boolean) or `enum` (`value` is one of `options`). `label`
(*optional*) is a display name for consumer-defined keys; `options` is present for `enum` only.
Well-known keys, with fixed meaning: `tun`, `system_proxy`, `allow_lan`, `ipv6`, `sniffing` (bool),
`log_level` (enum). Consumers MAY add their own keys.

`POST /v1/settings` body `{"key":"<key>","value":<bool|string>}`. Unknown key → `not_found`; a
value of the wrong type or outside `options` → `bad_request`. Response
`{"ok":true,"setting":{…the setting's new state…}}`.

### 8.19 Actions (capability `actions`)

`GET /v1/actions` → `{"actions":[{"id":"flush_dns"},{"id":"clear_cache","label":"Clear cache"}]}`.
Well-known ids: `flush_dns`, `flush_fakeip`, `update_geo`, `restart_core`, `healthcheck_all`;
`label` (*optional*) names consumer-defined ones.

`POST /v1/actions` body `{"action":"<id>"}` runs one; an id not listed → `not_found`. Response
`{"ok":true}`.

---

## 9. Phase 2 — core forwarding & events

### 9.1 `ANY /v1/core/*` (capability `core`)

Forwards only the **whitelisted** native Clash-API calls to the localhost core
(`http://127.0.0.1:<coreport>`). Path mapping: `/v1/core/<X>` → `/<X>` on the core. The gateway
enforces bearer auth (§5.2) and the whitelist, then relays the core's status, body, and safe
headers verbatim (§5.4).

**Whitelist (method + path).** Every entry exists in mihomo's external-controller.

| Method | Core path | Purpose |
|--------|-----------|---------|
| `GET` | `/version` · `/configs` · `/memory` · `/rules` | Read core version, running config, memory, rules. |
| `GET` | `/traffic` · `/logs` · `/connections` | Traffic, log and connection streams/snapshots. |
| `GET` | `/proxies` · `/proxies/{name}` | List proxies and groups / read one. |
| `PUT` | `/proxies/{group}` | Select a node in a group (`{"name":"<node>"}`). |
| `DELETE` | `/proxies/{group}` | Clear the pinned node of an automatic group. |
| `GET` | `/proxies/{name}/delay` | Delay-test one proxy (`?url=&timeout=`). |
| `GET` | `/group` · `/group/{name}` | List groups / read one. |
| `GET` | `/group/{name}/delay` | Delay-test a whole group. |
| `GET` | `/providers/proxies` · `/providers/proxies/{name}` | Proxy providers. |
| `PUT` | `/providers/proxies/{name}` | Update a proxy provider. |
| `GET` | `/providers/proxies/{name}/healthcheck` | Health-check a proxy provider. |
| `GET` | `/providers/rules` | Rule providers. |
| `PUT` | `/providers/rules/{name}` | Update a rule provider. |
| `DELETE` | `/connections` · `/connections/{id}` | Close all / one connection. |

A `{…}` segment matches exactly one non-empty path segment. Anything not in this table MUST be
refused with `forbidden` **without** contacting the core, notably:

- `PUT /configs` and `PATCH /configs`: loading or patching configuration could rebind
  `external-controller` onto the LAN without a secret and bypass the gateway entirely. Mode and
  settings changes go through `mode` (§8.10) and `settings` (§8.18) instead.
- `/upgrade*`, `/restart`, `/storage/*`, `/cache/*`, `/debug/*`, `/configs/geo`, and every
  unlisted method.

Selection is `PUT /proxies/{group}`; mihomo has no `PUT /group/{name}`.

**Read-only mode.** Writes forwarded here reach the core behind the app's back (§8.6). An agent
whose app owns that state (selected node, providers) SHOULD run the forward **read-only**, which
relays only the whitelisted `GET` calls and refuses everything else with `forbidden`.

Streaming responses (`/traffic`, `/logs`, `/connections`, and WebSocket upgrades of them) MUST be
relayed without buffering.

### 9.2 `GET /v1/events` (capability `events`)

A [server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html) stream over
the same pinned-TLS, bearer-authorized channel, so controllers update live instead of polling: if
one controller (or the user on the agent screen) changes something, every other controller sees it.

- Request: `GET /v1/events` with `Authorization: Bearer <token>`. Auth (and validation) errors are
  returned as normal JSON errors **before** the stream starts; no event is sent without a valid
  token.
- Query `topics` (*optional*, comma-separated): `traffic`, `logs`. Unknown topics are ignored.
  `level` (*optional*, with `logs`): `error`, `warning`, `info` or `debug`, as in §8.17; any other
  value → `bad_request`.
- Response: `200`, `Content-Type: text/event-stream`. Each event is exactly
  `event: <type>\ndata: <canonical JSON>\n\n` (canonical JSON never contains a raw newline). Lines
  starting with `:` are heartbeats (sent at least every 30 s) and MUST be ignored.

| `event` | `data` | When |
|---------|--------|------|
| `status` | the §8.1 status object | first event of every stream, and whenever power, name or summary changes |
| `changed` | `{"resource":"<name>"}` | a resource changed: refetch its `GET` endpoint |
| `traffic` | the §8.16 traffic object | about once a second, topic `traffic`, if `traffic` is advertised |
| `log` | one §8.17 log line | topic `logs`, filtered by `level` |

`resource` is one of `proxies`, `mode`, `profiles`, `providers`, `connections`, `settings`
(the matching `GET /v1/…`). Controllers MUST ignore unknown event types and resources.

The agent MUST emit these for changes made through the gateway **and** for the same changes made on
the device itself. Events are not replayed: on reconnect a controller refetches what it shows.
An agent MAY close a stream whose reader falls behind; it MUST close streams of a controller whose
pairing is revoked (§7.3, §7.4).

---

## 10. Versioning

- The protocol is versioned by a single **major** version, exposed as TXT `ver` (§4.3) and
  `status.ver` (§8.1).
- A controller speaking a major version the agent does not implement MUST receive
  `version_unsupported` (409) rather than a misinterpreted request.
- New optional features are added via **capabilities** (§8.3) without a major bump; breaking wire
  changes bump the major version.

---

## 11. Conformance

An implementation is conforming if it:

1. Implements all P1 endpoints (§8.1–§8.5) and the discovery (§4), pairing (§6), and transport (§5) rules.
2. Produces and accepts the exact byte encodings of §3 and passes every applicable vector in
   [`vectors/`](vectors/), including `control.json` for each remote button it advertises.
3. Enforces the security requirements of §2 (default-off, pinning, bearer auth, whitelist).

P2/P3 features are conformant when advertised via capabilities (§8.3) and matching their sections.
