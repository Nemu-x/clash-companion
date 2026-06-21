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

1. **App-only operations** the core cannot perform — VPN/tunnel on/off, subscription import,
   rename, status — fulfilled by the consumer's **Hooks**.
2. **Whitelist forwarding** (Phase 2) of a fixed set of native Clash-API calls to the **localhost**
   core, so controllers speak mihomo's own dialect.

The core `external-controller` is **never** exposed on the LAN directly. It is reachable from the
LAN only through the gateway's `/v1/core/*` whitelist (§9).

### 1.2 Phasing

| Phase | Scope |
|-------|-------|
| **P1** | discovery · QR/paste/PIN pairing (TLS + token) · `/v1/status` · `/v1/power` · `/v1/subscription` · `/v1/rename` · reconnect-by-deviceId |
| **P2** | `ANY /v1/core/*` whitelist forward · `WS /v1/events` (live status/traffic) |
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
  are forwarded. `/upgrade`, arbitrary config file paths, and unlisted methods are always refused.
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
- Stable for the device's lifetime; unchanged by rename (§8.7) or IP change (§4.4).

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
- **App-only** success responses (§8) return `200` with a body containing `"ok": true` plus any
  result fields.
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
with `unauthorized`. Other controllers' tokens MUST continue to work.

---

## 8. v1 endpoints (P1, app-only)

All endpoints are under `/v1`, require a valid bearer token (§5.2), and use canonical JSON (§3.4).

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

### 8.2 `POST /v1/power`

Body: `{"action":"on"|"off"|"toggle"}`. Invokes the consumer power hook. An `action` outside the
three values → `bad_request`.

Response: `{"ok":true,"power":"on"}` (the resulting state).

### 8.3 Capability advertisement

`capabilities` enumerates the optional features the agent implements, drawn from:
`status`, `power`, `subscription`, `rename` (P1), `core` (`/v1/core/*`), `events`
(`WS /v1/events`) (P2). Controllers MUST hide features whose capability is absent.

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

---

## 9. Phase 2 — core forwarding & events

### 9.1 `ANY /v1/core/*` (capability `core`)

Forwards only the **whitelisted** native Clash-API calls to the localhost core
(`http://127.0.0.1:<coreport>`). Path mapping: `/v1/core/<X>` → `/<X>` on the core. The gateway
enforces bearer auth (§5.2) and the whitelist, then relays the core's status, body, and safe
headers verbatim (§5.4).

**Whitelist (method + path):**

| Method | Core path | Purpose |
|--------|-----------|---------|
| `GET` | `/configs` | Read current config. |
| `PUT` | `/configs` | Apply a config (`{payload}`). |
| `GET` | `/proxies` | List proxies. |
| `GET` | `/proxies/{name}` | Read one proxy. |
| `PUT` | `/proxies/{name}` | Select a node within a group. |
| `GET` | `/group` | List groups. |
| `GET` | `/group/{name}` | Read one group. |
| `PUT` | `/group/{name}` | Select within a group. |
| `GET` | `/traffic` | Traffic stream/snapshot. |
| `GET` | `/connections` | Active connections. |
| `GET` | `/version` | Core version. |
| `GET` | `/logs` | Log stream. |

Anything not in this table — notably `/upgrade`, arbitrary file paths, and unlisted methods — MUST
be refused with `forbidden` **without** contacting the core.

### 9.2 `WS /v1/events` (capability `events`)

A WebSocket over the same pinned-TLS, bearer-authorized channel streaming live status and traffic
frames. Authorization MUST be enforced at the upgrade handshake; an upgrade without a valid token
MUST be refused before any frame is sent. Frame payloads relay the core's native event JSON to
preserve the dialect (see `design.md` open question).

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

1. Implements all P1 endpoints (§8) and the discovery (§4), pairing (§6), and transport (§5) rules.
2. Produces and accepts the exact byte encodings of §3 and passes every applicable vector in
   [`vectors/`](vectors/).
3. Enforces the security requirements of §2 (default-off, pinning, bearer auth, whitelist).

P2/P3 features are conformant when advertised via capabilities (§8.3) and matching their sections.
