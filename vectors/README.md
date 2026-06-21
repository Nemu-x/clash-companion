# clashctl golden vectors

Language-neutral conformance vectors for the [clashctl protocol](../PROTOCOL.md). Every
implementation — the Go reference in [`../go/`](../go/) and other-language consumers (the Kotlin
ClashFest) — runs these to prove **byte-for-byte interop**.

The vectors were produced by the reference implementation (`go run ./cmd/genvectors` from
[`../go`](../go)) and hand-checked against [PROTOCOL.md](../PROTOCOL.md). They are plain JSON with
no shared code: load the file, run the listed transform, assert the expected output.

## Files

| File | PROTOCOL.md | Contract |
|------|-------------|----------|
| `ids.json` | §3.1, §3.2, §7.2 | `base64url(no-pad)` of fixed bytes for `deviceId`/`token`; `tokenHash = lowercasehex(sha256(token))`. |
| `fingerprint.json` | §3.3 | `certDer` (base64) → `fp = lowercasehex(sha256(DER))`. |
| `pairing.json` | §6.1 | For each case: `Encode(fields)` must equal `uri` exactly; `Decode(uri)` must reproduce `fields`; `decodes:false` cases must be rejected. |
| `canonical_json.json` | §3.4 | Parse `input` as JSON, canonicalize, result must equal `canonical` byte-for-byte. |
| `discovery_txt.json` | §4.3 | TXT `Encode(fields)` must equal `encoded` (key order `app,id,name,ver,fp`); decode tolerates any order. |
| `whitelist.json` | §9.1 | `Allowed(method, path)` must equal `allowed` for the core-forward whitelist. |

## How to run them

**Go** (reference): `go test ./...` in [`../go`](../go) loads and asserts every file via
`internal/testvectors`.

**Any language:** load the JSON, apply the transform named in the table, and compare to the
expected value. A one-byte divergence means the implementations are not interoperable. For
`canonical_json.json`, treat all JSON numbers as integers (the protocol uses no fractional
numbers).

## Regenerating

These are golden files; regenerate only when the protocol encodings change:

```sh
cd ../go && go run ./cmd/genvectors ../vectors
```

`fingerprint.json` embeds a fixed certificate DER so its expected `fp` stays stable across
regenerations. After regenerating, the Go test suite must still pass.
