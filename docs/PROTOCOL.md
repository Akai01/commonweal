# Wire protocol v1

Every message carries `v`. An unrecognised version is refused, never guessed at.

## Signing

Signatures are computed over **canonical JSON**: sorted keys, `(",", ":")` separators,
UTF-8, no NaN. Two encoders must agree byte-for-byte or verification fails in a way
that looks like tampering.

## 1. Roster — the trust anchor

```json
{
  "v": 1,
  "federation_id": "my-lab",
  "roster_version": 7,
  "updated": "2026-08-02T00:00:00Z",
  "admins": ["alice"],
  "members": [
    {"id": "alice", "sign_pub": "<b64 Ed25519>", "enc_pub": "<b64 X25519>",
     "role": "admin", "joined": "2026-08-01"}
  ],
  "peers": [
    {"id": "bob-ws", "owner": "bob", "enc_pub": "<b64 X25519>",
     "endpoint": "https://10.0.0.5:9101", "model": "glm-5.2",
     "engine": "sglang", "engine_version": "0.4", "hw_class": "cuda-sm90",
     "capacity_gb": 128.0, "max_concurrent": 32,
     "availability": null, "shards": [], "attestation": null}
  ],
  "signatures": ["<b64 Ed25519 over canonical(body)>"]
}
```

Signatures cover the body with `signatures` excluded.

### Shard groups: `contributors`

A peer is normally one machine with one owner. A **shard group** is several machines
pooling memory behind one endpoint — and behind one `owner`, whoever runs the head. An
optional `contributors` list names who supplied the memory, so credit does not all land on
the head's owner while the members who provided the RAM earn nothing:

```json
{"id": "lab-group", "owner": "bob", "model": "glm-5.2",
 "endpoint": "https://10.0.0.5:9101", "max_concurrent": 32,
 "shards": [[0, 40], [40, 80]],
 "contributors": [{"member": "alice", "gb": 128.0},
                  {"member": "bob",   "gb": 128.0},
                  {"member": "carol", "gb": 64.0}]}
```

- **Declared, not reported.** The roster is admin-signed, so the split is something a
  person vouched for rather than something the machine running the head asserts about
  everyone else.
- **`capacity_gb` must equal the shares**, and is derived from them when omitted. Two
  numbers that should agree and don't is refused at parse time.
- Every named member must be on the roster, same rule as `owner` — otherwise credit goes
  somewhere unaccountable.
- Credit is the heartbeat's reported residency divided in these proportions. The
  coordinator **caps reported residency at `capacity_gb`**, so a peer cannot beat
  `resident_gb: 999999` and mint standing for everyone it names. A roster that declares no
  capacity gets no cap.
- **Omitted from the signed bytes when empty**, unlike every other peer field. An absent
  list and an empty one both mean "the owner contributed it all", so nothing is ambiguous
  — and rosters signed before this field existed still verify.

**Verification rules** (`Roster.load`):

1. `trusted_admin_keys` is supplied by the caller from local config — **never read from
   the document.** A self-vouching roster is forgeable by anyone.
2. `roster_version` must be strictly greater than any version already held.
3. At least one signature must verify against a trusted admin key, and that admin must
   be listed in `admins`.
4. Every peer's `owner` must be a listed member; `admins` must all be members.

## 2. Lease — round one

```
POST /v1/lease
```

All control-plane requests use this signed wrapper:

```json
{
  "member_id": "alice",
  "nonce": "<random>",
  "ts": 1785000000.0,
  "body": {"model": "glm-5.2"},
  "sig": "<b64 Ed25519 over canonical({member_id, nonce, ts, body})>"
}
```

Rejected if: stale (>120 s), future-dated (>30 s skew), nonce replayed, signer unknown,
or signature bad. The nonce is recorded *after* signature verification so an
unauthenticated caller cannot flood the cache.

Response:

```json
{
  "request_id": "…", "peer_id": "bob-ws",
  "peer_enc_pub": "<b64 X25519>", "peer_endpoint": "https://…",
  "model": "glm-5.2", "engine": "sglang", "engine_version": "0.4",
  "hw_class": "cuda-sm90", "expires_at": 1785000300.0
}
```

`503 no_capacity` — no live peer serves the model.
`429 queue_full` (with `Retry-After`) — pool saturated and the queue is at its bound.

Waiters are ordered by **fair-share score**, not arrival. Contributors in surplus are
served first.

## 3. Envelope — round two

```
POST /v1/infer
```

```json
{
  "v": 1,
  "request_id": "…",
  "sealed_key": "<b64 SealedBox(32-byte master) to peer_enc_pub>",
  "iv": "<b64 96-bit>",
  "ciphertext": "<b64 AES-256-GCM(request_json), tag appended>",
  "sender": "alice",
  "ts": 1785000000.0,
  "sig": "<b64 Ed25519 over canonical(v, request_id, sealed_key, iv, ciphertext, sender, ts)>"
}
```

`ts` sits **inside the signed bytes** because a signature proves authorship, not
recency: without a signed clock, a captured envelope would stay spendable forever, and
the coordinator necessarily holds every envelope. Both recipients therefore refuse
replays independently:

- The **peer** rejects an envelope whose `ts` is stale (>120 s) or future-dated
  (>30 s), and remembers seen `request_id`s so the same envelope cannot be spent twice
  within the window. The seen-set is in-memory; a restart forgets it, but a replay
  older than the window is refused as stale anyway, so the exposure is bounded by the
  window, not by uptime.
- The **coordinator** applies the same freshness check, and a lease redeems **exactly
  once** — a duplicate envelope arriving while the first is still streaming is refused
  rather than relayed twice.

Keys are derived from the master so request and response never share a (key, nonce)
pair:

```
k_req  = HKDF-SHA256(master, info="commonweal/v1/request")
k_resp = HKDF-SHA256(master, info="commonweal/v1/response")
```

Inner plaintext is an OpenAI chat-completions body.

`400 bad_envelope` · `401 unauthorized` · `409 no_lease` (unknown, expired, or issued
to a different member).

## 4. Response stream

`application/x-ndjson`, one frame per line, discriminated by `kind`.

**Chunk** — encrypted with `k_resp`; nonce is `seq` as 12 big-endian bytes, so a
reordered or replayed chunk fails authentication rather than decrypting to something
plausible.

```json
{"kind": "chunk", "v": 1, "request_id": "…", "seq": 0,
 "ciphertext": "<b64>", "final": false}
```

The last chunk has `"final": true` and empty plaintext. **A stream ending without it
was truncated** — clients must raise, not return a short answer.

**Receipt** — trailing, **not encrypted**. The coordinator must read counts to run the
ledger. It learns *how much*, never *what*.

```json
{"kind": "receipt", "v": 1, "request_id": "…",
 "prompt_tokens": 128, "completion_tokens": 512,
 "engine": "sglang", "engine_version": "0.4", "hw_class": "cuda-sm90",
 "finish_reason": "stop"}
```

`finish_reason` is the engine's own word for why generation stopped: `"stop"` for a
finished answer, `"length"` for one the token budget cut off, `""` when the engine did
not say. It exists for the same reason `final` does — `final` distinguishes a complete
stream from a lost one, and `finish_reason` distinguishes a complete *answer* from a
capped one. With reasoning models a capped answer is the common case, not the rare one.

Receipts are read permissively: absent optional fields default rather than raising, so
members can upgrade on their own schedule. A count of `0` means *not reported*, and the
peer's char/4 estimator fills in — recording a hard zero for a request that produced
text would understate the ledger in the serving peer's favour.

**Error** — terminal. Emitted mid-stream when the status code is already spent.

```json
{"kind": "error", "v": 1, "request_id": "…", "message": "…"}
```

## 5. Heartbeat

```
POST /v1/peers/heartbeat        body: {"peer_id": "bob-ws", "resident_gb": 62.0,
                                       "healthy": true, "detail": "served a request 3s ago"}
```

Same signed wrapper. The roster decides what the beat means:

| signer | role | effect |
|---|---|---|
| the peer's `owner` | serving liveness | `healthy`/`detail` gate routing; credits contributors who are not attesting |
| a declared `contributor` | residency attestation | credits that member, capped at its declared share; **cannot** affect routing |
| anyone else | — | 403 |

A contributor attesting must never be able to make a broken group routable — that would
let one member's daemon override another member's readiness probe. Only the machine
running the endpoint can say whether the group can serve.

Contributors are how "which member left" gets answered: a departed member is one whose
attestations went stale, which needs no knowledge of the engine's shard topology. Members
who never attest are still credited on the head's word, so a group where only the head runs
a daemon behaves as before. The two crediting paths **partition** time rather than
overlapping it — an interval settled by one is never re-billed by the other, including an
outage, which is settled as owing nothing rather than left to be claimed on recovery.

`healthy` is what the peer's readiness probe found — a real one-token completion, not a
port check. `detail` is optional and carries the reason in the peer's own words, so an
operator can see *why* a peer left the pool without curling every peer in a group. It is
inside the signed body, and omitted when empty so an older peer's signed bytes are
unchanged.

`detail` originates in an engine error message and is echoed to every member on
`/v1/stats`, so the coordinator sanitises it: printable characters only, whitespace
collapsed, truncated to 200 characters. It is a diagnostic, never a control signal —
routing keys off `healthy` alone.

Contribution is credited as `resident_gb × elapsed` since the previous beat, capped at
300 s so a peer that vanishes for hours cannot claim the whole gap, and at the roster's
declared `capacity_gb` so a peer cannot mint standing by over-reporting.

## 6. Reads

```
GET /v1/health                                          — open
POST /v1/roster   POST /v1/stats   POST /v1/concurrency — members only
```

Only `/v1/health` is unauthenticated, and it reveals nothing beyond liveness, the
federation id and the roster version. That is meant literally: both servers disable
FastAPI's generated `/docs`, `/redoc` and `/openapi.json`, which are open by default.
This document is the specification, so a generated schema tells a reader nothing new,
and an interactive request builder on a public always-on service is surface with no
matching use. The other three carry the federation's metadata —
who is in it, where their machines are, when they are active — and the coordinator is
public and always-on, so they require the same signed wrapper as `/v1/lease` (an empty
`body` is fine). Members' metadata is members' business; a passer-by gets `401`.

`/v1/concurrency` reports observed concurrency, so a group can see whether its real
load would benefit from a batching engine before investing in one. Only request-*start*
events are sampled; lease and end events would bias the distribution toward the moments
concurrency is changing rather than the steady state.

`/v1/roster` is a convenience: recipients verify it themselves against pinned admin
keys. Serving it grants the coordinator no authority, and the signature requirement
protects its contents, not its integrity.

## 7. The peer's own surface

Everything above is the coordinator. A peer serves two endpoints of its own, and its
`endpoint` is named in the roster, so anyone holding a roster — and anyone who scans
the port — knows where to find them.

```
POST /infer     — a signed, sealed envelope (§3). Verified against the roster.
GET  /health    — open
```

Exactly those two: the generated documentation routes are disabled here as well.

`POST /infer` is the data plane: the sender is checked against the roster and the
envelope's freshness and `request_id` are checked before anything is decrypted, so an
unauthenticated caller cannot spend the peer's capacity or its CPU.

`GET /health` takes **no signature**, deliberately — a peer that could only be probed
by an authenticated caller could not be watched by an ordinary uptime monitor or a
container orchestrator. It is not the same disclosure as the coordinator's
`/v1/health`, and the difference is worth stating plainly:

```json
{"status": "ok", "detail": "served a request 3s ago", "peer_id": "bob-ws",
 "model": "glm-5.2", "engine": "sglang", "engine_version": "0.4",
 "hw_class": "cuda-sm90"}
```

So an unauthenticated caller who can reach a peer learns which model it serves, which
engine and **which version** of it, and what class of hardware is underneath. The
version is the part worth thinking about: it names a specific build of an external
program, which is exactly what someone hunting for a known vulnerability in llama.cpp
or vLLM would want. `docs/THREAT-MODEL.md` records this rather than leaving it to be
discovered.

`detail` is sanitised on the way out — printable characters only, whitespace collapsed,
200 characters — by the same rule the coordinator applies before `/v1/stats` echoes it.
The string originates in an engine's error body, so it is untrusted text arriving at an
operator's terminal, and a backend is free to put an ANSI escape sequence in it.

A peer binds to `127.0.0.1` by default and has to be deliberately exposed. Where the
coordinator reaches it across a network, mutual TLS (`--tls-client-ca`) is the way to
keep `/health` off the public internet without giving up monitoring inside the
federation.

## 8. Transport

All hops support TLS. Servers take `--tls-cert/--tls-key`, and `--tls-client-ca` to
require client certificates (mutual TLS). Clients take `--ca-bundle`,
`--client-cert/--client-key`, and `--insecure` for development.

Payload sealing is independent of TLS and always applies. TLS additionally protects the
control plane — leases, heartbeats, roster fetches — which sealing does not cover.

## Error shape

```json
{"error": {"code": "queue_full", "message": "inference queue is full"}}
```

| code | status |
|---|---|
| `bad_envelope`, `bad_request`, `unsealable` | 400 |
| `unauthorized` | 401 |
| `forbidden` | 403 |
| `unknown_peer` | 404 |
| `no_lease` | 409 |
| `queue_full` | 429 |
| `no_capacity` | 503 |
