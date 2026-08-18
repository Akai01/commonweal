# Architecture

Commonweal is a **control plane** for pooled LLM inference among a group of
members who already trust one another. It routes and meters work; it does not
run models. Inference engines are external processes that each member operates,
reached over an OpenAI-compatible HTTP interface.

This document describes what the system is, how a request flows through it, and
why the security-relevant pieces are built the way they are. The wire format is
specified in [PROTOCOL.md](PROTOCOL.md); what is and isn't protected is in
[THREAT-MODEL.md](THREAT-MODEL.md).

## 1. The model

A **federation** is a set of members with pre-existing, real-world trust who
pool their machines into one logical inference cluster on a contribute-to-use
basis. Each member runs their own engine on their own hardware; the control
plane lets the group share that capacity as if it were one service.

The shape is the one email and Matrix use: independent operators, each
authoritative over their own resources, interoperating through a common
protocol, with **trust decided per-member rather than globally**.

Trust is inherited from outside the system. That single assumption is what lets
the design stay small: it does not have to defend against its own participants,
so it needs no consensus, no redundant re-execution, and no homomorphic
cryptography. It is **not** a blockchain, a volunteer network, or a marketplace
(see §10).

## 2. Trust boundary

```
   ┌──────────┐  1. lease (signed)           ┌───────────────────────┐
   │  CLIENT  │ ───────────────────────────► │  COORDINATOR          │
   │ (member) │ ◄─────────────────────────── │  UNTRUSTED            │
   │          │  2. peer id; key from roster │  · roster + registry  │
   │          │                              │  · admission + queue  │
   │          │  3. sealed to THAT peer      │  · fair-share sched   │
   │          │ ═══════════════════════════► │  · ledger             │
   │          │ ◄═══════════════════════════ │  · relays ciphertext  │
   └──────────┘  4. sealed chunks back       │  · HOLDS NO KEY       │
                                             └───────────┬───────────┘
                     ═════════ TRUST BOUNDARY ═══════════╪═══════════
                                                         ▼
                                         ┌───────────────────────────┐
                                         │ PEER  (member's machine)  │
                                         │ unseals, calls its engine │
                                         └───────────────────────────┘
```

- **Members trust members.** Nothing else is trusted.
- The **coordinator is untrusted infrastructure.** It routes sealed ciphertext,
  meters usage, and schedules — and holds no key that can open a request. That
  is what lets it be public, always-on, and run by whoever is willing, without
  widening the trust boundary to include them.
- A **peer** is the one place plaintext exists on the serving side. It decrypts
  because a matmul on ciphertext is not a matmul. Membership, not cryptography,
  is therefore the privacy boundary — [THREAT-MODEL.md](THREAT-MODEL.md) says so
  plainly rather than implying the encryption protects against the machine doing
  the work.

## 3. Components

| component | role |
|---|---|
| **client** (`commonweal.client`) | holds the member identity; runs the two-round flow; the only place both the plaintext prompt and the response key exist |
| **coordinator** (`commonweal.coordinator`) | roster + peer registry, admission queue, fair-share scheduler, usage ledger, opaque relay. Holds no decryption key. |
| **peer** (`commonweal.peer`) | registers and heartbeats, verifies and unseals requests, drives an external engine through the adapter, re-seals and streams the reply |
| **engine adapter** (`commonweal.engines`) | a thin `Engine` protocol; `MockEngine` for tests, `OpenAICompatEngine` for real backends |
| **roster** (`commonweal.roster`) | the admin-signed trust anchor: who the members are, their public keys, and which peers serve which models |
| **protocol** (`commonweal.proto`) | wire types, canonical signing bytes, and a strict version gate |

## 4. Request lifecycle

A request takes two rounds. The point of the split is least privilege.

1. **Lease.** The client sends a signed request to `POST /v1/lease`. The
   coordinator authenticates it against the roster, applies fair-share
   admission (queuing if the pool is saturated), assigns a live peer, and
   returns that peer's id, its public key, and a `request_id`.
2. **Resolve.** The client looks the assigned `peer_id` up in **its own pinned
   roster** and takes the encryption key from there. A lease naming a peer the
   roster does not list, offering a key the roster does not list for it, or
   serving a different model, is refused outright.
3. **Infer.** The client seals the prompt **to the assigned peer alone** and
   posts the envelope to `POST /v1/infer`. The coordinator verifies the sender's
   signature, redeems the lease exactly once, and relays the opaque envelope to
   the peer.
4. **Serve.** The peer verifies the sender, refuses replays, unseals, calls its
   engine, and streams back a sequence of independently-authenticated ciphertext
   chunks plus a trailing usage receipt.
5. **Meter.** The coordinator reads the (unencrypted) receipt to record token
   counts in the ledger, then releases the peer's slot.

The alternative — a shared pool key every peer holds — would let any peer
decrypt any request. The extra round trip costs about a millisecond against
multi-second inference; least privilege is worth far more than that.

Step 2 is what keeps step 1 from mattering more than it should. The coordinator
decides *which* peer serves a request — that is its job, and it needs the
freedom to schedule. It does not decide *who can read* the request: a
coordinator that could name the recipient key would simply name its own, and
the sealing, signing and nonce machinery would all keep working while it read
every prompt. Routing is the coordinator's; key material is the roster's.

## 5. Cryptography

The primitives are libsodium (via PyNaCl) and `cryptography`'s AES-GCM. No
curve arithmetic is implemented here; that is how projects earn CVEs.

**Sealing.** Each request draws a fresh 32-byte master secret, sealed to the
assigned peer with an **X25519 sealed box**. Request and response are encrypted
with **AES-256-GCM** under two keys derived from that master by
HKDF-SHA256 with distinct info strings (`commonweal/v1/request`,
`commonweal/v1/response`), so request and response can never share a
(key, nonce) pair. The hybrid construction — asymmetric seal of a symmetric
key — is what lets a streamed response authenticate each chunk without
per-chunk asymmetric work.

**Chunk integrity.** Each response chunk's nonce is derived from its sequence
number rather than carried on the wire, so a dropped, reordered, or replayed
chunk fails authentication instead of decrypting to something plausible. The
stream ends with an explicit final marker; a stream that ends without it was
truncated, and the client raises rather than returning a short answer.

**Identity.** Members and peers hold Ed25519 signing keys. Every control-plane
request and every request envelope is signed; the coordinator authenticates the
sender against the roster without being able to read the payload.

**Replay.** A signature proves who wrote a message, never when. Every signed
message therefore carries a timestamp inside its signed bytes, and recipients
enforce a freshness window (120 s, with 30 s of clock-skew grace) backed by a
seen-value cache — a nonce cache on the control plane, a `request_id` seen-set
on the peer's data plane. A lease redeems exactly once, so a duplicate envelope
in flight is refused rather than served twice. The caches are in memory; the
signed timestamp bounds the exposure across a restart. See
[replay.py](../src/commonweal/replay.py).

## 6. Roster and membership

The roster is a signed JSON document — the trust anchor. It names the members
and their public keys, lists the peers and the models they serve, and is signed
by one or more federation admins.

- **Admin keys are pinned locally**, from out-of-band configuration, and are
  never read from the document itself. A roster that vouched for its own signers
  would be forgeable by anyone. Pinning those keys when you join *is* the act of
  joining.
- **Versions increase monotonically.** A recipient rejects any roster whose
  version is not strictly greater than the one it holds, so an old copy cannot be
  replayed to reinstate an expelled member.
- **Peers may declare contributors.** When several machines pool memory behind
  one endpoint, the entry names who supplied what, so credit is shared rather
  than landing entirely on whoever runs the endpoint. The split is declared in
  the admin-signed roster, not asserted by the machine.

Because it is small, signed, and versioned, a roster distributes fine as a file
or a git repository.

## 7. Accounting and scheduling

Contribution is measured in **GB-hours of resident memory**, not requests
served: committing memory to the pool is the expensive act even when no request
routes to a given peer. Peers report residency on a heartbeat; the coordinator
caps it at the roster-declared capacity so a peer cannot mint standing by
over-reporting.

Scheduling is a **priority queue ordered by fair share**, not FIFO. Fair share
is `(gb_hours + 1) / (ktokens + 1)` — the priors let a newcomer start usable
rather than starved, and a member who has contributed more than consumed is
served first when the pool is contended. That queue *is* the incentive
mechanism; among people who already know each other it is a sufficient one,
which is the whole reason to choose a federation. Accounting is a handful of
SQLite tables ([ledger.py](../src/commonweal/ledger.py)) — deliberately not a
chain.

Readiness is proved, not assumed: a peer reports itself ready by running a real
one-token completion against its engine, not by checking that a port is open,
because an engine can be listening and unable to serve. The probe is skipped
while requests are succeeding, so it costs nothing under load.

## 8. Engines are external

The control plane needs almost nothing from an engine — load a model, and stream
tokens for a prompt — so the `Engine` protocol is small and every real engine
satisfies it. Engines run as **separate processes**; the peer starts them,
health-checks them, and speaks HTTP to them. No engine source enters this
repository.

In practice there are two adapters: `MockEngine`, deterministic and dependency-
free, for tests and local development; and `OpenAICompatEngine`, which reaches
any server exposing an OpenAI-compatible surface — llama.cpp, Ollama, vLLM,
SGLang, TGI, LMDeploy, LM Studio. What real backends actually do, and the
surprises that cost us, are recorded in [ENGINE-NOTES.md](ENGINE-NOTES.md).

## 9. Reproducibility: equivalence, not bit-identity

A heterogeneous federation cannot promise byte-identical output: AVX2, AVX-512,
CUDA, and Metal round differently, and engine versions differ. Commonweal
guarantees **equivalence** — same model, same weights, same sampling semantics —
not bit-identity, and makes the difference visible instead of asserting it away:
every response is stamped with the serving peer's `engine`, `engine_version`,
and `hw_class`, so a user who sees two different answers can tell why.

This is enough because a federation faces *faults*, not *adversaries*.
Tolerance-based comparison is fatal against an adversary — they hide inside the
band forever — but against a fault (bad RAM, a corrupted model, a version
mismatch) the divergence is far outside any sane tolerance and is trivially
caught. For work that must be reproducible, pin a reference hardware class, at
the cost of a smaller peer pool.

## 10. Design principles and non-goals

- **This is a control plane, not an engine.** Kernels, batching, and model
  formats are out of scope; they belong to whatever engine a member runs.
- **The coordinator never holds a decryption key.** This is the load-bearing
  property; a test asserts it.
- **Honesty about what is protected.** The threat model is a user-facing
  document. Never imply the cryptography defends against a compute peer — it does
  not, and saying so would void the project's credibility.
- **No consensus, token, or blockchain layer.** Accounting is a database table;
  the incentive is membership.
- **Not designed for untrusted peers.** Doing so reintroduces every problem the
  federation model was chosen to avoid.
- **Not permissionless.** Joining is a deliberate, vouched-for act — that is the
  security model, not a limitation of it.

## 11. Status

**What ships today** is the replicated federation: each peer runs a complete
model, and the coordinator routes, meters, and fair-shares whole requests across
peers, over both HTTP and HTTPS, with sealed payloads, signed identities, replay
protection, and contribution accounting. It is exercised end to end against real
engines (see [ENGINE-NOTES.md](ENGINE-NOTES.md)) and by the test suite.

**Splitting one model across members** — so a group can serve a model no single
member can hold — is the natural next step. The roster schema and the ledger
already accommodate multi-machine shard groups, but sharded inference itself is
not yet a supported configuration: it depends on an external engine that can
serve a layer range and exchange hidden state (llama.cpp's RPC backend and exo
both do this), and it is bounded by availability, since every machine in a shard
group is a single point of failure for the whole model. Until then, peers each
run a whole model.

Known limitations: coordinator failover is manual; the OpenAI-compatible adapter
is verified against llama.cpp and Ollama but not yet against a batching backend
such as vLLM or SGLang.
