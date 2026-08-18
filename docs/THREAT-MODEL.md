# Threat model

Written to be accurate rather than reassuring. Overstating what encryption buys is the
one failure that would make everything else here untrustworthy.

## The boundary

**Members trust members. Nothing else is trusted.**

```
client ─┐
        ├─ UNTRUSTED: network, coordinator, non-members
        └─ TRUSTED:   compute peers (members' machines)
```

Cryptography's job is to protect against everything on the untrusted side. It cannot
and does not protect against the trusted side, because a peer must decrypt in order to
compute — a matmul on ciphertext is not a matmul.

## Protected against

| threat | mechanism |
|---|---|
| Passive network observers (content) | payload sealed with X25519 + AES-256-GCM, independent of transport |
| Passive observers (control plane) | TLS on every hop — `--tls-cert/--tls-key` inbound, `--ca-bundle` outbound |
| Rogue server impersonation | certificates verified against a pinned CA; asserted by `test_untrusted_certificate_is_refused` |
| **The coordinator**, including one actively lying | relays sealed bytes; holds no decryption key, **and cannot nominate one** — the client seals to the key the signed roster names for the assigned peer, not to the key the lease response carries. Asserted by `test_coordinator_cannot_decrypt` and `test_client_refuses_a_coordinator_substituted_peer_key` |
| Tampering in transit | AES-GCM tag → hard abort, never partial delivery |
| Non-members submitting work | Ed25519 signature checked against the signed roster |
| Non-members reading the federation's metadata *from the coordinator* | `/v1/roster`, `/v1/stats` and `/v1/concurrency` require a member signature; only `/v1/health` is open. This is the coordinator only — see the peer `/health` entry below |
| Replayed control requests | nonce cache + timestamp window (120 s, 30 s skew grace) |
| Replayed sealed envelopes | `ts` is inside the envelope's signed bytes; the peer refuses stale envelopes and remembers seen `request_id`s, and a lease redeems exactly once at the coordinator |
| Reordered / replayed response chunks | counter-derived nonces; wrong position fails authentication |
| Truncated responses | explicit final marker; its absence raises `TruncatedStream` |
| Roster forgery | admin keys pinned locally, never read from the document |
| Roster rollback | version must strictly increase |
| Cross-member lease theft | leases bound to the member they were issued to |
| One peer reading another's traffic | request sealed to the assigned peer alone (two-round lease) |
| A coordinator routing to a peer that is not on the roster, or one serving a different model | the client resolves the lease's `peer_id` in its own pinned roster and refuses a lease that names an unknown peer or the wrong model |

### Why the client needs its own roster

The coordinator row above is the load-bearing one, and it depends on an
operational requirement worth stating on its own: **a client verifies peer keys
against a roster it holds, exactly as peers and coordinators do.** `commonweal
chat` therefore requires `--roster` and `--admin-key`, and `CommonwealClient`
takes a `Roster`. Neither is optional.

The reason is that "the coordinator holds no key" is not by itself enough. A
coordinator that holds no key can still *choose* one: answer the lease with its
own X25519 public key, and the client seals the master secret where the
coordinator can open it. Nothing downstream notices, because every signature,
nonce and sequence check still passes — they authenticate a session, and the
coordinator picked the session key. The prompt decrypts and forged reply chunks
verify.

So the lease says *which peer*; the roster says *which key*. The client refuses
a lease whose key disagrees with the signed document rather than reconciling
them, because the only reason for the two to differ is that someone is lying.
This is the same rule that makes admin keys trustworthy — pinned out of band,
never taken from the party being checked.

## NOT protected against — state this to users

**A compute peer.** It decrypts your prompt and sees your activations. This is
structural, not an oversight. If you would not send a member your prompt in a chat
message, do not send it through their peer.

**A malicious member.** They can read what routes to them and return corrupted output.
Mitigation is expulsion and real-world accountability, not cryptography. A federation
is only as private as its least trustworthy member.

**Your identity keys at rest, by default.** `commonweal keygen` writes the Ed25519 and X25519
secret halves into a `0600` file, which is readable by root, by anything running as you,
and by whatever backs your home directory up. `--keyring` moves them into the OS keychain
instead, leaving only the public block on disk; `commonweal keyring-migrate` converts an
existing identity. It is opt-in rather than the default because peers and coordinators run
on headless servers where no keychain exists, and a default that fails there would be
worse than an honest file. `keygen` says which one you got.

A leaked identity is full impersonation of that member until an admin publishes a roster
without them. Migration raises the floor and does not erase the past: the old bytes stay
recoverable from the disk until it is overwritten.

**An engine `api_key`, if you pass one on the command line.** The `--engine` spec accepts
`{"api_key": "..."}` for a backend that wants an `Authorization` header — a hosted
gateway rather than a local llama.cpp. Written inline it lands in `ps` output for every
local user and in the shell history, which is a weaker place than this project puts its
own keys. It never leaves the peer and is not part of the federation's trust model, but
it is somebody's credential: for a backend that needs one, pass the spec through a
`0600` file (`--engine "$(cat engine.json)"`) or a systemd `EnvironmentFile` rather than
typing it into the command. A local engine on `127.0.0.1` needs no key at all, which is
the configuration this is built around.

**A compromised client machine.** The plaintext and the master secret both live there.

**Traffic analysis.** The coordinator sees who talks to whom, when, and how much. TLS
hides this from the *network*, not from the coordinator. Members see the same picture
through the authenticated read endpoints; the signature requirement keeps it from
*non-members*, nothing more.

**A peer's `GET /health`, to anyone who can reach the peer.** Locking down the
coordinator's read endpoints does not lock down the peers, and it would be easy to read
the row above as though it did. Each peer serves an unauthenticated `/health` that
names its model, its engine, its **engine version**, and its hardware class
(docs/PROTOCOL.md §7). It is unauthenticated on purpose — a peer that only answered
signed probes could not be watched by an ordinary uptime monitor — but the trade is
real: an engine version identifies a specific build of an external program, which is
the first thing someone looking for a known vulnerability in llama.cpp or vLLM wants.
Nothing about members, prompts, or the roster is exposed there, and `/infer` next to it
is fully authenticated, so this discloses configuration, never content or capacity.

A peer binds to `127.0.0.1` by default and must be deliberately exposed. Where it is
reachable across a network, `--tls-client-ca` (mutual TLS) keeps `/health` inside the
federation while leaving monitoring possible for the members who hold a certificate.
The `detail` string in that response is sanitised before it is returned — printable
characters only, whitespace collapsed, 200 characters — because it originates in an
engine's error body and ends up in an operator's terminal.

**Replay, across a restart.** Both replay caches — the coordinator's nonce cache and
the peer's envelope seen-set — are in memory, so a restart forgets them. The signed
timestamp bounds the exposure: a captured message is refusable as stale 120 s (plus
30 s skew grace) after it was signed, whatever the caches remember.

**Anything, if TLS is off.** Without `--tls-cert`, payload content is still sealed but
leases, heartbeats and roster fetches travel in clear. Both servers print a warning at
startup. `--insecure` disables certificate verification and is for development only.

**Token counts.** The trailing `Receipt` frame is deliberately **not encrypted** — the
coordinator must learn counts to run the ledger. It learns *how much* was generated,
never *what*. This is an explicit trade, not an accident.

The receipt also carries `finish_reason` (`"stop"` / `"length"` / `""`), added 2026-08-03
so a client can tell a finished answer from one the token cap cut short. The coordinator
therefore also learns *whether a response hit its limit*. This is length-class metadata,
not content, and it is not fully derivable from the counts alone — `max_tokens` travels
inside the sealed payload, so the coordinator cannot otherwise tell a request that
stopped naturally at 200 tokens from one capped at 200. Small, real, and stated here
rather than discovered later. Nothing about *what* was generated is exposed by it.

**That a request failed, and roughly why.** An `error` frame is unencrypted for the
same structural reason the receipt is: it is emitted when the status code is already
spent, and a client that never established a session key still has to be able to read
it. So the coordinator learns that a request failed and sees a bounded diagnostic
string — which may name an engine's HTTP status or say that a peer was unreachable.
That is failure-class metadata, not content. It is bounded rather than trusted: every
emitter sanitises the message to printable characters, collapsed whitespace and 400
characters, because the text originates in an engine's error body or a peer's raw HTTP
response and ends at an operator's terminal. Without that, a backend behind a gateway
could write an ANSI escape into every member's terminal, and could put far more of a
request's context in front of the coordinator than the receipt concedes.

**Availability.** The coordinator is untrusted but not optional. It can go down or
refuse to route. Failover is currently manual.

## Deliberately out of scope

| not defended | why |
|---|---|
| Byzantine / adversarial peers | federation assumes membership carries accountability. Defending against adversaries reintroduces verification, which needs 2–3× redundant execution or zkML |
| Consensus on output correctness | float math is not bit-reproducible across heterogeneous hardware; exact-match consensus is unsatisfiable by construction |
| Homomorphic or MPC inference | 10⁴–10⁶× (FHE) or 2–3 orders of magnitude more communication (MPC) |

## Fault detection, and why tolerance is enough here

We do not verify that a peer computed correctly. We do not need to.

Tolerance-based comparison is **fatal** against an adversary — they hide inside the
band forever. Against *faults* it is fine: bad RAM, a corrupted shard, or a mismatched
model version all diverge far outside any sane tolerance and are trivially caught.

A federation faces faults, not adversaries. That is the entire verification requirement,
and equivalence satisfies it.

## Reproducibility: equivalence, not bit-identity

A heterogeneous federation **cannot** promise byte-identical output. AVX2, AVX-512,
CUDA and Metal round differently; engine versions differ.

We guarantee: same model, same weights, same sampling semantics.
We do **not** guarantee: identical bytes across peers.

Therefore every response carries `engine`, `engine_version` and `hw_class`, surfaced by
`Completion.served_by()`. A user seeing two different answers can tell why.

For work needing reproducibility, pin a reference hardware class — at the cost of a
smaller peer pool.

## Optional hardening

Peers with SEV-SNP, TDX, or confidential-computing GPUs can publish a remote
attestation. The roster schema carries an `attestation` field for this. Clients could
then require attested peers only. **Not implemented** — the field exists so adding it
later is not a schema break.

## Residual risks ranked

1. **A member's machine is compromised** — highest likelihood, full prompt exposure
2. **Federation grows past real trust** — the social failure that silently voids the model
3. **Coordinator outage** — availability only; no confidentiality impact
4. **Client key theft** — full impersonation until the roster is updated
