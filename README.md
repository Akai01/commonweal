# commonweal

**A trusted-federation control plane for pooled LLM inference.**

A group of people who already trust each other — a team, a lab, a few friends —
pool their machines into one inference service, contribute-to-use. Each member
runs their own model on their own hardware; commonweal routes requests across
the group, meters usage, and schedules fairly, so everyone can reach capacity
none of them runs alone.

It is **only the control plane**. Inference engines run as external processes;
commonweal speaks OpenAI-compatible HTTP to whatever each member runs
(llama.cpp, Ollama, vLLM, SGLang, …).

```
   ┌──────────┐  1. lease (signed)           ┌───────────────────────┐
   │  CLIENT  │ ───────────────────────────► │  COORDINATOR          │
   │ (member) │ ◄─────────────────────────── │  UNTRUSTED            │
   │          │  2. {peer, its public key}   │  · roster + registry  │
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

## Why a federation

Every hard problem in decentralized inference — peers reading your prompts,
verifying nobody cheated, consensus under floating-point non-determinism,
incentives to contribute — is a *consequence of assuming strangers*.

commonweal doesn't solve those problems; it picks the configuration where they
don't arise. Trust is inherited from the real world instead of manufactured by
cryptography. It's the email/Matrix model: decentralized operation, scoped
trust. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for exactly what that
does and does not buy — including what is *not* protected.

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
```

## Quick start

**1 — Everyone makes an identity.** Send the printed public block to your admin.

```bash
commonweal --identity alice.json keygen alice
commonweal --identity bob.json   keygen bob
```

Secret keys are written to a `0600` file by default, and `keygen` says so. On a
desktop, `pip install '.[keyring]'` and `keygen --keyring` stores them in the OS
keychain instead, leaving only the public block on disk. It is opt-in because
the headless servers that run peers usually have no keychain.

**2 — The admin builds and signs a roster.**

```bash
commonweal --identity alice.json roster init my-lab --out roster.json
# add members + peers to roster.json, then:
commonweal --identity alice.json roster sign roster.json
# prints the admin key to distribute out of band
```

**3 — Members run peers.** The engine is external; point `--engine` at it.

```bash
commonweal-peer --roster roster.json --admin-key alice=<KEY> \
                --identity bob.json --peer-id bob-ws \
                --coordinator http://coord:8080 --resident-gb 62 --hw-class cpu \
                --engine '{"kind":"openai","base_url":"http://localhost:11434/v1","model":"llama-3.1-8b"}'
```

The `model` in `--engine` must match what the roster advertises for this peer,
or the peer refuses to start: the coordinator routes on the roster, and a peer
answering with some other model makes every provenance stamp it writes a false
one.

**4 — Someone runs the coordinator.** It needs no trust and no keys.

```bash
commonweal-coordinator --roster roster.json --admin-key alice=<KEY> --port 8080 \
                       --tls-cert coord.pem --tls-key coord.key      # HTTPS
```

Every component takes `--tls-cert/--tls-key` (inbound) and
`--ca-bundle/--client-cert/--client-key` (outbound, including mutual TLS).
Without them it serves plain HTTP and says so on startup.

**5 — Use it.**

```bash
commonweal --identity alice.json chat "hello" --model llama-3.1-8b --coordinator http://coord:8080
```

Develop against `--engine '{"kind":"mock"}'` — the whole federation is
exercisable in milliseconds without downloading a model.

## Design decisions worth knowing

**Two-round leases.** The client asks for a lease, learns which peer it got *and
that peer's public key*, then seals the request to that peer alone. A shared
pool key would let every peer decrypt every request. The extra round trip costs
about a millisecond against multi-second inference.

**The coordinator holds no key.** It relays sealed bytes and meters usage. It
learns *how much* was generated, never *what* — token counts arrive in a clear
trailing receipt frame, an explicit trade documented in the threat model.
`tests/test_e2e.py::test_coordinator_cannot_decrypt` asserts the property.

**Sealed, replay-proof envelopes.** Requests are sealed with an X25519 sealed
box over AES-256-GCM; response chunks carry counter-derived nonces, so a
reordered or replayed chunk fails authentication instead of decrypting to
plausible output. Every envelope carries a signed timestamp, and peers refuse
stale or already-seen envelopes, so a captured request cannot be spent twice.

**Admin keys come from local config, never from the roster.** A roster that
vouched for its own signers would be forgeable by anyone. You pin admin keys out
of band when you join — that hand-off *is* the act of joining. Roster versions
strictly increase, so an old copy can't be replayed to reinstate an expelled
member.

**Contribution is GB-hours of residency, not requests served.** A peer holding
memory resident all night has done the expensive thing even if no request routed
to it. Fair share is `(gb_hours + 1) / (ktokens + 1)`; the priors mean a
newcomer starts usable rather than starved.

**Provenance on every answer.** A heterogeneous federation *cannot* promise
byte-identical output — AVX2, AVX-512, CUDA and Metal round differently. So
commonweal guarantees equivalence, not bit-identity, and stamps `engine`,
`engine_version`, and `hw_class` onto every response.

## What this is not

- Not an inference engine. Engines are external processes.
- Not a blockchain. Accounting is a SQLite table; the incentive is membership.
- Not for untrusted peers. A peer decrypts because it must; membership is the
  privacy boundary.
- Not permissionless. Joining is a deliberate, vouched-for act.

## Layout

| path | role |
|---|---|
| `src/commonweal/proto/` | wire types, canonical signing bytes, versioning |
| `src/commonweal/crypto.py` | X25519 sealed boxes + AES-256-GCM, Ed25519 identity |
| `src/commonweal/replay.py` | freshness window + seen-value cache, shared by both planes |
| `src/commonweal/roster.py` | the signed roster — the trust anchor |
| `src/commonweal/ledger.py` | contribution/consumption, fair share |
| `src/commonweal/engines/` | engine adapters (mock, OpenAI-compatible) |
| `src/commonweal/coordinator/` | registry, scheduler, relay, HTTP API |
| `src/commonweal/peer/` | the one component that sees plaintext |
| `src/commonweal/client/` | identity, two-round flow, CLI |
| `src/commonweal/tlsconfig.py` | transport security for every hop |

```bash
.venv/bin/python -m pytest -q     # 211 tests
```

## Docs

| doc | what it covers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the design and the reasoning behind it |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | wire format v1 |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | what is and is not protected |
| [docs/ENGINE-NOTES.md](docs/ENGINE-NOTES.md) | what live backends actually do — reasoning fields, usage frames |
| [SECURITY.md](SECURITY.md) | how to report a vulnerability, and which findings are documented design |

## Status

The replicated federation — every peer runs a whole model, the coordinator
routes and meters across them — is implemented and tested end to end over both
HTTP and HTTPS. Splitting a single model across members (so a group can serve a
model none of them can hold alone) is the natural next step but not yet a
supported configuration; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §11.

Known gaps: coordinator failover is manual, and the adapter is verified against
llama.cpp and Ollama but not yet against a batching backend like vLLM or SGLang.

## License

MIT — see [LICENSE](LICENSE).
