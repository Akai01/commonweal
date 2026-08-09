# Security policy

## Status

Pre-1.0, no releases, no production deployments we know of. Only `main` is supported;
there is nothing older to backport to.

This is a small project maintained in spare time. Reports are read and taken seriously,
but there is no bounty and no response-time guarantee.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting** — the *Security* tab → *Report a
vulnerability*. That keeps the report private until there is something to say publicly.

Please do not open a public issue for anything that would let someone read another
member's prompts, impersonate a member, or forge a roster.

Useful in a report: what you did, what happened, and what you expected. A failing test is
worth more than a paragraph.

## What counts

`docs/THREAT-MODEL.md` is the contract, and it is unusually explicit about what this
system does *not* defend against. Reading it first will save you time, because several
things that look like vulnerabilities are documented design.

### In scope — these would be real

- **The coordinator reading request or response content.** It relays sealed bytes and
  holds no decryption key. That claim is the architecture's foundation; anything that
  breaks it is the most serious report you can file.
  (`tests/test_e2e.py::test_coordinator_cannot_decrypt`)
- **A non-member getting work accepted**, or a member impersonating another.
- **Roster forgery**: a roster accepted without a signature from a pinned admin key, or a
  rollback to an older version reinstating an expelled member.
- **Chunk reordering, replay, or truncation** accepted as a valid response rather than
  failing authentication.
- **Replay of a signed control request** outside the nonce cache and timestamp window.
- **Key material reaching disk, logs, or an unauthenticated endpoint** where it was not
  meant to.
- **A peer being able to mint fair-share standing** beyond what the signed roster
  declares for it.
- Denial of service that a single member can cause cheaply and unilaterally — for
  example an unauthenticated request that makes a member's machine do real work. (One of
  these was found and fixed during development: concurrent `/health` requests each
  triggered an inference probe.)

### Not in scope — documented, not defects

- **A peer reading the prompt it is asked to compute.** A peer decrypts because it must;
  a matmul on ciphertext is not a matmul. Membership, not cryptography, is the privacy
  boundary. This is the project's central trade and it is stated everywhere.
- **A malicious member** returning wrong output, or reading what routes to them. The
  mitigation is expulsion and real-world accountability. The system is explicitly not
  designed for untrusted peers.
- **The coordinator learning token counts and `finish_reason`.** The receipt frame is
  deliberately unencrypted so the ledger can work; it learns *how much*, never *what*.
- **Traffic analysis**: request timing, sizes, and which peer served which member are
  visible to the coordinator by construction.
- **A peer's unauthenticated `GET /health`** disclosing its model, engine, engine version
  and hardware class. It takes no signature so that ordinary monitoring can reach it, and
  what it discloses is spelled out in `docs/PROTOCOL.md` §7 and `docs/THREAT-MODEL.md`.
  Use `--tls-client-ca` to keep it inside the federation. A report that it exposes
  something *beyond* that list — anything about members, prompts, the roster, or key
  material — is very much in scope.
- **A member over-reporting the memory it holds**, within its roster-declared cap. That
  is a social problem in a federation that already assumes trust.
- **Anything requiring an already-compromised client machine.** The plaintext and the
  master secret both live there.
- Findings against the **inference engines** this talks to (llama.cpp, Ollama, SGLang,
  vLLM). They are external processes; report those upstream.

If you are unsure which side of that line something falls on, report it privately anyway.
A wrong guess in that direction costs nothing.
