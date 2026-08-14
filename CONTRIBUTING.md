# Contributing

Bug reports, failing tests, and patches are all welcome. This is a small project
maintained in spare time, so there is no response-time guarantee — but everything
gets read.

**Security issues do not belong in the issue tracker.** Use the *Security* tab →
*Report a vulnerability*, and read [SECURITY.md](SECURITY.md) first: it says
exactly what is in scope, and several things that look like vulnerabilities are
documented design.

## Getting set up

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest -q          # 214 tests, about 25 seconds
```

Python 3.12 is the floor; CI runs 3.12 and 3.13. The suite needs no network, no
GPU, and no model — it starts real servers on ephemeral ports and generates a real
CA for the TLS run. If it needs more than that from you, something is wrong and it
is worth reporting.

Develop against the mock engine. The whole federation is exercisable in
milliseconds without downloading weights:

```bash
--engine '{"kind":"mock"}'
```

## The conventions that are not obvious

Most of this codebase's rules are visible in the code once you know to look. These
are the ones that have bitten people.

**Every behaviour gets a test, and the test says what it is for.** The suite is not
a coverage exercise; it is the record of what this system claims. Test names here
are sentences (`test_coordinator_cannot_decrypt`,
`test_attestation_cannot_make_a_broken_group_routable`), and docstrings explain the
failure the test exists to prevent. A patch that changes behaviour without a test
is incomplete, and a bug report with a failing test is worth more than a paragraph.

**Comments explain why, not what.** The reader can see what the line does. What
they cannot see is the alternative you rejected, the backend that misbehaves, or
the attack the check exists to stop. That is what the comment is for. A patch
written in a terser style will look foreign next to the surrounding code.

**[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) is a contract, not commentary.** If
your change touches what is or is not protected — a new endpoint, a new field on
the wire, a relaxed check, anything an attacker could reach — it updates that
document in the same commit. The threat model being accurate rather than
reassuring is the property the whole project rests on; a change that quietly makes
it false is worse than the bug it fixed.

**Signed bytes are compatibility surface.** Roster fields are covered by admin
signatures, and control-plane bodies are covered by member signatures. Emitting a
new key unconditionally invalidates every signature made before that field
existed. See how `contributors` handles it in
[roster.py](src/commonweal/roster.py) — omitted entirely when empty, because an
absent list and an empty one mean the same thing, so nothing is traded for the
compatibility. Adding a field to signed bytes without that care is a silent
break-everything change.

**Engines stay external.** No inference code enters this repository. The `Engine`
protocol in [engines/base.py](src/commonweal/engines/base.py) is deliberately tiny
— health plus a token stream. If a change needs more from an engine than that, the
design question comes before the patch.

**Docs ship with the change.** [docs/PROTOCOL.md](docs/PROTOCOL.md) specifies the
wire format and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the
reasoning. A wire change that lands without the spec update leaves the next person
reading a document that lies to them.

## Style

Prose in comments and docs uses British spelling (`sanitise`, `behaviour`);
wire-protocol identifiers do not change to match (`unauthorized` is an error code
on the wire and stays as it is). Lines run to roughly 96 columns — a soft limit,
not a rule to contort code around.

Before opening a PR:

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
```

The lint rule set is pinned in `pyproject.toml` rather than left to ruff's
defaults, which grow between releases — otherwise updating ruff would fail the
gate on code nobody touched. If a new rule is worth adopting, adopt it in its own
commit.

## Pull requests

Small and focused beats large and comprehensive. Say what the change does and why
the current behaviour is wrong — the second half is the part that is hard to
reconstruct later, and it usually becomes the commit message.

If you are unsure whether something is a bug or an intentional trade, open an issue
and ask before writing the patch. Several of this project's sharper edges are
deliberate, and they are all written down somewhere in `docs/`.
