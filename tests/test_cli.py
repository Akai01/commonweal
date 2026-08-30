"""The three programs a user actually runs.

Coverage here was 0% for both daemon entry points and 38% for the client CLI,
with every subcommand body uncovered. That gap mattered more than the number
suggests: these modules hold refusals that exist for security reasons and had
never executed under test, so a regression in one would have broken first use
without turning the suite red.

The most important case is `chat`. The client seals to the peer key its pinned
roster names rather than the one the lease response carries, which is what stops
an untrusted coordinator nominating a key of its own and reading every prompt.
That property has end-to-end tests, but they all construct `CommonwealClient`
directly -- so if the CLI stopped passing the roster through, the guarantee would
be gone and every one of those tests would still pass. This file closes that
path.

One measurement note, so nobody "improves" it later by making these tests worse:
the `chat` cases run the CLI in a subprocess, which `coverage` does not trace, so
`client/cli.py` still reports ~38% even though its security-critical path is now
covered. The subprocess is not incidental -- `_cmd_chat` calls `asyncio.run`,
which cannot nest inside the running loop of an async test, and the server these
tests talk to lives on that loop. Rewriting them in-process to move a percentage
would cost the coverage they actually provide.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from commonweal.client.keys import Identity
from commonweal.crypto import sign_bytes
from commonweal.proto import b64
from commonweal.roster import Roster

from .harness import free_port, serve


def _federation(tmp_path: Path, *, peer_endpoint: str, model: str = "mock-1b"):
    """An identity file and a signed roster on disk, as a member would hold them.

    Deliberately built the way `roster init` + `roster sign` build one, so these
    tests exercise the same documents the quickstart produces.
    """
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_path = tmp_path / "alice-identity.json"
    alice.save(alice_path)

    body = {
        "v": 1,
        "federation_id": "test-lab",
        "roster_version": 1,
        "updated": "2026-08-02T00:00:00Z",
        "admins": ["alice"],
        "members": [
            {**alice.public_entry(), "role": "admin", "joined": ""},
            {**bob.public_entry(), "role": "member", "joined": ""},
        ],
        "peers": [{
            "id": "bob-ws", "owner": "bob", "enc_pub": b64(bob.enc_pub),
            "endpoint": peer_endpoint, "model": model, "engine": "mock",
            "engine_version": "0", "hw_class": "test",
            "capacity_gb": 8.0, "max_concurrent": 2,
            "availability": None, "shards": [], "attestation": None,
        }],
    }
    doc = {**body, "signatures": []}
    doc["signatures"] = [sign_bytes(Roster.parse(doc).signed_bytes(), alice.signing_key)]
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    return alice, bob, alice_path, roster_path, b64(alice.sign_pub)


async def _cli(*args: str):
    """Run the client CLI in a subprocess. Returns (returncode, stdout, stderr).

    Through `main()` rather than the installed console script, so the test does
    not depend on the entry point being on PATH -- and in a subprocess because
    `_cmd_chat` calls `asyncio.run`, which cannot nest inside the running loop
    of an async test.

    Awaited rather than `subprocess.run`, because the server these tests talk to
    runs as a task on this very event loop: blocking it would stop the server
    answering, and the CLI would hang until the timeout rather than getting its
    lease.
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c",
        "import sys; from commonweal.client.cli import main; sys.exit(main(sys.argv[1:]))",
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=60)
    return proc.returncode, out.decode(), err.decode()


# --- chat: the path that carries the key-substitution defence --------------

async def test_chat_refuses_a_coordinator_that_substitutes_its_own_peer_key(tmp_path):
    """The whole point of the CLI holding a roster, exercised through the CLI.

    A coordinator answering the lease with its own X25519 key would be handed the
    master secret if the client sealed to it. The three tests that already cover
    this build the client in-process; this one goes through argument parsing,
    roster loading and admin-key pinning, which is what a user actually runs.
    """
    from nacl.public import PrivateKey

    port = free_port()
    alice, bob, ident, roster, key = _federation(
        tmp_path, peer_endpoint=f"http://127.0.0.1:{free_port()}"
    )
    evil = b64(bytes(PrivateKey.generate().public_key))
    sealed = {}

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/v1/lease")
    async def _lease():
        return JSONResponse({
            "request_id": "r1", "peer_id": "bob-ws", "peer_enc_pub": evil,
            "peer_endpoint": "http://127.0.0.1:1", "model": "mock-1b",
            "engine": "mock", "engine_version": "0", "hw_class": "test",
            "expires_at": 9e9,
        })

    @app.post("/v1/infer")
    async def _infer():
        sealed["reached"] = True
        return JSONResponse({}, status_code=500)

    async with serve(app, port) as url:
        rc, out, err = await _cli(
            "--identity", str(ident), "chat", "secret prompt",
            "--model", "mock-1b", "--roster", str(roster),
            "--admin-key", f"alice={key}", "--coordinator", url)

    assert rc == 1, out
    assert "roster does not list" in err
    assert "reached" not in sealed, "the CLI sealed the prompt and sent it anyway"


async def test_chat_will_not_run_without_a_roster(tmp_path):
    """Required, not optional-with-a-warning: without it the coordinator would
    be choosing who can read the prompt, and the caller could not tell."""
    alice, bob, ident, roster, key = _federation(tmp_path, peer_endpoint="http://127.0.0.1:1")
    rc, _, err = await _cli("--identity", str(ident), "chat", "hi",
                            "--model", "mock-1b", "--coordinator", "http://127.0.0.1:1")
    assert rc != 0
    assert "--roster" in err


async def test_chat_refuses_an_admin_key_that_does_not_verify_the_roster(tmp_path):
    """Pinning only means something if a wrong pin is refused."""
    alice, bob, ident, roster, key = _federation(tmp_path, peer_endpoint="http://127.0.0.1:1")
    stranger = b64(Identity.generate("mallory").sign_pub)
    rc, _, err = await _cli("--identity", str(ident), "chat", "hi", "--model", "mock-1b",
                            "--roster", str(roster), "--admin-key", f"alice={stranger}",
                            "--coordinator", "http://127.0.0.1:1")
    assert rc == 1
    assert "no signature from a trusted admin key" in err


async def test_chat_requires_at_least_one_admin_key(tmp_path):
    alice, bob, ident, roster, key = _federation(tmp_path, peer_endpoint="http://127.0.0.1:1")
    rc, _, err = await _cli("--identity", str(ident), "chat", "hi", "--model", "mock-1b",
                            "--roster", str(roster), "--coordinator", "http://127.0.0.1:1")
    assert rc == 1
    assert "at least one --admin-key" in err


# --- the daemons: refusals that had never executed under test --------------

def test_a_peer_refuses_to_start_when_its_engine_serves_another_model(tmp_path, capsys):
    """The check that stops a peer writing false provenance.

    The coordinator routes on the roster, so a peer whose engine serves something
    else answers for a model it does not run and every provenance stamp it writes
    is a lie. Local, certain, and a typo away at any time -- and until now, never
    executed by a test.
    """
    from commonweal.peer.__main__ import main

    alice, bob, _, roster, key = _federation(tmp_path, peer_endpoint="http://127.0.0.1:1")
    bob_path = tmp_path / "bob-identity.json"
    Identity(
        member_id="bob", sign_seed=bob.sign_seed, sign_pub=bob.sign_pub,
        enc_priv=bob.enc_priv, enc_pub=bob.enc_pub,
    ).save(bob_path)

    rc = main([
        "--roster", str(roster), "--admin-key", f"alice={key}",
        "--identity", str(bob_path), "--peer-id", "bob-ws",
        "--engine", json.dumps({"kind": "mock", "model": "something-else"}),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "roster advertises model 'mock-1b'" in err
    assert "something-else" in err


def test_a_peer_refuses_to_start_under_an_identity_that_does_not_own_it(tmp_path, capsys):
    """A member may run their own peers, not somebody else's."""
    from commonweal.peer.__main__ import main

    alice, bob, alice_path, roster, key = _federation(
        tmp_path, peer_endpoint="http://127.0.0.1:1"
    )
    rc = main([
        "--roster", str(roster), "--admin-key", f"alice={key}",
        "--identity", str(alice_path), "--peer-id", "bob-ws",
        "--engine", json.dumps({"kind": "mock", "model": "mock-1b"}),
    ])
    assert rc == 1
    assert "is owned by 'bob'" in capsys.readouterr().err


def test_the_coordinator_refuses_to_start_without_a_pinned_admin_key(tmp_path, capsys):
    """Admin keys come from local config, never from the document. A coordinator
    that started without one would be verifying the roster against nothing."""
    from commonweal.coordinator.__main__ import main

    alice, bob, _, roster, key = _federation(tmp_path, peer_endpoint="http://127.0.0.1:1")
    rc = main(["--roster", str(roster), "--ledger", str(tmp_path / "l.db"),
               "--concurrency-log", str(tmp_path / "c.db")])
    assert rc == 1
    assert "at least one --admin-key is required" in capsys.readouterr().err


def test_the_coordinator_refuses_a_roster_it_cannot_verify(tmp_path, capsys):
    from commonweal.coordinator.__main__ import main

    alice, bob, _, roster, key = _federation(tmp_path, peer_endpoint="http://127.0.0.1:1")
    stranger = b64(Identity.generate("mallory").sign_pub)
    rc = main(["--roster", str(roster), "--admin-key", f"alice={stranger}",
               "--ledger", str(tmp_path / "l.db"),
               "--concurrency-log", str(tmp_path / "c.db")])
    assert rc == 1
    assert "cannot load roster" in capsys.readouterr().err
