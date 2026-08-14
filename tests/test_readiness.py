"""Readiness, as distinct from liveness.

These exist because of a real failure mode, not a hypothetical one. An engine
can report `{"status":"ok"}` on `GET /v1/models` while being unable to answer --
the socket is open, so the old check passed, and the coordinator would have kept
routing there. It is worst under sharding, where a shard group is all-or-nothing,
so readiness has to exercise the model rather than the port.
"""

from __future__ import annotations

import httpx

from commonweal.engines import EngineError, GenerationParams, MockEngine, NoAnswerError, Usage
from commonweal.peer import Peer, PeerConfig, create_app
from commonweal.roster import Roster

from .conftest import Identity, build_roster
from .harness import free_port, serve


def _peer(engine, **config) -> Peer:
    alice, bob = Identity("alice"), Identity("bob")
    entry = {
        "id": "bob-ws", "owner": "bob", "enc_pub": bob.enc_pub,
        "endpoint": "http://127.0.0.1:9101", "model": "mock-1b",
        "engine": "mock", "engine_version": "0", "hw_class": "test",
        "capacity_gb": 8.0, "max_concurrent": 4,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})
    clock = config.pop("clock", None)
    return Peer(
        PeerConfig(peer_id="bob-ws", hw_class="test", **config),
        roster, engine, bob.enc_priv,
        **({"clock": clock} if clock else {}),
    )


class WedgedEngine:
    """Listening, but unable to serve -- the shard-loss shape.

    `health()` passes because the port is open. Inference fails. This is exactly
    what a llama.cpp RPC head looks like between losing a worker and dying.
    """

    name, version, model = "wedged", "0", "mock-1b"

    def __init__(self):
        self.probes = 0

    async def health(self):
        return True

    async def stream(self, messages, params):
        self.probes += 1
        raise EngineError("shard 2 is gone")
        yield ""      # pragma: no cover - makes this an async generator


class ThinkingEngine:
    """A reasoning model given a one-token budget: all thought, no answer."""

    name, version, model = "thinking", "0", "mock-1b"

    def __init__(self):
        self.probes = 0

    async def health(self):
        return True

    async def stream(self, messages, params):
        self.probes += 1
        raise NoAnswerError("engine spent its budget on reasoning")
        yield ""      # pragma: no cover


class CountingMock(MockEngine):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.probes = 0

    async def stream(self, messages, params):
        self.probes += 1
        async for item in super().stream(messages, params):
            yield item


# --- the failure that motivated all of this -----------------------------

async def test_engine_that_is_listening_but_cannot_serve_is_not_ready():
    engine = WedgedEngine()
    peer = _peer(engine)

    assert await engine.health() is True, "precondition: the old check passes"

    readiness = await peer.ready()
    assert readiness.ok is False
    assert "shard 2 is gone" in readiness.reason
    assert engine.probes == 1


async def test_health_endpoint_reports_degraded_and_says_why():
    port = free_port()
    async with serve(create_app(_peer(WedgedEngine())), port) as url:
        async with httpx.AsyncClient(timeout=10) as c:
            body = (await c.get(f"{url}/health")).json()
    assert body["status"] == "degraded"
    assert "shard 2 is gone" in body["detail"]


# --- what an unauthenticated caller gets from a peer --------------------
#
# `/health` takes no signature, so it is reachable by anyone who can reach the
# peer. That is deliberate -- an uptime monitor cannot sign -- but it means the
# response is a published surface rather than an internal one, and it needs the
# same treatment the coordinator gives `detail` before /v1/stats echoes it.


class HostileEngine:
    """A backend whose error body is not text you would print unexamined.

    Not hypothetical: `OpenAICompatEngine` puts up to 400 characters of the
    backend's raw response into the `EngineError` it raises, and an engine sitting
    behind a gateway can put anything at all in there.
    """

    name, version, model = "hostile", "0", "mock-1b"

    async def health(self):
        return True

    async def stream(self, messages, params):
        raise EngineError(
            "engine returned 401: \x1b[31mred\x1b[0m\r\n\ttabbed\x00null " + "x" * 500
        )
        yield ""      # pragma: no cover


async def test_peer_health_sanitises_engine_text_before_returning_it():
    from commonweal.sanitise import MAX_DETAIL_CHARS

    port = free_port()
    async with serve(create_app(_peer(HostileEngine())), port) as url:
        async with httpx.AsyncClient(timeout=10) as c:
            detail = (await c.get(f"{url}/health")).json()["detail"]

    assert "\x1b" not in detail, "an ANSI escape would reach the operator's terminal"
    assert "\x00" not in detail
    assert "\r" not in detail and "\n" not in detail and "\t" not in detail
    assert len(detail) <= MAX_DETAIL_CHARS
    assert "engine returned 401" in detail, "still has to be a usable diagnostic"


async def test_peer_health_discloses_configuration_but_never_membership():
    """Pins the unauthenticated disclosure so it stays a decision, not a drift.

    Model, engine, engine version and hardware class are exposed on purpose and
    are documented in docs/PROTOCOL.md §7 and docs/THREAT-MODEL.md. Anything
    about members, the roster, or the federation itself must not be.
    """
    port = free_port()
    async with serve(create_app(_peer(MockEngine())), port) as url:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(f"{url}/health")     # no signature, no credential

    assert resp.status_code == 200
    body = resp.json()
    # The exact set, not a subset: a field added here becomes public the day it
    # ships, so widening the disclosure should have to be a deliberate edit.
    assert set(body) == {
        "status", "detail", "peer_id", "model", "engine", "engine_version", "hw_class",
    }
    # `peer_id` is "bob-ws", so the owner's name is inherently part of an id the
    # roster already publishes. Nothing *else* about the federation may leak:
    # not its name, and not a member who does not run this peer.
    blob = str(body).lower()
    for leaked in ("alice", "test-lab"):
        assert leaked not in blob, f"{leaked!r} must not be on an open endpoint"


async def test_no_generated_api_docs_are_served():
    """FastAPI mounts /docs, /redoc and /openapi.json unauthenticated by default.

    Both servers turn them off. The wire format is specified in
    docs/PROTOCOL.md, so a generated schema tells a reader nothing new, while an
    interactive request builder on a public always-on service is surface with no
    matching use. A framework default is exactly the kind of thing that comes
    back on a dependency bump, so it is pinned rather than assumed.
    """
    from commonweal.coordinator.app import Coordinator
    from commonweal.coordinator.app import create_app as coordinator_app

    alice, bob = Identity("alice"), Identity("bob")
    entry = {
        "id": "bob-ws", "owner": "bob", "enc_pub": bob.enc_pub,
        "endpoint": "http://127.0.0.1:9101", "model": "mock-1b",
        "engine": "mock", "engine_version": "0", "hw_class": "test",
        "capacity_gb": 8.0, "max_concurrent": 2,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})

    for app in (create_app(_peer(MockEngine())), coordinator_app(Coordinator(roster))):
        port = free_port()
        async with serve(app, port) as url:
            async with httpx.AsyncClient(timeout=10) as c:
                for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
                    resp = await c.get(f"{url}{path}")
                    assert resp.status_code == 404, f"{path} is served on {url}"


async def test_working_engine_is_ready():
    peer = _peer(MockEngine())
    readiness = await peer.ready()
    assert readiness.ok is True
    assert "produced output" in readiness.reason


# --- a thinking engine is not a broken engine ---------------------------

async def test_reasoning_only_response_still_counts_as_ready():
    """A one-token probe against a reasoning model produces thought and no
    answer. That is the engine working as configured; taking the peer out of the
    pool for it would evict healthy peers for doing the right thing."""
    peer = _peer(ThinkingEngine())
    readiness = await peer.ready()
    assert readiness.ok is True
    assert "reasoning only" in readiness.reason


def test_no_answer_error_is_an_engine_error():
    """So callers that only care whether a *request* worked keep working."""
    assert issubclass(NoAnswerError, EngineError)


# --- the probe must be cheap ------------------------------------------------

async def test_recent_request_counts_as_readiness_without_probing():
    """Serving is proof of readiness, so a busy peer never pays for a probe."""
    engine = CountingMock()
    peer = _peer(engine)
    peer.note_progress()

    for _ in range(5):
        assert (await peer.ready()).ok is True
    assert engine.probes == 0
    assert "served a request" in (await peer.ready()).reason


async def test_probe_result_is_cached_between_calls():
    """`/health` is unauthenticated; without a floor on probe frequency an
    onlooker could make this peer run inference as fast as they can poll."""
    engine = CountingMock()
    now = [1000.0]
    peer = _peer(engine, probe_interval=15.0, clock=lambda: now[0])

    for _ in range(4):
        assert (await peer.ready()).ok is True
    assert engine.probes == 1

    now[0] += 16.0
    assert (await peer.ready()).ok is True
    assert engine.probes == 2


async def test_concurrent_health_checks_cause_one_probe():
    """The interval alone only rate-limits *sequential* callers. `/health` is
    unauthenticated, so without single-flight an onlooker could fire N concurrent
    requests and make a member's machine run N inference probes -- which is
    exactly the amplification the interval was supposed to prevent. Measured at 25
    probes for 25 requests before this was fixed.
    """
    import asyncio

    class SlowCounter(MockEngine):
        def __init__(self):
            super().__init__()
            self.probes = 0

        async def stream(self, messages, params):
            self.probes += 1
            await asyncio.sleep(0.05)        # a real probe is not instant
            async for item in super().stream(messages, params):
                yield item

    engine = SlowCounter()
    peer = _peer(engine, probe_interval=15.0)
    verdicts = await asyncio.gather(*[peer.ready() for _ in range(25)])

    assert all(v.ok for v in verdicts)
    assert engine.probes == 1


async def test_readiness_window_expiry_reprobes():
    engine = CountingMock()
    now = [1000.0]
    peer = _peer(engine, readiness_window=60.0, probe_interval=0.0, clock=lambda: now[0])

    peer.note_progress()
    assert engine.probes == 0

    now[0] += 61.0                       # the last success is now too old to trust
    assert (await peer.ready()).ok is True
    assert engine.probes == 1


async def test_inference_probe_can_be_turned_off():
    """Opting out is allowed, and gets the weaker guarantee it asks for."""
    engine = WedgedEngine()
    peer = _peer(engine, inference_probe=False)
    readiness = await peer.ready()
    assert readiness.ok is True, "liveness alone cannot see a wedged engine"
    assert "inference probe disabled" in readiness.reason
    assert engine.probes == 0


async def test_engine_raising_a_bare_exception_is_not_ready():
    """A probe must never take the peer's own process down with it."""

    class Exploding:
        name, version, model = "boom", "0", "mock-1b"

        async def health(self):
            return True

        async def stream(self, messages, params):
            raise RuntimeError("kernel panic")
            yield ""   # pragma: no cover

    readiness = await _peer(Exploding()).ready()
    assert readiness.ok is False
    assert "kernel panic" in readiness.reason


async def test_engine_yielding_nothing_is_not_ready():
    class Silent:
        name, version, model = "silent", "0", "mock-1b"

        async def health(self):
            return True

        async def stream(self, messages, params):
            return
            yield ""   # pragma: no cover

    readiness = await _peer(Silent()).ready()
    assert readiness.ok is False
    assert "nothing at all" in readiness.reason


async def test_probe_asks_for_a_single_token():
    """The probe should cost one decode step, not a full generation."""
    seen: list[GenerationParams] = []

    class Recorder:
        name, version, model = "recorder", "0", "mock-1b"

        async def health(self):
            return True

        async def stream(self, messages, params):
            seen.append(params)
            yield "x"
            yield Usage(prompt_tokens=1, completion_tokens=1)

    assert (await _peer(Recorder()).ready()).ok is True
    assert seen[0].max_tokens == 1
    assert seen[0].temperature == 0.0


# --- the reason has to reach the coordinator ----------------------------

async def test_heartbeat_carries_the_reason_not_just_a_verdict():
    """Otherwise diagnosing a shard group means curling every peer in it."""
    from commonweal.peer.heartbeat import heartbeat_loop

    sent: list[dict] = []

    async def fake_send(url, **kw):
        sent.append(kw)
        return True

    import commonweal.peer.heartbeat as hb

    original, hb.send_heartbeat = hb.send_heartbeat, fake_send
    try:
        peer = _peer(WedgedEngine())
        stop = __import__("asyncio").Event()
        task = __import__("asyncio").create_task(
            heartbeat_loop("http://127.0.0.1:1", member_id="bob", peer_id="bob-ws",
                           signing_key=None, resident_gb=1.0,
                           readiness=peer.ready, interval=0.05, stop=stop)
        )
        for _ in range(100):
            if sent:
                break
            await __import__("asyncio").sleep(0.02)
        stop.set()
        await task
    finally:
        hb.send_heartbeat = original

    assert sent, "expected at least one heartbeat"
    assert sent[0]["healthy"] is False
    assert "shard 2 is gone" in sent[0]["detail"]


async def test_a_plain_bool_readiness_still_works():
    """A caller with nothing to explain should not have to invent an object."""
    from commonweal.peer.heartbeat import heartbeat_loop

    sent: list[dict] = []
    import commonweal.peer.heartbeat as hb

    async def fake_send(url, **kw):
        sent.append(kw)
        return True

    async def always_ready() -> bool:
        return True

    original, hb.send_heartbeat = hb.send_heartbeat, fake_send
    try:
        stop = __import__("asyncio").Event()
        task = __import__("asyncio").create_task(
            heartbeat_loop("http://127.0.0.1:1", member_id="bob", peer_id="bob-ws",
                           signing_key=None, resident_gb=1.0,
                           readiness=always_ready, interval=0.05, stop=stop)
        )
        for _ in range(100):
            if sent:
                break
            await __import__("asyncio").sleep(0.02)
        stop.set()
        await task
    finally:
        hb.send_heartbeat = original

    assert sent[0]["healthy"] is True
    assert sent[0]["detail"] == ""


# --- and it must be safe to show ----------------------------------------
#
# The reason originates in an engine error message -- backend output nobody here
# wrote -- and /v1/stats echoes it to every member's terminal.

def _registry():
    from commonweal.coordinator.registry import Registry
    from commonweal.ledger import Ledger

    alice, bob = Identity("alice"), Identity("bob")
    entry = {
        "id": "bob-ws", "owner": "bob", "enc_pub": bob.enc_pub,
        "endpoint": "http://127.0.0.1:9101", "model": "mock-1b",
        "engine": "mock", "engine_version": "0", "hw_class": "test",
        "capacity_gb": 8.0, "max_concurrent": 2,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})
    return Registry(roster, Ledger())


def test_detail_reaches_the_stats_snapshot():
    reg = _registry()
    reg.heartbeat("bob-ws", resident_gb=8.0, healthy=False, detail="shard 2 is gone")
    row = next(r for r in reg.snapshot() if r["peer_id"] == "bob-ws")
    assert row["live"] is False
    assert row["detail"] == "shard 2 is gone"


def test_detail_is_length_bounded():
    from commonweal.sanitise import MAX_DETAIL_CHARS

    reg = _registry()
    reg.heartbeat("bob-ws", detail="x" * 5000)
    assert len(reg.state("bob-ws").detail) == MAX_DETAIL_CHARS


def test_detail_strips_control_characters_and_collapses_whitespace():
    reg = _registry()
    # The zero-width space is written as an escape on purpose: as a literal it is
    # invisible, so the test would read as though it never covered the case.
    reg.heartbeat("bob-ws", detail="broke\r\n\tat\x00 layer\u200b 7    now")
    assert reg.state("bob-ws").detail == "broke at layer 7 now"


def test_non_string_detail_is_ignored():
    reg = _registry()
    reg.heartbeat("bob-ws", detail={"nested": "object"})   # type: ignore[arg-type]
    assert reg.state("bob-ws").detail == ""


def test_relay_failures_explain_themselves_too():
    """A peer evicted by the reactive path should say so as clearly as one that
    reported itself unready."""
    reg = _registry()
    reg.heartbeat("bob-ws", resident_gb=8.0)
    reg.mark_failure("bob-ws")
    reg.mark_failure("bob-ws")
    assert reg.state("bob-ws").healthy is False
    assert "relay failures" in reg.state("bob-ws").detail


async def test_abandoned_probe_stream_is_closed():
    """The probe stops at the first item, so the generator must be closed rather
    than left for the garbage collector -- otherwise a real engine's HTTP
    connection leaks once per probe."""
    closed = []

    class Watcher:
        name, version, model = "watcher", "0", "mock-1b"

        async def health(self):
            return True

        async def stream(self, messages, params):
            try:
                yield "first"
                yield "second"      # pragma: no cover - probe stops before this
            finally:
                closed.append(True)

    assert (await _peer(Watcher()).ready()).ok is True
    assert closed == [True]
