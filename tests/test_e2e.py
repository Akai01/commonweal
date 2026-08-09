"""End-to-end: client -> coordinator -> peer -> back, over real HTTP.

The assertions that matter most are not "it works" but the two structural
claims the whole design rests on:

  * the coordinator relays content it provably cannot read, and
  * a heterogeneous federation stamps provenance onto every answer.
"""

from __future__ import annotations

import secrets
import time

import httpx
import pytest

from commonweal.client import CommonwealClient, Identity as ClientIdentity
from commonweal.coordinator import Coordinator, create_app as create_coordinator
from commonweal.coordinator.auth import sign_request
from commonweal.engines import GenerationParams, MockEngine
from commonweal.ledger import Ledger
from commonweal.peer import Peer, PeerConfig, create_app as create_peer
from commonweal.roster import Roster

from .conftest import Identity, build_roster
from .harness import free_port, serve


async def _expected_mock_output(prompt: str) -> str:
    """Text only -- the engine also yields a trailing `Usage`."""
    from commonweal.engines import Usage

    engine = MockEngine()
    msgs = [{"role": "user", "content": prompt}]
    return "".join(
        [c async for c in engine.stream(msgs, GenerationParams()) if not isinstance(c, Usage)]
    )


class Federation:
    """A running two-node federation: one coordinator, one peer."""

    def __init__(self, coordinator_url, peer_url, coordinator, alice, bob):
        self.coordinator_url = coordinator_url
        self.peer_url = peer_url
        self.coordinator = coordinator
        self.alice = alice
        self.bob = bob

    def client(self) -> CommonwealClient:
        ident = ClientIdentity(
            member_id="alice",
            sign_seed=bytes(self.alice.signing_key),
            sign_pub=bytes(self.alice.signing_key.verify_key),
            enc_priv=self.alice.enc_priv,
            enc_pub=b"",
        )
        return CommonwealClient(self.coordinator_url, ident, timeout=30.0)

    async def heartbeat(self, resident_gb: float = 62.0) -> None:
        doc = sign_request(
            "bob",
            {"peer_id": "bob-ws", "resident_gb": resident_gb, "healthy": True},
            self.bob.signing_key,
            nonce=secrets.token_urlsafe(12),
            ts=time.time(),
        )
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(f"{self.coordinator_url}/v1/peers/heartbeat", json=doc)
        assert resp.status_code == 200, resp.text


@pytest.fixture
async def federation():
    alice, bob = Identity("alice"), Identity("bob")
    peer_port, coord_port = free_port(), free_port()

    peer_entry = {
        "id": "bob-ws",
        "owner": "bob",
        "enc_pub": bob.enc_pub,
        "endpoint": f"http://127.0.0.1:{peer_port}",
        "model": "mock-1b",
        "engine": "mock",
        "engine_version": "0",
        "hw_class": "test-x86",
        "capacity_gb": 128.0,
        "max_concurrent": 2,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[peer_entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})

    peer = Peer(
        PeerConfig(peer_id="bob-ws", hw_class="test-x86"),
        roster,
        MockEngine(),
        bob.enc_priv,
    )
    coordinator = Coordinator(roster, ledger=Ledger())

    async with serve(create_peer(peer), peer_port) as peer_url:
        async with serve(create_coordinator(coordinator), coord_port) as coord_url:
            fed = Federation(coord_url, peer_url, coordinator, alice, bob)
            await fed.heartbeat()
            yield fed


# --- the happy path -----------------------------------------------------

async def test_round_trip(federation):
    result = await federation.client().complete(
        [{"role": "user", "content": "hello federation"}], model="mock-1b"
    )
    assert result.text == await _expected_mock_output("hello federation")
    assert result.peer_id == "bob-ws"


async def test_streaming_yields_incrementally(federation):
    chunks = [
        c
        async for c in federation.client().stream(
            [{"role": "user", "content": "stream me"}], model="mock-1b"
        )
    ]
    assert len(chunks) > 1
    assert "".join(chunks) == await _expected_mock_output("stream me")


async def test_capped_answer_is_labelled_as_capped(federation):
    """A stream can be complete and its answer still be cut short.

    `TruncatedStream` covers a lost connection. This covers a spent token
    budget, which reasoning models make the common outcome -- and an answer
    that stops mid-sentence is indistinguishable from a finished one unless the
    receipt says which it was.
    """
    result = await federation.client().complete(
        [{"role": "user", "content": "cap me"}], model="mock-1b", max_tokens=4
    )
    assert result.finish_reason == "length"
    assert result.truncated is True

    full = await federation.client().complete(
        [{"role": "user", "content": "cap me"}], model="mock-1b", max_tokens=512
    )
    assert full.finish_reason == "stop"
    assert full.truncated is False


async def test_streaming_callers_can_still_see_the_receipt(federation):
    """Incremental output must not cost the caller its provenance."""
    tags = {}
    async for tag, value in federation.client().events(
        [{"role": "user", "content": "cap me"}], model="mock-1b", max_tokens=4
    ):
        tags.setdefault(tag, []).append(value)
    assert tags["text"]
    assert tags["receipt"][-1].finish_reason == "length"


async def test_provenance_is_stamped(federation):
    """A heterogeneous federation cannot promise byte-identical output, so
    every answer must say which machine produced it."""
    result = await federation.client().complete(
        [{"role": "user", "content": "who served this"}], model="mock-1b"
    )
    assert result.hw_class == "test-x86"
    assert result.engine == "mock"
    assert "bob-ws" in result.served_by()


# --- the structural claim ----------------------------------------------

async def test_coordinator_cannot_decrypt(federation):
    """The load-bearing property: the coordinator holds no key that opens a
    request. If this ever fails, the coordinator has moved inside the trust
    boundary and the architecture's central claim is void."""
    coordinator = federation.coordinator
    for attr in vars(coordinator).values():
        assert not isinstance(attr, (bytes, bytearray)), "coordinator holds raw key material"
    assert not hasattr(coordinator, "enc_priv")
    assert not hasattr(coordinator, "_priv")

    # And the roster it serves carries only public halves.
    doc = coordinator.roster.to_dict()
    assert "enc_priv" not in repr(doc)
    assert "sign_seed" not in repr(doc)


async def test_prompt_never_appears_in_coordinator_traffic(federation):
    """Relay a request whose prompt is a unique marker, then assert the marker
    never appears in what the coordinator forwards."""
    marker = "SECRET-MARKER-" + secrets.token_hex(8)
    seen: list[bytes] = []

    original = httpx.AsyncClient.stream

    def spy(self, method, url, **kw):
        if "json" in kw:
            seen.append(repr(kw["json"]).encode())
        return original(self, method, url, **kw)

    httpx.AsyncClient.stream = spy
    try:
        await federation.client().complete(
            [{"role": "user", "content": marker}], model="mock-1b"
        )
    finally:
        httpx.AsyncClient.stream = original

    assert seen, "expected to observe relayed payloads"
    for payload in seen:
        assert marker.encode() not in payload


# --- accounting ---------------------------------------------------------

async def test_consumption_is_recorded(federation):
    await federation.client().complete(
        [{"role": "user", "content": "bill me"}], model="mock-1b"
    )
    totals = federation.coordinator.ledger.totals()
    assert totals["requests"] == 1
    assert totals["tokens"] > 0


async def test_contribution_credited_on_heartbeat(federation):
    await federation.heartbeat()
    await federation.heartbeat()
    assert federation.coordinator.ledger.balance("bob").gb_hours >= 0.0
    snapshot = federation.coordinator.registry.snapshot()
    assert snapshot[0]["live"] is True
    assert snapshot[0]["resident_gb"] == 62.0


async def test_slot_released_after_request(federation):
    client = federation.client()
    for _ in range(3):
        await client.complete([{"role": "user", "content": "hi"}], model="mock-1b")
    assert federation.coordinator.registry.state("bob-ws").in_flight == 0
    assert federation.coordinator.scheduler.active_leases == 0


# --- refusals -----------------------------------------------------------

async def test_unknown_model_refused(federation):
    with pytest.raises(Exception, match="no_capacity|no live peer"):
        await federation.client().complete(
            [{"role": "user", "content": "hi"}], model="does-not-exist"
        )


async def test_non_member_refused(federation):
    """A well-formed request from a real keypair that is not on the roster."""
    stranger = Identity("mallory")
    ident = ClientIdentity(
        member_id="mallory",
        sign_seed=bytes(stranger.signing_key),
        sign_pub=bytes(stranger.signing_key.verify_key),
        enc_priv=stranger.enc_priv,
        enc_pub=b"",
    )
    client = CommonwealClient(federation.coordinator_url, ident, timeout=10.0)
    with pytest.raises(Exception, match="unauthorized|unknown member"):
        await client.complete([{"role": "user", "content": "let me in"}], model="mock-1b")


async def test_infer_without_lease_refused(federation):
    """A sealed, correctly signed envelope with a request_id that was never
    leased must be refused -- the lease is what reserves capacity."""
    from commonweal.crypto import seal_request, sign_envelope
    from commonweal.proto import unb64

    envelope, _ = seal_request(
        b'{"messages":[{"role":"user","content":"hi"}]}',
        unb64(federation.bob.enc_pub),
        request_id="never-leased",
        sender="alice",
    )
    envelope = sign_envelope(envelope, federation.alice.signing_key)
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.post(f"{federation.coordinator_url}/v1/infer", json=envelope.to_dict())
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "no_lease"


async def test_replayed_lease_request_refused(federation):
    """Same nonce twice must not both succeed."""
    doc = sign_request(
        "alice", {"model": "mock-1b"}, federation.alice.signing_key,
        nonce="fixed-nonce", ts=time.time(),
    )
    async with httpx.AsyncClient(timeout=10) as c:
        first = await c.post(f"{federation.coordinator_url}/v1/lease", json=doc)
        second = await c.post(f"{federation.coordinator_url}/v1/lease", json=doc)
    assert first.status_code == 200
    assert second.status_code == 401
    assert "replay" in second.json()["error"]["message"]


async def test_stale_request_refused(federation):
    doc = sign_request(
        "alice", {"model": "mock-1b"}, federation.alice.signing_key,
        nonce=secrets.token_urlsafe(12), ts=time.time() - 9999,
    )
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.post(f"{federation.coordinator_url}/v1/lease", json=doc)
    assert resp.status_code == 401
    assert "stale" in resp.json()["error"]["message"]


async def test_health_and_stats(federation):
    doc = sign_request(
        "alice", {}, federation.alice.signing_key,
        nonce=secrets.token_urlsafe(12), ts=time.time(),
    )
    async with httpx.AsyncClient(timeout=10) as c:
        health = await c.get(f"{federation.coordinator_url}/v1/health")
        stats = await c.post(f"{federation.coordinator_url}/v1/stats", json=doc)
    assert health.json()["federation_id"] == "test-lab"
    body = stats.json()
    assert body["peers"][0]["peer_id"] == "bob-ws"
    assert "alice" in body["fair_share"]


async def test_metadata_reads_require_a_member_signature(federation):
    """Who is in a federation, where their machines are, and when they are
    active is the members' business. The coordinator is public and always-on,
    so an unsigned read of roster, stats or concurrency must be refused."""
    async with httpx.AsyncClient(timeout=10) as c:
        for endpoint in ("/v1/roster", "/v1/stats", "/v1/concurrency"):
            bare = await c.post(f"{federation.coordinator_url}{endpoint}", json={})
            assert bare.status_code == 401, endpoint
            old_get = await c.get(f"{federation.coordinator_url}{endpoint}")
            assert old_get.status_code == 405, endpoint


async def test_member_can_fetch_the_roster(federation):
    """The roster endpoint stays a convenience for members -- they verify the
    document against pinned admin keys themselves, so serving it grants the
    coordinator no authority."""
    doc = sign_request(
        "alice", {}, federation.alice.signing_key,
        nonce=secrets.token_urlsafe(12), ts=time.time(),
    )
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.post(f"{federation.coordinator_url}/v1/roster", json=doc)
    assert resp.status_code == 200
    assert resp.json()["federation_id"] == "test-lab"


# --- data-plane replay ---------------------------------------------------

def _sealed_envelope(federation, request_id: str, ts: float | None = None):
    from commonweal.crypto import seal_request, sign_envelope
    from commonweal.proto import unb64

    envelope, _ = seal_request(
        b'{"messages":[{"role":"user","content":"hi"}]}',
        unb64(federation.bob.enc_pub),
        request_id=request_id,
        sender="alice",
        **({} if ts is None else {"ts": ts}),
    )
    return sign_envelope(envelope, federation.alice.signing_key)


async def test_replayed_envelope_to_peer_refused(federation):
    """The peer is what a replay makes do real work, and the coordinator --
    which necessarily holds every envelope -- is untrusted. So the peer keeps
    its own seen-set: the same envelope must not be spendable twice, no matter
    who re-posts it."""
    envelope = _sealed_envelope(federation, "replay-me")
    async with httpx.AsyncClient(timeout=10) as c:
        first = await c.post(f"{federation.peer_url}/infer", json=envelope.to_dict())
        second = await c.post(f"{federation.peer_url}/infer", json=envelope.to_dict())
    assert first.status_code == 200
    assert second.status_code == 401
    assert "replayed" in second.json()["error"]["message"]


async def test_stale_envelope_refused_by_peer(federation):
    """An envelope's signature never expires; its signed timestamp is what
    bounds how long a capture stays spendable -- including across a peer
    restart, which empties the seen-set."""
    envelope = _sealed_envelope(federation, "stale-one", ts=time.time() - 9999)
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.post(f"{federation.peer_url}/infer", json=envelope.to_dict())
    assert resp.status_code == 401
    assert "stale" in resp.json()["error"]["message"]


async def test_stale_envelope_refused_by_coordinator(federation):
    envelope = _sealed_envelope(federation, "stale-two", ts=time.time() - 9999)
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.post(f"{federation.coordinator_url}/v1/infer", json=envelope.to_dict())
    assert resp.status_code == 401
    assert "stale" in resp.json()["error"]["message"]


async def test_lease_redeems_exactly_once(federation):
    """A duplicate envelope arriving while the first is still streaming must
    not make the pool relay the same work twice."""
    from commonweal.coordinator.scheduler import LeaseExpired

    scheduler = federation.coordinator.scheduler
    lease = await scheduler.acquire("alice", "mock-1b")
    assert scheduler.redeem(lease.request_id, "alice") is lease
    with pytest.raises(LeaseExpired, match="already redeemed"):
        scheduler.redeem(lease.request_id, "alice")
    scheduler.release(lease.request_id)
