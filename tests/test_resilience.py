"""Failure paths that leak capacity if they are wrong.

A leaked peer slot is the worst class of bug here: nothing errors, the pool
just quietly shrinks until it stops serving. These tests exist because that
failure is invisible until it is severe.
"""

from __future__ import annotations

import asyncio
import secrets
import time

import httpx
import pytest

from commonweal.client import CommonwealClient, Identity as ClientIdentity
from commonweal.coordinator import Coordinator, create_app as create_coordinator
from commonweal.coordinator.auth import sign_request
from commonweal.engines import MockEngine
from commonweal.ledger import Ledger
from commonweal.peer import Peer, PeerConfig, create_app as create_peer
from commonweal.roster import Roster

from .conftest import Identity, build_roster
from .harness import free_port, serve


async def _build(*, engine=None, max_concurrent=2, peer_up=True):
    alice, bob = Identity("alice"), Identity("bob")
    peer_port, coord_port = free_port(), free_port()
    entry = {
        "id": "bob-ws", "owner": "bob", "enc_pub": bob.enc_pub,
        "endpoint": f"http://127.0.0.1:{peer_port}", "model": "mock-1b",
        "engine": "mock", "engine_version": "0", "hw_class": "test",
        "capacity_gb": 8.0, "max_concurrent": max_concurrent,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})
    coordinator = Coordinator(roster, ledger=Ledger())
    peer = Peer(
        PeerConfig(peer_id="bob-ws", hw_class="test"), roster,
        engine or MockEngine(), bob.enc_priv,
    )
    return alice, bob, peer, peer_port, coordinator, coord_port


def _client(coord_url, ident: Identity, member_id="alice") -> CommonwealClient:
    return CommonwealClient(
        coord_url,
        ClientIdentity(
            member_id=member_id,
            sign_seed=bytes(ident.signing_key),
            sign_pub=bytes(ident.signing_key.verify_key),
            enc_priv=ident.enc_priv, enc_pub=b"",
        ),
        timeout=30.0,
    )


async def _beat(coord_url, bob):
    doc = sign_request(
        "bob", {"peer_id": "bob-ws", "resident_gb": 8.0, "healthy": True},
        bob.signing_key, nonce=secrets.token_urlsafe(12), ts=time.time(),
    )
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(f"{coord_url}/v1/peers/heartbeat", json=doc)


async def test_client_disconnect_releases_slot():
    """Abandoning a stream mid-flight must return the peer slot.

    If this regresses, every abandoned request permanently consumes capacity
    and the federation degrades silently."""
    alice, bob, peer, pport, coordinator, cport = await _build(
        engine=MockEngine(delay=0.15, tokens=40)
    )
    async with serve(create_peer(peer), pport):
        async with serve(create_coordinator(coordinator), cport) as coord_url:
            await _beat(coord_url, bob)
            client = _client(coord_url, alice)

            # Take the first chunk, then walk away.
            agen = client.stream([{"role": "user", "content": "long"}], model="mock-1b")
            first = await agen.__anext__()
            assert first
            await agen.aclose()

            for _ in range(100):
                if coordinator.registry.state("bob-ws").in_flight == 0:
                    break
                await asyncio.sleep(0.05)

            assert coordinator.registry.state("bob-ws").in_flight == 0, "peer slot leaked"
            assert coordinator.scheduler.active_leases == 0, "lease leaked"


async def test_capacity_recovers_after_repeated_disconnects():
    """Capacity must survive many abandoned requests, not just one."""
    alice, bob, peer, pport, coordinator, cport = await _build(
        engine=MockEngine(delay=0.05, tokens=40), max_concurrent=1
    )
    async with serve(create_peer(peer), pport):
        async with serve(create_coordinator(coordinator), cport) as coord_url:
            await _beat(coord_url, bob)
            client = _client(coord_url, alice)

            for _ in range(3):
                agen = client.stream([{"role": "user", "content": "x"}], model="mock-1b")
                await agen.__anext__()
                await agen.aclose()
                for _ in range(60):
                    if coordinator.registry.state("bob-ws").in_flight == 0:
                        break
                    await asyncio.sleep(0.05)

            # The pool must still be usable afterwards.
            result = await client.complete(
                [{"role": "user", "content": "still working?"}], model="mock-1b"
            )
            assert result.text


async def test_dead_peer_marked_unhealthy_and_slot_released():
    """When a peer dies, the relay fails -- the slot must still come back and
    the peer must stop being offered."""
    alice, bob, peer, pport, coordinator, cport = await _build()
    async with serve(create_coordinator(coordinator), cport) as coord_url:
        await _beat(coord_url, bob)  # claims live; peer server was never started
        client = _client(coord_url, alice)

        with pytest.raises(Exception):
            await client.complete([{"role": "user", "content": "hi"}], model="mock-1b")

        assert coordinator.registry.state("bob-ws").in_flight == 0
        coordinator.registry.mark_failure("bob-ws")
        assert coordinator.registry.is_live("bob-ws") is False


async def test_queue_full_returns_429():
    """With one slot and a bounded queue, excess demand must be refused with a
    retryable status rather than piling up unbounded."""
    alice, bob, peer, pport, coordinator, cport = await _build(
        engine=MockEngine(delay=0.2, tokens=20), max_concurrent=1
    )
    coordinator.scheduler.max_queue = 1
    coordinator.scheduler.queue_timeout = 0.5

    async with serve(create_peer(peer), pport):
        async with serve(create_coordinator(coordinator), cport) as coord_url:
            await _beat(coord_url, bob)

            async def lease_once():
                doc = sign_request(
                    "alice", {"model": "mock-1b"}, alice.signing_key,
                    nonce=secrets.token_urlsafe(12), ts=time.time(),
                )
                async with httpx.AsyncClient(timeout=15) as c:
                    resp = await c.post(f"{coord_url}/v1/lease", json=doc)
                return resp.status_code

            codes = await asyncio.gather(*(lease_once() for _ in range(4)))
            assert 200 in codes
            assert 429 in codes, f"expected a refusal, got {codes}"


async def test_engine_that_cannot_serve_stops_receiving_traffic():
    """The payoff for readiness: it reaches the routing decision.

    A peer whose engine is listening but cannot answer used to report healthy
    (`GET /v1/models` succeeds), keep its place in the pool, and fail every
    request routed to it. Now the heartbeat carries what an actual inference
    probe found, so the coordinator refuses up front instead of handing out a
    lease that cannot be honoured.
    """
    from commonweal.engines import EngineError

    class WedgedEngine:
        name, version, model = "wedged", "0", "mock-1b"

        async def health(self):
            return True          # the old check, still passing

        async def stream(self, messages, params):
            raise EngineError("shard 2 is gone")
            yield ""             # pragma: no cover

    alice, bob, peer, pport, coordinator, cport = await _build(engine=WedgedEngine())
    async with serve(create_peer(peer), pport):
        async with serve(create_coordinator(coordinator), cport) as coord_url:
            assert await peer.engine.health() is True
            assert (await peer.ready()).ok is False

            # Exactly what heartbeat_loop sends, without waiting on its timer.
            doc = sign_request(
                "bob",
                {"peer_id": "bob-ws", "resident_gb": 8.0, "healthy": await peer.is_ready()},
                bob.signing_key, nonce=secrets.token_urlsafe(12), ts=time.time(),
            )
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.post(f"{coord_url}/v1/peers/heartbeat", json=doc)
            assert resp.status_code == 200

            assert coordinator.registry.is_live("bob-ws") is False
            with pytest.raises(Exception, match="no_capacity|no live peer"):
                await _client(coord_url, alice).complete(
                    [{"role": "user", "content": "hi"}], model="mock-1b"
                )


async def test_usage_without_counts_still_bills_via_the_estimator():
    """An engine may say *why* it stopped without saying how much it produced.

    Reading that as "zero tokens" would let a peer serve real text and record
    nothing against the member who spent it -- a silent hole in the ledger, in
    the peer's own favour. Zero means "not reported", so the estimator runs.
    """
    from commonweal.engines import Usage

    class CountlessEngine:
        name, version, model = "countless", "0", "mock-1b"

        async def health(self):
            return True

        async def stream(self, messages, params):
            yield "twelve chars"
            yield Usage(finish_reason="length")   # no counts, only a reason

    alice, bob, peer, pport, coordinator, cport = await _build(engine=CountlessEngine())
    async with serve(create_peer(peer), pport):
        async with serve(create_coordinator(coordinator), cport) as coord_url:
            await _beat(coord_url, bob)
            result = await _client(coord_url, alice).complete(
                [{"role": "user", "content": "hi"}], model="mock-1b"
            )
    assert result.text == "twelve chars"
    assert result.finish_reason == "length"
    assert result.completion_tokens == 3      # len("twelve chars") // 4
    assert result.prompt_tokens > 0
    assert coordinator.ledger.totals()["tokens"] > 0


async def test_engine_failure_surfaces_as_client_error():
    """An engine that raises mid-stream must reach the client as an error, not
    as a silently short answer."""
    from commonweal.engines import EngineError

    class BrokenEngine:
        name, version, model = "broken", "0", "mock-1b"

        async def health(self):
            return True

        async def stream(self, messages, params):
            yield "partial"
            raise EngineError("engine exploded")

    alice, bob, peer, pport, coordinator, cport = await _build(engine=BrokenEngine())
    async with serve(create_peer(peer), pport):
        async with serve(create_coordinator(coordinator), cport) as coord_url:
            await _beat(coord_url, bob)
            client = _client(coord_url, alice)
            with pytest.raises(Exception, match="exploded"):
                await client.complete([{"role": "user", "content": "hi"}], model="mock-1b")
            assert coordinator.registry.state("bob-ws").in_flight == 0
