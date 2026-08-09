"""Periodic liveness and residency reporting.

Heartbeats do double duty: they tell the coordinator this peer is up, and they
are how contribution is credited. A peer that stops beating stops earning its
owner fair-share standing -- which is the intended incentive, since a machine
that is not holding memory resident is not contributing anything.
"""

from __future__ import annotations

import asyncio
import secrets
import sys
import time

import httpx
from nacl.signing import SigningKey

from ..coordinator.auth import sign_request
from ..tlsconfig import DEFAULT_TLS, TLSConfig

DEFAULT_INTERVAL = 30.0


async def send_heartbeat(
    coordinator_url: str,
    *,
    member_id: str,
    peer_id: str,
    signing_key: SigningKey,
    resident_gb: float,
    healthy: bool = True,
    detail: str = "",
    timeout: float = 10.0,
    tls: TLSConfig = DEFAULT_TLS,
) -> bool:
    body = {"peer_id": peer_id, "resident_gb": resident_gb, "healthy": healthy}
    if detail:
        # Inside the signed body, so it cannot be edited in transit. Omitted when
        # empty to keep the signed bytes identical to an older peer's.
        body["detail"] = detail
    doc = sign_request(
        member_id,
        body,
        signing_key,
        nonce=secrets.token_urlsafe(12),
        ts=time.time(),
    )
    try:
        async with httpx.AsyncClient(timeout=timeout, **tls.httpx_kwargs()) as client:
            resp = await client.post(f"{coordinator_url.rstrip('/')}/v1/peers/heartbeat", json=doc)
        return resp.status_code < 300
    except httpx.HTTPError:
        return False


async def heartbeat_loop(
    coordinator_url: str,
    *,
    member_id: str,
    peer_id: str,
    signing_key: SigningKey,
    resident_gb: float,
    readiness=None,
    interval: float = DEFAULT_INTERVAL,
    stop: asyncio.Event | None = None,
    tls: TLSConfig = DEFAULT_TLS,
) -> None:
    """Beat until `stop` is set.

    `readiness` is an async callable returning this peer's `Readiness` -- normally
    `Peer.ready`, which actually exercises the model rather than checking that a
    port is open. What it reports gates routing: the coordinator will not offer a
    peer whose last beat said unhealthy, and the reason travels with it so an
    operator does not have to curl every peer in a group to find the broken one.

    A plain bool is accepted too, for a caller that has nothing to explain.

    A heartbeat that fails to send is logged by its return value and otherwise
    ignored: a transient coordinator outage should not take the peer down, and
    the coordinator's own timeout will mark us dead if it persists.
    """
    stop = stop or asyncio.Event()
    previous: bool | None = None
    while not stop.is_set():
        healthy, detail = True, ""
        if readiness is not None:
            try:
                verdict = await readiness()
                healthy = bool(getattr(verdict, "ok", verdict))
                detail = str(getattr(verdict, "reason", ""))
            except Exception as exc:
                healthy, detail = False, f"readiness check raised: {exc}"
        # A peer dropping out of the pool silently is the same class of failure
        # as a silently short answer, so say it once per transition.
        if previous is not None and healthy != previous:
            print(
                f"peer {peer_id!r} is now {'ready' if healthy else 'NOT ready'}"
                f"{'' if healthy else ' -- the coordinator will stop routing here'}"
                f"{f': {detail}' if detail else ''}",
                file=sys.stderr,
            )
        previous = healthy
        await send_heartbeat(
            coordinator_url,
            member_id=member_id,
            peer_id=peer_id,
            signing_key=signing_key,
            detail=detail,
            resident_gb=resident_gb,
            healthy=healthy,
            tls=tls,
        )
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except (TimeoutError, asyncio.TimeoutError):
            pass
