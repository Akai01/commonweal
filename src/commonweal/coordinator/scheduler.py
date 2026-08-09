"""Admission, queueing, and lease issuance.

Two ideas do most of the work here.

**Leases are two-round on purpose.** The client asks for a lease, learns which
peer it got and that peer's public key, and only then seals the request to that
one peer. The alternative -- a shared pool key -- would let every peer decrypt
every request. The extra round trip costs ~1 ms against multi-second inference;
least privilege is worth far more than that.

**The queue is priority-ordered by fair share, not FIFO.** That is the whole
incentive mechanism: contribute capacity, get served first when the pool is
contended. Members who have contributed more than they consumed jump ahead.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
import secrets
import time
from dataclasses import dataclass

from ..ledger import Ledger
from ..roster import Peer
from .registry import Registry

DEFAULT_LEASE_TTL = 300.0
DEFAULT_MAX_QUEUE = 32
DEFAULT_QUEUE_TIMEOUT = 120.0


class NoCapacity(Exception):
    """No live peer serves this model at all."""


class QueueFull(Exception):
    """Pool is saturated and the wait queue is at its bound."""


class LeaseExpired(Exception):
    """Lease is unknown, already used, or past its TTL."""


@dataclass(frozen=True)
class Lease:
    request_id: str
    member_id: str
    peer: Peer
    expires_at: float

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "peer_id": self.peer.id,
            "peer_enc_pub": self.peer.enc_pub,
            "peer_endpoint": self.peer.endpoint,
            "model": self.peer.model,
            "engine": self.peer.engine,
            "engine_version": self.peer.engine_version,
            "hw_class": self.peer.hw_class,
            "expires_at": self.expires_at,
        }


@dataclass(order=True)
class _Waiter:
    neg_score: float
    seq: int
    member_id: str = ""
    model: str = ""
    future: asyncio.Future = None  # type: ignore[assignment]


class Scheduler:
    def __init__(
        self,
        registry: Registry,
        ledger: Ledger,
        *,
        lease_ttl: float = DEFAULT_LEASE_TTL,
        max_queue: int = DEFAULT_MAX_QUEUE,
        queue_timeout: float = DEFAULT_QUEUE_TIMEOUT,
        clock=time.monotonic,
    ):
        self.registry = registry
        self.ledger = ledger
        self.lease_ttl = lease_ttl
        self.max_queue = max_queue
        self.queue_timeout = queue_timeout
        self._clock = clock
        self._waiters: list[_Waiter] = []
        self._seq = itertools.count()
        self._leases: dict[str, Lease] = {}
        self._redeemed: set[str] = set()

    # -- lease lifecycle -------------------------------------------------

    async def acquire(self, member_id: str, model: str) -> Lease:
        """Reserve a peer slot for `member_id`, waiting in priority order."""
        if not self.registry.live_peers(model):
            raise NoCapacity(f"no live peer serves model {model!r}")

        peer = self._pick(model)
        if peer is not None:
            return self._issue(member_id, peer)

        if len(self._waiters) >= self.max_queue:
            raise QueueFull("inference queue is full")

        loop = asyncio.get_running_loop()
        waiter = _Waiter(
            neg_score=-self.ledger.balance(member_id).score,
            seq=next(self._seq),
            member_id=member_id,
            model=model,
            future=loop.create_future(),
        )
        heapq.heappush(self._waiters, waiter)
        try:
            return await asyncio.wait_for(waiter.future, self.queue_timeout)
        except (TimeoutError, asyncio.TimeoutError):
            self._drop(waiter)
            raise QueueFull("timed out waiting for a free peer") from None
        except asyncio.CancelledError:
            self._drop(waiter)
            raise

    def release(self, request_id: str) -> None:
        """Return the slot and hand it to the highest-priority waiter."""
        lease = self._leases.pop(request_id, None)
        self._redeemed.discard(request_id)
        if lease is not None:
            self.registry.release_slot(lease.peer.id)
        self._dispatch()

    def redeem(self, request_id: str, member_id: str) -> Lease:
        """Look up a lease at /infer time -- at most once.

        Binds the lease to the member who was issued it, so a leaked
        request_id cannot be used by anyone else; and consumes it, so a
        duplicate envelope arriving while the first is still streaming cannot
        make the pool do the same work twice.
        """
        lease = self._leases.get(request_id)
        if lease is None:
            raise LeaseExpired(f"no active lease {request_id!r}")
        if lease.member_id != member_id:
            raise LeaseExpired("lease belongs to a different member")
        if self._clock() > lease.expires_at:
            self.release(request_id)
            raise LeaseExpired(f"lease {request_id!r} expired")
        if request_id in self._redeemed:
            raise LeaseExpired(f"lease {request_id!r} already redeemed")
        self._redeemed.add(request_id)
        return lease

    # -- internals -------------------------------------------------------

    def _pick(self, model: str) -> Peer | None:
        """Least-loaded live peer with a free slot, or None."""
        candidates = [p for p in self.registry.live_peers(model) if self.registry.has_capacity(p)]
        if not candidates:
            return None
        return min(candidates, key=lambda p: (self.registry.state(p.id).in_flight, p.id))

    def _issue(self, member_id: str, peer: Peer) -> Lease:
        self.registry.acquire_slot(peer.id)
        lease = Lease(
            request_id=secrets.token_urlsafe(16),
            member_id=member_id,
            peer=peer,
            expires_at=self._clock() + self.lease_ttl,
        )
        self._leases[lease.request_id] = lease
        return lease

    def _dispatch(self) -> None:
        """Give freed slots to the best waiters that can actually be served."""
        deferred: list[_Waiter] = []
        while self._waiters:
            waiter = heapq.heappop(self._waiters)
            if waiter.future.done():
                continue
            peer = self._pick(waiter.model)
            if peer is None:
                deferred.append(waiter)
                # No capacity for this model; a lower-priority waiter on a
                # different model may still be servable, so keep scanning.
                continue
            waiter.future.set_result(self._issue(waiter.member_id, peer))
        for waiter in deferred:
            heapq.heappush(self._waiters, waiter)

    def _drop(self, waiter: _Waiter) -> None:
        try:
            self._waiters.remove(waiter)
            heapq.heapify(self._waiters)
        except ValueError:
            pass

    # -- introspection ---------------------------------------------------

    @property
    def queue_depth(self) -> int:
        return len(self._waiters)

    @property
    def active_leases(self) -> int:
        return len(self._leases)

    def expire_stale(self) -> int:
        """Reclaim slots for leases nobody redeemed. Returns count reclaimed."""
        now = self._clock()
        stale = [rid for rid, lease in self._leases.items() if now > lease.expires_at]
        for rid in stale:
            self.release(rid)
        return len(stale)
