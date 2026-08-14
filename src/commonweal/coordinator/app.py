"""The coordinator HTTP surface.

**This process is untrusted by design.** It routes sealed ciphertext, meters
usage, and schedules -- and it holds no key that could open a request. That is
what lets it be public, always-on, and run by whoever is willing, without
widening the trust boundary to include them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..ledger import Ledger
from ..measure import ConcurrencyLog
from ..proto import Envelope, ProtocolError
from ..crypto import verify_envelope
from ..replay import ReplayError, check_fresh
from ..roster import Roster, RosterError
from ..sanitise import sanitise_message
from ..tlsconfig import DEFAULT_TLS, TLSConfig
from .auth import AuthError, NonceCache, verify_signed_request
from .registry import Registry
from .relay import RelayError, relay_to_peer
from .scheduler import LeaseExpired, NoCapacity, QueueFull, Scheduler


@dataclass
class CoordinatorConfig:
    relay_timeout: float = 300.0
    max_queue: int = 32
    queue_timeout: float = 120.0
    lease_ttl: float = 300.0
    # Outbound TLS for relays to peers. Inbound TLS is uvicorn's business.
    tls: TLSConfig = DEFAULT_TLS


class Coordinator:
    def __init__(
        self,
        roster: Roster,
        *,
        ledger: Ledger | None = None,
        config: CoordinatorConfig | None = None,
        concurrency: ConcurrencyLog | None = None,
    ):
        self.config = config or CoordinatorConfig()
        self.roster = roster
        self.ledger = ledger or Ledger()
        self.registry = Registry(roster, self.ledger)
        self.scheduler = Scheduler(
            self.registry,
            self.ledger,
            lease_ttl=self.config.lease_ttl,
            max_queue=self.config.max_queue,
            queue_timeout=self.config.queue_timeout,
        )
        self.nonces = NonceCache()
        # See measure.py: records from day one because the answer
        # needs weeks of wall clock and decides whether batching is worth
        # building at all.
        self.concurrency = concurrency or ConcurrencyLog()

    def observe(self, event: str, member_id: str, model: str) -> None:
        self.concurrency.record(
            member_id=member_id,
            model=model,
            event=event,
            in_flight=sum(
                self.registry.state(p).in_flight for p in self.roster.peers
            ),
            queue_depth=self.scheduler.queue_depth,
            at=time.time(),
        )


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


def create_app(coordinator: Coordinator) -> FastAPI:
    # FastAPI serves /docs, /redoc and /openapi.json unauthenticated by default.
    # This process is meant to be public and always-on, and the threat model says
    # only /v1/health is open -- which would not be true with a Swagger console
    # mounted next to it. The wire format is specified in docs/PROTOCOL.md, so a
    # generated schema adds nothing a reader of this repository does not have,
    # and an interactive request builder aimed at a public service is surface
    # with no corresponding use.
    app = FastAPI(
        title="commonweal coordinator", version="0.1.0",
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.state.coordinator = coordinator

    @app.get("/v1/health")
    async def health():
        return {
            "status": "ok",
            "federation_id": coordinator.roster.federation_id,
            "roster_version": coordinator.roster.roster_version,
        }

    async def _member_only(request: Request) -> JSONResponse | None:
        """These reads carry the federation's metadata -- who is in it, where
        their machines are, when they are active. The coordinator is public and
        always-on, so without a member signature that map would be readable by
        the whole internet, which the threat model has no business conceding."""
        try:
            doc = await request.json()
            verify_signed_request(doc, coordinator.roster, coordinator.nonces)
        except (AuthError, ValueError) as exc:
            return _error(401, "unauthorized", str(exc))
        return None

    @app.post("/v1/roster")
    async def get_roster(request: Request):
        """Serve the signed roster -- to members. Recipients verify it against
        admin keys they pinned at join time, so this endpoint is a convenience,
        not a source of authority; the signature requirement protects the
        contents (every peer's endpoint), not the document's integrity."""
        refused = await _member_only(request)
        if refused is not None:
            return refused
        return coordinator.roster.to_dict()

    @app.post("/v1/stats")
    async def stats(request: Request):
        refused = await _member_only(request)
        if refused is not None:
            return refused
        return {
            "peers": coordinator.registry.snapshot(),
            "queue_depth": coordinator.scheduler.queue_depth,
            "active_leases": coordinator.scheduler.active_leases,
            "totals": coordinator.ledger.totals(),
            "fair_share": coordinator.ledger.fair_share(list(coordinator.roster.members)),
        }

    @app.post("/v1/concurrency")
    async def concurrency(request: Request):
        """The open question: what concurrency does this federation generate?

        Batching is only worth building if the answer is high. Reported here
        rather than buried in a database so the decision can be made on data."""
        refused = await _member_only(request)
        if refused is not None:
            return refused
        report = coordinator.concurrency.report()
        return {
            "samples": report.samples,
            "span_hours": round(report.span_hours, 2),
            "mean_in_flight": round(report.mean_in_flight, 2),
            "p50": report.p50,
            "p95": report.p95,
            "max_in_flight": report.max_in_flight,
            "mean_queue_depth": round(report.mean_queue_depth, 2),
            "by_hour_utc": coordinator.concurrency.hourly_histogram(),
            "verdict": report.verdict(),
        }

    @app.post("/v1/peers/heartbeat")
    async def heartbeat(request: Request):
        try:
            doc = await request.json()
            member_id, body = verify_signed_request(
                doc, coordinator.roster, coordinator.nonces
            )
        except (AuthError, ValueError) as exc:
            return _error(401, "unauthorized", str(exc))

        peer_id = body.get("peer_id")
        if not isinstance(peer_id, str):
            return _error(400, "bad_request", "peer_id is required")
        try:
            peer = coordinator.roster.peer(peer_id)
        except RosterError as exc:
            return _error(404, "unknown_peer", str(exc))
        # The owner runs the endpoint, so only the owner reports whether the peer
        # can serve. A declared contributor may attest to holding its own share
        # of the memory -- which credits that member and shows the group who is
        # still up, but deliberately cannot make a broken group routable.
        if peer.owner == member_id:
            coordinator.registry.heartbeat(
                peer_id,
                resident_gb=float(body.get("resident_gb", 0.0)),
                healthy=bool(body.get("healthy", True)),
                # Optional: a peer on an older build omits it, and the registry
                # sanitises it before it is echoed to members on /v1/stats.
                detail=body.get("detail", ""),
            )
            return {"ok": True, "peer_id": peer_id, "role": "owner"}

        if any(c.member == member_id for c in peer.contributors):
            coordinator.registry.attest(
                peer_id, member_id,
                resident_gb=float(body.get("resident_gb", 0.0)),
            )
            return {"ok": True, "peer_id": peer_id, "role": "contributor"}

        return _error(
            403, "forbidden",
            f"{member_id!r} neither owns nor is a declared contributor to peer {peer_id!r}",
        )

    @app.post("/v1/lease")
    async def lease(request: Request):
        """Round one: assign a peer and disclose its public key.

        The client then seals the request to that peer alone, so no other peer
        -- and not the coordinator -- can open it."""
        try:
            doc = await request.json()
            member_id, body = verify_signed_request(
                doc, coordinator.roster, coordinator.nonces
            )
        except (AuthError, ValueError) as exc:
            return _error(401, "unauthorized", str(exc))

        model = body.get("model")
        if not isinstance(model, str) or not model:
            return _error(400, "bad_request", "model is required")

        coordinator.scheduler.expire_stale()
        try:
            granted = await coordinator.scheduler.acquire(member_id, model)
        except NoCapacity as exc:
            return _error(503, "no_capacity", str(exc))
        except QueueFull as exc:
            return JSONResponse(
                {"error": {"code": "queue_full", "message": str(exc)}},
                status_code=429,
                headers={"Retry-After": "5"},
            )
        coordinator.observe("lease", member_id, model)
        return granted.to_dict()

    @app.post("/v1/infer")
    async def infer(request: Request):
        """Round two: relay a sealed envelope and stream the sealed reply."""
        try:
            envelope = Envelope.from_dict(await request.json())
        except (ProtocolError, ValueError) as exc:
            return _error(400, "bad_envelope", str(exc))

        try:
            member = coordinator.roster.member(envelope.sender)
            verify_envelope(envelope, member.sign_pub_bytes)
        except (RosterError, ProtocolError) as exc:
            return _error(401, "unauthorized", str(exc))

        # The peer keeps the authoritative seen-set; this check just refuses
        # obvious replays before a lease lookup is spent on them.
        try:
            check_fresh(envelope.ts, now=time.time())
        except ReplayError as exc:
            return _error(401, "unauthorized", str(exc))

        try:
            granted = coordinator.scheduler.redeem(envelope.request_id, envelope.sender)
        except LeaseExpired as exc:
            return _error(409, "no_lease", str(exc))

        peer = granted.peer

        def on_receipt(receipt):
            coordinator.ledger.record_consumption(
                member_id=envelope.sender,
                request_id=envelope.request_id,
                peer_id=peer.id,
                prompt_tokens=receipt.prompt_tokens,
                completion_tokens=receipt.completion_tokens,
                engine=receipt.engine or peer.engine,
                engine_version=receipt.engine_version or peer.engine_version,
                hw_class=receipt.hw_class or peer.hw_class,
            )

        coordinator.observe("start", envelope.sender, peer.model)

        async def stream():
            try:
                async for line in relay_to_peer(
                    peer.endpoint,
                    envelope.to_dict(),
                    timeout=coordinator.config.relay_timeout,
                    on_receipt=on_receipt,
                    tls=coordinator.config.tls,
                ):
                    yield line + "\n"
            except RelayError as exc:
                coordinator.registry.mark_failure(peer.id)
                # The stream has already begun, so the status code is spent --
                # emit a terminal error frame the client can distinguish from a
                # clean end-of-stream.
                yield _error_frame(envelope.request_id, str(exc))
            finally:
                coordinator.scheduler.release(envelope.request_id)
                coordinator.observe("end", envelope.sender, peer.model)

        return StreamingResponse(
            stream(),
            media_type="application/x-ndjson",
            headers={"X-Commonweal-Peer": peer.id, "X-Commonweal-Hw-Class": peer.hw_class},
        )

    return app


def _error_frame(request_id: str, message: str) -> str:
    import json

    # A `RelayError` embeds up to 400 characters of the peer's raw HTTP response
    # body, so this carries text the coordinator did not write to a terminal it
    # does not control. Same rule as everywhere else that untrusted text is
    # emitted -- see commonweal.sanitise.
    return json.dumps(
        {"kind": "error", "v": 1, "request_id": request_id,
         "message": sanitise_message(message)}
    ) + "\n"
