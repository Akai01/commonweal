"""The peer: the one place in the system that sees plaintext.

A peer decrypts because it must -- a matmul on ciphertext is not a matmul. That
is why membership, not cryptography, is a federation's privacy boundary, and
why `docs/THREAT-MODEL.md` says so plainly rather than implying the encryption
protects against the machine doing the work.

The peer verifies the sender against the signed roster before decrypting, so
only members can spend its capacity.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from nacl.public import PrivateKey

from ..crypto import SealError, seal_chunk, unseal_request, verify_envelope
from ..engines import Engine, EngineError, GenerationParams, NoAnswerError, Usage
from ..proto import Chunk, Envelope, ProtocolError, Receipt
from ..replay import NonceCache, ReplayError, check_fresh
from ..roster import Roster, RosterError
from ..sanitise import sanitise_detail, sanitise_message

# One token, no sampling: enough to prove the engine can actually run the model,
# cheap enough to do while idle.
_PROBE_MESSAGES = [{"role": "user", "content": "ping"}]
_PROBE_PARAMS = GenerationParams(max_tokens=1, temperature=0.0, top_p=1.0)


@dataclass
class PeerConfig:
    peer_id: str
    hw_class: str = "unknown"
    max_tokens_cap: int = 4096
    # A request that recently succeeded is proof of readiness, so the probe only
    # runs on an idle peer and costs nothing under load.
    readiness_window: float = 60.0
    # Ceiling on probe frequency. /health is unauthenticated, so without this an
    # onlooker could make us run inference as often as they like.
    probe_interval: float = 15.0
    # Escape hatch: fall back to the liveness check for operators who would
    # rather not spend tokens on probing.
    inference_probe: bool = True


@dataclass(frozen=True)
class Readiness:
    """Whether this peer can serve *right now*, and how we know.

    Distinct from liveness. An engine can hold its socket open while being
    unable to answer -- for example after losing part of a sharded model. A
    check that only proves a port is listening would call such a peer healthy
    and keep routing to it. A readiness check has to prove the engine can
    actually serve, not merely that it is up.
    """

    ok: bool
    reason: str


class Peer:
    def __init__(
        self,
        config: PeerConfig,
        roster: Roster,
        engine: Engine,
        enc_private_key: bytes,
        *,
        clock=time.monotonic,
    ):
        self.config = config
        self.roster = roster
        self.engine = engine
        self._priv = PrivateKey(enc_private_key)
        self._clock = clock
        self._last_progress = 0.0
        self._cached: Readiness | None = None
        self._cached_at = 0.0
        # Single-flight. The interval alone only rate-limits *sequential* callers:
        # 25 concurrent /health requests produced 25 engine probes before this
        # existed, which is the amplification the interval was meant to stop.
        self._probe_lock = asyncio.Lock()
        # The signature on an envelope proves a member wrote it, not that it is
        # not a capture being spent a second time. The coordinator necessarily
        # holds every envelope, and it is untrusted -- so the peer keeps its own
        # seen-set rather than taking anyone's word for freshness.
        self.replay = NonceCache(what="request_id")

    def note_progress(self) -> None:
        """Record that the engine just produced output for a real request.

        Called per chunk rather than at end of stream: a long generation that is
        streaming happily is evidence of readiness while it is still running,
        and waiting for it to finish would let the probe fire against a busy
        engine and time out on capacity rather than on health.
        """
        self._last_progress = self._clock()

    async def is_ready(self) -> bool:
        return (await self.ready()).ok

    def _fresh(self, now: float) -> Readiness | None:
        if self._cached is not None and (now - self._cached_at) < self.config.probe_interval:
            return self._cached
        return None

    async def ready(self) -> Readiness:
        now = self._clock()
        idle_for = now - self._last_progress
        if self._last_progress and idle_for <= self.config.readiness_window:
            return Readiness(True, f"served a request {idle_for:.0f}s ago")
        cached = self._fresh(now)
        if cached is not None:
            return cached

        async with self._probe_lock:
            # Re-check inside the lock: whoever held it may have just probed, and
            # one probe is meant to answer for everyone in the interval.
            now = self._clock()
            cached = self._fresh(now)
            if cached is not None:
                return cached
            result = await self._probe()
            self._cached, self._cached_at = result, now
            return result

    async def _probe(self) -> Readiness:
        if not self.config.inference_probe:
            try:
                ok = await self.engine.health()
            except Exception as exc:                       # a health check should not raise
                return Readiness(False, f"liveness check raised: {exc}")
            return Readiness(ok, "liveness only; inference probe disabled")

        stream = self.engine.stream(_PROBE_MESSAGES, _PROBE_PARAMS)
        try:
            async for _ in stream:
                return Readiness(True, "inference probe produced output")
            return Readiness(False, "inference probe produced nothing at all")
        except NoAnswerError:
            # It reached the model and computed; it just spent a one-token
            # budget on thinking. That is a working reasoning model, not a
            # broken peer, and conflating them would take healthy peers out of
            # the pool for doing exactly what they are configured to do.
            return Readiness(True, "inference probe reached the model (reasoning only)")
        except EngineError as exc:
            return Readiness(False, f"inference probe failed: {exc}")
        except Exception as exc:
            return Readiness(False, f"inference probe raised: {exc}")
        finally:
            aclose = getattr(stream, "aclose", None)
            if aclose is not None:
                await aclose()   # abandoning a stream must not leak its connection


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


def _estimate_tokens(chars: int) -> int:
    """Fallback char/4 heuristic, used only when the engine reports no usage.

    Deliberately approximate and deliberately visible. Engines that support
    `stream_options.include_usage` (vLLM, SGLang, OpenAI) give real counts and
    those are always preferred -- inventing precision we do not have would make
    the ledger look more authoritative than it is.
    """
    return max(1, chars // 4) if chars else 0


def create_app(peer: Peer) -> FastAPI:
    # No /docs, /redoc or /openapi.json. A peer is the one component that holds
    # plaintext, and the schema it would publish is already in docs/PROTOCOL.md.
    # Same reasoning as the coordinator; see the comment there.
    app = FastAPI(
        title=f"commonweal peer {peer.config.peer_id}", version="0.1.0",
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.state.peer = peer

    @app.get("/health")
    async def health():
        """Liveness for the coordinator -- and the one endpoint here with no
        signature check, because a peer that could only be probed by an
        authenticated caller could not be monitored by ordinary tooling.

        `detail` is sanitised for the same reason the coordinator sanitises it
        before `/v1/stats` echoes it: the text comes out of an engine's error
        body, and this response goes to whoever asked, including an operator's
        terminal. What the endpoint discloses is documented in
        docs/PROTOCOL.md §7 and accounted for in docs/THREAT-MODEL.md.
        """
        readiness = await peer.ready()
        return {
            "status": "ok" if readiness.ok else "degraded",
            "detail": sanitise_detail(readiness.reason),
            "peer_id": peer.config.peer_id,
            "model": peer.engine.model,
            "engine": peer.engine.name,
            "engine_version": peer.engine.version,
            "hw_class": peer.config.hw_class,
        }

    @app.post("/infer")
    async def infer(request: Request):
        try:
            envelope = Envelope.from_dict(await request.json())
        except (ProtocolError, ValueError) as exc:
            return _error(400, "bad_envelope", str(exc))

        # Authenticate before decrypting: only members may spend our capacity.
        try:
            member = peer.roster.member(envelope.sender)
            verify_envelope(envelope, member.sign_pub_bytes)
        except (RosterError, ProtocolError) as exc:
            return _error(401, "unauthorized", str(exc))

        # Then refuse replays before spending anything on decryption or
        # inference. Checked after the signature so junk cannot fill the
        # seen-set, same ordering as the coordinator's nonce cache.
        try:
            check_fresh(envelope.ts, now=time.time())
            peer.replay.check_and_add(envelope.request_id)
        except ReplayError as exc:
            return _error(401, "unauthorized", str(exc))

        try:
            payload, master = unseal_request(envelope, peer._priv)
        except SealError as exc:
            return _error(400, "unsealable", str(exc))

        try:
            body = json.loads(payload)
            messages = body["messages"]
            if not isinstance(messages, list) or not messages:
                raise ValueError("messages must be a non-empty list")
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            return _error(400, "bad_request", f"malformed request payload: {exc}")

        params = GenerationParams.from_request(body)
        params = GenerationParams(
            max_tokens=min(params.max_tokens, peer.config.max_tokens_cap),
            temperature=params.temperature,
            top_p=params.top_p,
        )
        prompt_chars = sum(len(m.get("content", "")) for m in messages)

        async def stream():
            seq = 0
            produced = 0
            reported: Usage | None = None
            try:
                async for item in peer.engine.stream(messages, params):
                    if isinstance(item, Usage):
                        reported = item
                        continue
                    produced += len(item)
                    peer.note_progress()
                    yield json.dumps(
                        Chunk(
                            request_id=envelope.request_id,
                            seq=seq,
                            ciphertext=seal_chunk(item.encode("utf-8"), master, seq),
                        ).to_dict()
                    ) + "\n"
                    seq += 1
            except EngineError as exc:
                # `OpenAICompatEngine` puts up to 400 characters of the backend's
                # raw error body in here, and this frame is **not** encrypted: it
                # crosses the untrusted coordinator in clear on its way to the
                # client's terminal. So an engine behind a gateway must not be
                # able to reach through it with an ANSI escape, nor say more about
                # the request than the receipt already concedes. Bounded at
                # MAX_MESSAGE_CHARS, not MAX_DETAIL_CHARS, because a NoAnswerError
                # carries the guidance telling an operator how to get an answer.
                yield json.dumps(
                    {"kind": "error", "v": 1,
                     "request_id": envelope.request_id,
                     "message": sanitise_message(str(exc))}
                ) + "\n"
                return

            # Explicit end-of-stream. A stream that stops without this was
            # truncated, and the client must be able to tell the difference
            # between a short answer and a lost connection.
            yield json.dumps(
                Chunk(
                    request_id=envelope.request_id,
                    seq=seq,
                    ciphertext=seal_chunk(b"", master, seq),
                    final=True,
                ).to_dict()
            ) + "\n"

            # The engine's own counts win when it reports them; the estimator
            # is a fallback, not a default. A zero count is read as "not
            # reported" rather than as zero tokens, because an engine may
            # describe why it stopped without reporting counts at all -- and
            # billing a request that produced text as zero would understate the
            # ledger in the peer's own favour.
            yield json.dumps(
                Receipt(
                    request_id=envelope.request_id,
                    prompt_tokens=(
                        reported.prompt_tokens
                        if reported and reported.prompt_tokens
                        else _estimate_tokens(prompt_chars)
                    ),
                    completion_tokens=(
                        reported.completion_tokens
                        if reported and reported.completion_tokens
                        else _estimate_tokens(produced)
                    ),
                    engine=peer.engine.name,
                    engine_version=peer.engine.version,
                    hw_class=peer.config.hw_class,
                    finish_reason=reported.finish_reason if reported else "",
                ).to_dict()
            ) + "\n"

        return StreamingResponse(stream(), media_type="application/x-ndjson")

    return app
