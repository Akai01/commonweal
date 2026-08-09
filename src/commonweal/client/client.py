"""The two-round client flow.

    1. lease  -- ask the coordinator for a peer; learn its public key
    2. infer  -- seal to that peer alone, relay through the coordinator

The client is the only component that holds both the plaintext prompt and the
master secret. The coordinator sees neither.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from ..coordinator.auth import sign_request
from ..crypto import SealError, seal_request, sign_envelope, unseal_chunk
from ..proto import KIND_CHUNK, KIND_RECEIPT, Chunk, Receipt, unb64
from ..tlsconfig import DEFAULT_TLS, TLSConfig
from .keys import Identity


class ClientError(Exception):
    """Request failed, was refused, or arrived corrupted."""


class TruncatedStream(ClientError):
    """Stream ended without the final marker -- the answer is incomplete.

    Raised rather than returning a short result: silently handing back a
    truncated answer is the failure mode most likely to go unnoticed.
    """


@dataclass
class Completion:
    text: str
    peer_id: str
    engine: str
    engine_version: str
    hw_class: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = ""

    def served_by(self) -> str:
        """Provenance line. A heterogeneous federation cannot promise
        byte-identical output, so who produced an answer is part of the answer."""
        return f"{self.peer_id} ({self.engine} {self.engine_version}, {self.hw_class})"

    @property
    def truncated(self) -> bool:
        """True if the token cap, not the model, ended the answer.

        A complete stream can still carry an incomplete answer. `TruncatedStream`
        covers a lost connection; this covers a budget that ran out, which with
        reasoning models is the common case rather than the rare one.
        """
        return self.finish_reason == "length"


class CommonwealClient:
    def __init__(
        self,
        coordinator_url: str,
        identity: Identity,
        *,
        timeout: float = 300.0,
        tls: TLSConfig = DEFAULT_TLS,
    ):
        self.coordinator_url = coordinator_url.rstrip("/")
        self.identity = identity
        self.timeout = timeout
        self.tls = tls

    async def lease(self, model: str, *, client: httpx.AsyncClient) -> dict:
        doc = sign_request(
            self.identity.member_id,
            {"model": model},
            self.identity.signing_key,
            nonce=secrets.token_urlsafe(12),
            ts=time.time(),
        )
        resp = await client.post(f"{self.coordinator_url}/v1/lease", json=doc)
        if resp.status_code >= 400:
            raise ClientError(_describe(resp))
        return resp.json()

    async def stream(
        self,
        messages: list[dict[str, str]],
        *,
        model: str,
        max_tokens: int = 512,
        temperature: float = 0.7,
        top_p: float = 1.0,
    ) -> AsyncIterator[str]:
        """Yield decrypted response text. Raises on any integrity failure.

        Text only. A caller that also needs provenance or the finish reason --
        which is how it learns the answer was capped -- wants `events`.
        """
        async for tag, value in self.events(
            messages, model=model, max_tokens=max_tokens,
            temperature=temperature, top_p=top_p,
        ):
            if tag == "text":
                yield value

    async def complete(self, messages, **kw) -> Completion:
        """Collect a full response plus its provenance."""
        parts: list[str] = []
        meta: Receipt | None = None
        peer_id = ""
        async for tag, value in self.events(messages, **kw):
            if tag == "text":
                parts.append(value)
            elif tag == "receipt":
                meta = value
            elif tag == "peer":
                peer_id = value
        return Completion(
            text="".join(parts),
            peer_id=peer_id,
            engine=meta.engine if meta else "",
            engine_version=meta.engine_version if meta else "",
            hw_class=meta.hw_class if meta else "",
            prompt_tokens=meta.prompt_tokens if meta else 0,
            completion_tokens=meta.completion_tokens if meta else 0,
            finish_reason=meta.finish_reason if meta else "",
        )

    async def events(
        self,
        messages: list[dict[str, str]],
        *,
        model: str,
        max_tokens: int = 512,
        temperature: float = 0.7,
        top_p: float = 1.0,
    ):
        """Yields (tag, value) pairs: ("peer", id), ("text", str), ("receipt", Receipt).

        Tagged rather than type-dispatched because response text and metadata
        are both strings often enough that isinstance checks would silently
        concatenate provenance into the answer.

        Public because streaming callers need the receipt too: it is the only
        place the finish reason appears, and a caller that streams should not
        have to give that up to keep incremental output.
        """
        async with httpx.AsyncClient(timeout=self.timeout, **self.tls.httpx_kwargs()) as client:
            granted = await self.lease(model, client=client)
            yield "peer", granted["peer_id"]

            payload = json.dumps({
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": top_p,
            }).encode("utf-8")

            envelope, master = seal_request(
                payload,
                unb64(granted["peer_enc_pub"]),
                request_id=granted["request_id"],
                sender=self.identity.member_id,
            )
            envelope = sign_envelope(envelope, self.identity.signing_key)

            async with client.stream(
                "POST", f"{self.coordinator_url}/v1/infer", json=envelope.to_dict()
            ) as resp:
                if resp.status_code >= 400:
                    raise ClientError(_describe_stream(await resp.aread(), resp.status_code))

                expected_seq = 0
                saw_final = False
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    frame = _decode(line)
                    kind = frame.get("kind")

                    if kind == "error":
                        raise ClientError(frame.get("message", "peer error"))

                    if kind == KIND_CHUNK:
                        chunk = Chunk.from_dict(frame)
                        if chunk.seq != expected_seq:
                            raise ClientError(
                                f"chunk out of order: expected {expected_seq}, got {chunk.seq}"
                            )
                        try:
                            text = unseal_chunk(chunk.ciphertext, master, chunk.seq)
                        except SealError as exc:
                            raise ClientError(str(exc)) from exc
                        expected_seq += 1
                        if chunk.final:
                            saw_final = True
                        elif text:
                            yield "text", text.decode("utf-8", "replace")

                    elif kind == KIND_RECEIPT:
                        yield "receipt", Receipt.from_dict(frame)

                if not saw_final:
                    raise TruncatedStream(
                        "response ended without a final marker; treat it as incomplete"
                    )


def _decode(line: str) -> dict:
    try:
        frame = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ClientError(f"malformed frame: {line[:120]}") from exc
    if not isinstance(frame, dict):
        raise ClientError("frame must be an object")
    return frame


def _describe(resp: httpx.Response) -> str:
    try:
        err = resp.json().get("error", {})
        return f"{resp.status_code} {err.get('code', '')}: {err.get('message', '')}".strip()
    except (json.JSONDecodeError, ValueError, AttributeError):
        return f"{resp.status_code}: {resp.text[:200]}"


def _describe_stream(raw: bytes, status: int) -> str:
    try:
        err = json.loads(raw).get("error", {})
        return f"{status} {err.get('code', '')}: {err.get('message', '')}".strip()
    except (json.JSONDecodeError, ValueError, AttributeError):
        return f"{status}: {raw.decode('utf-8', 'replace')[:200]}"
