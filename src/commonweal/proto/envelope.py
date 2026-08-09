"""Wire types: the sealed request envelope and the sealed response chunk.

These carry only opaque, already-encrypted fields. The coordinator handles them
without ever holding a key that could open one -- that property is what makes it
untrusted infrastructure rather than part of the trust boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import canonical
from .version import PROTO_VERSION, ProtocolError, check_version

_ENVELOPE_FIELDS = ("v", "request_id", "sealed_key", "iv", "ciphertext", "sender", "ts")
_CHUNK_FIELDS = ("v", "request_id", "seq", "ciphertext", "final")
_RECEIPT_FIELDS = (
    "v", "request_id", "prompt_tokens", "completion_tokens",
    "engine", "engine_version", "hw_class", "finish_reason",
)

KIND_CHUNK = "chunk"
KIND_RECEIPT = "receipt"


def _require_str(d: dict[str, Any], key: str) -> str:
    val = d.get(key)
    if not isinstance(val, str) or not val:
        raise ProtocolError(f"field {key!r} must be a non-empty string")
    return val


@dataclass(frozen=True)
class Envelope:
    """A request sealed to exactly one recipient.

    `sealed_key` is an X25519 sealed box holding the 32-byte master secret; the
    AES-256-GCM ciphertext carries its own tag. `sig` is the sender's Ed25519
    signature and is what the coordinator checks against the roster -- it can
    authenticate the sender without being able to read the payload.

    `ts` is inside the signed bytes because a signature proves authorship, not
    recency: without a signed clock, a captured envelope stays spendable
    forever, and inference is the most expensive thing a replay can buy.
    """

    request_id: str
    sealed_key: str
    iv: str
    ciphertext: str
    sender: str
    ts: float
    sig: str | None = None
    v: int = PROTO_VERSION

    def signed_bytes(self) -> bytes:
        """Exactly the fields the signature covers -- `sig` itself excluded."""
        return canonical({k: getattr(self, k) for k in _ENVELOPE_FIELDS})

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in _ENVELOPE_FIELDS}
        if self.sig is not None:
            d["sig"] = self.sig
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Envelope:
        if not isinstance(d, dict):
            raise ProtocolError("envelope must be an object")
        check_version(d.get("v"))
        sig = d.get("sig")
        if sig is not None and not isinstance(sig, str):
            raise ProtocolError("field 'sig' must be a string when present")
        ts = d.get("ts")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            raise ProtocolError("field 'ts' must be a number")
        return cls(
            v=d["v"],
            request_id=_require_str(d, "request_id"),
            sealed_key=_require_str(d, "sealed_key"),
            iv=_require_str(d, "iv"),
            ciphertext=_require_str(d, "ciphertext"),
            sender=_require_str(d, "sender"),
            # Kept exactly as parsed: coercing an int to float here would change
            # its canonical JSON encoding and break the sender's signature.
            ts=ts,
            sig=sig,
        )


@dataclass(frozen=True)
class Chunk:
    """One authenticated slice of a streamed response.

    The nonce is derived from `seq` rather than carried, so a dropped or
    reordered chunk fails authentication instead of decrypting to something
    plausible. `final` marks clean end-of-stream: a stream that ends without it
    was truncated, which the client must treat as an error rather than a short
    answer.
    """

    request_id: str
    seq: int
    ciphertext: str
    final: bool = False
    v: int = PROTO_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {"kind": KIND_CHUNK, **{k: getattr(self, k) for k in _CHUNK_FIELDS}}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Chunk:
        if not isinstance(d, dict):
            raise ProtocolError("chunk must be an object")
        check_version(d.get("v"))
        seq = d.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise ProtocolError("field 'seq' must be a non-negative int")
        final = d.get("final", False)
        if not isinstance(final, bool):
            raise ProtocolError("field 'final' must be a bool")
        return cls(
            v=d["v"],
            request_id=_require_str(d, "request_id"),
            seq=seq,
            ciphertext=_require_str(d, "ciphertext"),
            final=final,
        )


@dataclass(frozen=True)
class Receipt:
    """Trailing metering frame -- **deliberately not encrypted**.

    The coordinator must learn token counts to run the ledger, and it cannot
    read the response stream. So the peer states the counts in clear at
    end-of-stream. The trade is explicit and belongs in the threat model: the
    coordinator learns *how much* was generated, never *what*.

    `engine`/`engine_version`/`hw_class` ride along so a heterogeneous
    federation can trace output divergence back to the machine that produced it.

    `finish_reason` is the engine's word for why generation stopped. It is here
    for the same reason `Chunk.final` exists: an answer cut short by the token
    cap is complete-looking and incomplete, and the client must be able to tell.
    """

    request_id: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    engine: str = ""
    engine_version: str = ""
    hw_class: str = ""
    finish_reason: str = ""
    v: int = PROTO_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {"kind": KIND_RECEIPT, **{k: getattr(self, k) for k in _RECEIPT_FIELDS}}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Receipt:
        if not isinstance(d, dict):
            raise ProtocolError("receipt must be an object")
        check_version(d.get("v"))
        counts = {}
        for key in ("prompt_tokens", "completion_tokens"):
            val = d.get(key, 0)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ProtocolError(f"field {key!r} must be a non-negative int")
            counts[key] = val
        # Optional string metadata is read permissively: a peer running an older
        # build omits fields a newer client knows about, and the ledger still
        # needs the counts.
        return cls(
            v=d["v"],
            request_id=_require_str(d, "request_id"),
            engine=d.get("engine", ""),
            engine_version=d.get("engine_version", ""),
            hw_class=d.get("hw_class", ""),
            finish_reason=(
                d["finish_reason"] if isinstance(d.get("finish_reason"), str) else ""
            ),
            **counts,
        )


def parse_frame(d: dict[str, Any]) -> Chunk | Receipt:
    """Decode one line of a peer's NDJSON response stream."""
    kind = d.get("kind")
    if kind == KIND_CHUNK:
        return Chunk.from_dict(d)
    if kind == KIND_RECEIPT:
        return Receipt.from_dict(d)
    raise ProtocolError(f"unknown frame kind {kind!r}")
