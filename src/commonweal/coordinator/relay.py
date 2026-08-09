"""Opaque relay from coordinator to peer.

The coordinator forwards sealed bytes and streams sealed bytes back. It parses
only enough framing to find the trailing receipt for metering -- it never holds
a key that could open a chunk. That is the property that makes the coordinator
untrusted infrastructure, and `tests/test_e2e.py::test_coordinator_cannot_decrypt`
asserts it.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx

from ..proto import KIND_RECEIPT, Receipt
from ..tlsconfig import DEFAULT_TLS, TLSConfig


class RelayError(Exception):
    """Peer was unreachable or answered with an error."""


async def relay_to_peer(
    peer_endpoint: str,
    envelope: dict,
    *,
    timeout: float = 300.0,
    on_receipt=None,
    tls: TLSConfig = DEFAULT_TLS,
) -> AsyncIterator[str]:
    """Stream a peer's NDJSON response back verbatim.

    Yields each line unchanged. `on_receipt` is invoked with the trailing
    `Receipt` if one arrives, which is how the ledger learns token counts
    without the coordinator being able to read a single token.
    """
    url = f"{peer_endpoint.rstrip('/')}/infer"
    try:
        async with httpx.AsyncClient(timeout=timeout, **tls.httpx_kwargs()) as client:
            async with client.stream("POST", url, json=envelope) as resp:
                if resp.status_code >= 400:
                    detail = (await resp.aread()).decode("utf-8", "replace")[:400]
                    raise RelayError(f"peer returned {resp.status_code}: {detail}")
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    if on_receipt is not None:
                        receipt = _sniff_receipt(line)
                        if receipt is not None:
                            on_receipt(receipt)
                    yield line
    except httpx.HTTPError as exc:
        raise RelayError(f"peer unreachable at {peer_endpoint}: {exc}") from exc


def _sniff_receipt(line: str) -> Receipt | None:
    """Return the Receipt if this line is one; never raise on a bad frame.

    A malformed line is the peer's problem and is passed through to the client
    untouched -- the relay's job is delivery, not validation.
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or obj.get("kind") != KIND_RECEIPT:
        return None
    try:
        return Receipt.from_dict(obj)
    except Exception:
        return None
