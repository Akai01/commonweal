"""Signed control-plane requests.

Leases and heartbeats are authenticated with the caller's Ed25519 identity key
rather than a bearer token. A token that leaks grants access until it is
rotated; a signature covers one specific request and expires on its own.

Replay protection is a nonce plus a timestamp window. Without it, a captured
lease request could be resubmitted forever to drain a member's fair-share
standing.
"""

from __future__ import annotations

import time
from typing import Any

from ..crypto import verify_bytes
from ..proto import ProtocolError, canonical
from ..replay import (
    CLOCK_SKEW_GRACE,
    DEFAULT_MAX_AGE,
    NonceCache,
    ReplayError,
    check_fresh,
)
from ..roster import Roster, RosterError

__all__ = [
    "AuthError",
    "CLOCK_SKEW_GRACE",
    "DEFAULT_MAX_AGE",
    "NonceCache",
    "sign_request",
    "signed_payload",
    "verify_signed_request",
]


class AuthError(Exception):
    """Request is unsigned, missigned, stale, or replayed."""


def signed_payload(member_id: str, nonce: str, ts: float, body: dict[str, Any]) -> bytes:
    return canonical({"member_id": member_id, "nonce": nonce, "ts": ts, "body": body})


def sign_request(member_id: str, body: dict[str, Any], signing_key, *, nonce: str, ts: float) -> dict:
    from ..crypto import sign_bytes

    return {
        "member_id": member_id,
        "nonce": nonce,
        "ts": ts,
        "body": body,
        "sig": sign_bytes(signed_payload(member_id, nonce, ts, body), signing_key),
    }


def verify_signed_request(
    doc: dict[str, Any],
    roster: Roster,
    nonces: NonceCache,
    *,
    max_age: float = DEFAULT_MAX_AGE,
    clock=time.time,
) -> tuple[str, dict[str, Any]]:
    """Return (member_id, body) or raise AuthError."""
    if not isinstance(doc, dict):
        raise AuthError("request must be an object")
    member_id = doc.get("member_id")
    nonce = doc.get("nonce")
    sig = doc.get("sig")
    ts = doc.get("ts")
    body = doc.get("body")
    if not all(isinstance(x, str) and x for x in (member_id, nonce, sig)):
        raise AuthError("member_id, nonce and sig are required")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise AuthError("ts must be a number")
    if not isinstance(body, dict):
        raise AuthError("body must be an object")

    try:
        check_fresh(ts, now=clock(), max_age=max_age)
    except ReplayError as exc:
        raise AuthError(str(exc)) from exc

    try:
        member = roster.member(member_id)
    except RosterError as exc:
        raise AuthError(str(exc)) from exc

    try:
        verify_bytes(signed_payload(member_id, nonce, ts, body), sig, member.sign_pub_bytes)
    except ProtocolError as exc:
        raise AuthError(f"bad signature from {member_id!r}") from exc

    # Only after the signature checks out, so an unauthenticated caller cannot
    # fill the cache with junk nonces.
    try:
        nonces.check_and_add(nonce)
    except ReplayError as exc:
        raise AuthError(str(exc)) from exc
    return member_id, body
