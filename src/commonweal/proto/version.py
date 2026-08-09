"""Protocol version negotiation.

Every wire message carries `v`. A peer that does not recognise a version must
refuse the message rather than guess at its shape.
"""

from __future__ import annotations

PROTO_VERSION = 1
SUPPORTED_VERSIONS = frozenset({1})


class ProtocolError(Exception):
    """Malformed, unsupported, or unverifiable wire message."""


def check_version(v: object) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ProtocolError(f"protocol version must be an int, got {type(v).__name__}")
    if v not in SUPPORTED_VERSIONS:
        raise ProtocolError(
            f"unsupported protocol version {v}; this build speaks {sorted(SUPPORTED_VERSIONS)}"
        )
    return v
