"""Deterministic byte encoding for anything that gets signed.

Signatures are computed over canonical bytes, never over a dict or a
pretty-printed blob: two encoders must agree byte-for-byte or verification
fails for reasons that look like tampering.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def canonical(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, no insignificant whitespace, UTF-8.

    `ensure_ascii=False` keeps non-ASCII as real UTF-8 rather than \\uXXXX
    escapes, so the encoding does not depend on the producer's locale.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    """Strict base64 decode.

    `validate=True` so that a corrupted field raises here rather than silently
    decoding to different bytes and failing later as an opaque auth error.
    """
    return base64.b64decode(text.encode("ascii"), validate=True)
