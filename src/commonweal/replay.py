"""Replay rejection, shared by the control plane and the sealed data plane.

A signature proves who wrote a message, never when it last crossed the wire.
Anything that spends capacity on receipt therefore needs two checks a signature
cannot give it: the message is recent, and this exact message has not been seen
before. The freshness window bounds how long the seen-set must remember; the
seen-set closes the window from the inside.
"""

from __future__ import annotations

import math
import time

DEFAULT_MAX_AGE = 120.0
# Tolerates modest clock skew between members' machines without opening a
# meaningful replay window.
CLOCK_SKEW_GRACE = 30.0
# Upper bound on remembered values. At the 120 s window a member would have to
# sustain thousands of signed requests per second to approach this; hitting it
# means something is flooding, and the oldest entries are the safe ones to drop
# because anything older than the window is already refused as stale.
DEFAULT_MAX_ENTRIES = 100_000


class ReplayError(Exception):
    """Message is stale, future-dated, or already seen."""


def check_fresh(ts: float, *, now: float, max_age: float = DEFAULT_MAX_AGE) -> None:
    """Raise unless `ts` is within the acceptance window around `now`.

    A non-finite `ts` is rejected outright: NaN compares false against every
    bound, so without this a NaN timestamp would read as permanently fresh. The
    canonical encoder already refuses to sign NaN, but checking here keeps the
    freshness guarantee a property of this function rather than of the encoder.
    """
    if not math.isfinite(ts):
        raise ReplayError("request timestamp is not a finite number")
    if ts > now + CLOCK_SKEW_GRACE:
        raise ReplayError("request timestamp is in the future")
    if now - ts > max_age:
        raise ReplayError("request is stale")


class NonceCache:
    """Remembers values long enough to outlive the freshness window.

    In-memory on purpose: a restart forgets everything, but a replayed message
    older than the freshness window is refused as stale anyway, so the exposure
    is bounded by `max_age + CLOCK_SKEW_GRACE`, not by uptime.
    """

    def __init__(
        self,
        ttl: float = DEFAULT_MAX_AGE * 2,
        clock=time.time,
        what: str = "nonce",
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self._ttl = ttl
        self._clock = clock
        self._what = what
        self._max_entries = max_entries
        self._seen: dict[str, float] = {}

    def check_and_add(self, value: str) -> None:
        now = self._clock()
        if self._seen:
            self._prune(now)
        if value in self._seen:
            raise ReplayError(f"replayed {self._what}")
        # A flood of fresh values could still outrun expiry; cap the set so a
        # member cannot grow it without bound. Evicting the soonest-to-expire
        # only shortens their protection, and they are the least valuable to
        # keep -- everything past the window is refused as stale regardless.
        if len(self._seen) >= self._max_entries:
            oldest = min(self._seen, key=self._seen.__getitem__)
            del self._seen[oldest]
        self._seen[value] = now + self._ttl

    def _prune(self, now: float) -> None:
        expired = [n for n, exp in self._seen.items() if exp <= now]
        for n in expired:
            del self._seen[n]

    def __len__(self) -> int:
        return len(self._seen)
