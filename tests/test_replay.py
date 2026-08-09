"""The shared replay defence: freshness window and the seen-set.

Both the control plane (nonces) and the sealed data plane (envelope
request_ids) lean on this module, so its edges are worth pinning directly
rather than only through the end-to-end paths.
"""

from __future__ import annotations

import pytest

from commonweal.replay import (
    CLOCK_SKEW_GRACE,
    DEFAULT_MAX_AGE,
    NonceCache,
    ReplayError,
    check_fresh,
)


def test_fresh_timestamp_passes():
    check_fresh(1000.0, now=1000.0)


def test_stale_timestamp_refused():
    with pytest.raises(ReplayError, match="stale"):
        check_fresh(1000.0, now=1000.0 + DEFAULT_MAX_AGE + 1)


def test_future_timestamp_refused():
    with pytest.raises(ReplayError, match="future"):
        check_fresh(1000.0 + CLOCK_SKEW_GRACE + 1, now=1000.0)


def test_skew_grace_is_tolerated():
    check_fresh(1000.0 + CLOCK_SKEW_GRACE, now=1000.0)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_timestamp_refused(bad):
    """NaN compares false against every bound, so without an explicit guard a
    NaN timestamp would read as permanently fresh and outlive any cache."""
    with pytest.raises(ReplayError, match="finite"):
        check_fresh(bad, now=1000.0)


def test_second_sighting_is_a_replay():
    clock = [1000.0]
    cache = NonceCache(clock=lambda: clock[0])
    cache.check_and_add("abc")
    with pytest.raises(ReplayError, match="replayed"):
        cache.check_and_add("abc")


def test_label_names_the_replayed_thing():
    cache = NonceCache(what="request_id")
    cache.check_and_add("r1")
    with pytest.raises(ReplayError, match="replayed request_id"):
        cache.check_and_add("r1")


def test_entry_expires_after_ttl_and_is_accepted_again():
    clock = [1000.0]
    cache = NonceCache(ttl=10.0, clock=lambda: clock[0])
    cache.check_and_add("x")
    clock[0] += 11.0
    cache.check_and_add("x")  # the first sighting has expired; not a replay
    assert len(cache) == 1


def test_cache_is_bounded_under_a_flood():
    """A member cannot grow the seen-set without bound: past the cap the
    soonest-to-expire entry is evicted, and anything that old is refused as
    stale anyway."""
    clock = [1000.0]
    cache = NonceCache(ttl=10_000.0, clock=lambda: clock[0], max_entries=8)
    for i in range(100):
        clock[0] += 0.001
        cache.check_and_add(f"n{i}")
    assert len(cache) <= 8
