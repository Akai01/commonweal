"""Q1 instrumentation: does the concurrency measurement answer the question?"""

from __future__ import annotations

import pytest

from commonweal.measure import ConcurrencyLog


def _fill(log, flights, *, start=1_785_000_000.0, event="start"):
    for i, n in enumerate(flights):
        log.record(
            member_id="alice", model="m", event=event,
            in_flight=n, queue_depth=0, at=start + i * 60,
        )


def test_empty_log_reports_nothing():
    assert ConcurrencyLog().report().samples == 0


def test_insufficient_data_says_so_rather_than_guessing():
    log = ConcurrencyLog()
    _fill(log, [1] * 10)
    assert "insufficient data" in log.report().verdict()


def test_low_concurrency_recommends_access_play():
    """The outcome that would invalidate Phase C -- it must be stated plainly."""
    log = ConcurrencyLog()
    _fill(log, [1, 2, 1, 3, 2] * 40)
    report = log.report()
    assert report.p95 <= 3
    assert "LOW concurrency" in report.verdict()
    assert "ACCESS play" in report.verdict()


def test_high_concurrency_recommends_batching():
    log = ConcurrencyLog()
    _fill(log, list(range(1, 41)) * 5)
    verdict = log.report().verdict()
    assert "HIGH concurrency" in verdict
    assert "GEMM" in verdict


def test_moderate_concurrency_is_distinguished():
    log = ConcurrencyLog()
    _fill(log, [4, 5, 6, 5, 4] * 40)
    assert "MODERATE" in log.report().verdict()


def test_only_start_events_are_sampled():
    """Lease and end events bias toward moments concurrency is changing."""
    log = ConcurrencyLog()
    _fill(log, [1] * 120, event="start")
    _fill(log, [99] * 120, event="end")
    assert log.report().max_in_flight == 1


def test_span_and_histogram():
    log = ConcurrencyLog()
    _fill(log, [2] * 120)
    report = log.report()
    assert report.samples == 120
    assert report.span_hours == pytest.approx(119 / 60.0, rel=1e-3)
    assert sum(log.hourly_histogram().values()) == 120


def test_persists_to_disk(tmp_path):
    path = tmp_path / "c.db"
    log = ConcurrencyLog(path)
    _fill(log, [3] * 120)
    log.close()
    assert ConcurrencyLog(path).report().samples == 120
