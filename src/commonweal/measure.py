"""Concurrency measurement -- the number that decides what to build next.

The open question: **what concurrency does a real federation actually
generate?** Every throughput argument for batching assumes sustained concurrent
load. Six people do not generate B=32; they generate bursts of one to three
with long idle gaps.

If real load is 1-3 concurrent, batching buys almost nothing and the federation
is an *access* play -- running a model none of you could alone -- rather than a
*throughput* play. That reordering is large enough that it should be settled
with data before more is built.

The measurement needs weeks of wall clock, so it records from day one and costs
one row per request.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS arrivals (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id    TEXT    NOT NULL,
    model        TEXT    NOT NULL,
    event        TEXT    NOT NULL,   -- 'lease' | 'start' | 'end'
    in_flight    INTEGER NOT NULL,   -- observed concurrency at this instant
    queue_depth  INTEGER NOT NULL,
    at           REAL    NOT NULL,   -- unix seconds
    at_iso       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arrivals_at ON arrivals(at);
"""


@dataclass(frozen=True)
class ConcurrencyReport:
    samples: int
    mean_in_flight: float
    p50: int
    p95: int
    max_in_flight: int
    mean_queue_depth: float
    span_hours: float

    def verdict(self) -> str:
        """The plain-language answer to the question above.

        Deliberately opinionated: the point of the measurement is to make a
        build decision, so it states one rather than handing back statistics.
        """
        if self.samples < 100:
            return (
                f"insufficient data ({self.samples} samples) -- keep collecting; "
                "two weeks of real use is the target"
            )
        if self.p95 <= 3:
            return (
                f"LOW concurrency (p95={self.p95}). Batching buys little. Treat this "
                "federation as an ACCESS play -- running a model no member could host "
                "alone -- rather than a throughput play."
            )
        if self.p95 <= 8:
            return (
                f"MODERATE concurrency (p95={self.p95}). Batching helps but will not "
                "reach the GEMM regime (~B=30). Modest gains; queueing and fair-share "
                "matter more than batch size."
            )
        return (
            f"HIGH concurrency (p95={self.p95}). Batching is worth real effort -- at "
            "B>=30 expert matmuls become GEMM and stop being bandwidth-starved."
        )


class ConcurrencyLog:
    """One row per lifecycle event. Cheap enough to leave on permanently."""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def record(
        self,
        *,
        member_id: str,
        model: str,
        event: str,
        in_flight: int,
        queue_depth: int,
        at: float,
    ) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO arrivals (member_id, model, event, in_flight, queue_depth,"
                " at, at_iso) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    member_id, model, event, int(in_flight), int(queue_depth),
                    float(at), datetime.fromtimestamp(at, UTC).isoformat(),
                ),
            )
        self._conn.commit()

    def report(self) -> ConcurrencyReport:
        """Summarise concurrency observed at request *start*.

        Only 'start' events are sampled: lease and end events would bias the
        distribution toward the moments concurrency is changing rather than
        the steady state we care about.
        """
        rows = self._conn.execute(
            "SELECT in_flight, queue_depth, at FROM arrivals WHERE event = 'start'"
            " ORDER BY in_flight"
        ).fetchall()
        if not rows:
            return ConcurrencyReport(0, 0.0, 0, 0, 0, 0.0, 0.0)

        flights = [r["in_flight"] for r in rows]
        queues = [r["queue_depth"] for r in rows]
        times = [r["at"] for r in rows]
        n = len(flights)
        return ConcurrencyReport(
            samples=n,
            mean_in_flight=sum(flights) / n,
            p50=flights[int(n * 0.50)] if n else 0,
            p95=flights[min(int(n * 0.95), n - 1)],
            max_in_flight=flights[-1],
            mean_queue_depth=sum(queues) / n,
            span_hours=(max(times) - min(times)) / 3600.0,
        )

    def hourly_histogram(self) -> dict[int, int]:
        """Requests per hour-of-day (UTC) -- shows whether load is bursty."""
        rows = self._conn.execute(
            "SELECT at_iso FROM arrivals WHERE event = 'start'"
        ).fetchall()
        hist: dict[int, int] = {}
        for row in rows:
            hour = datetime.fromisoformat(row["at_iso"]).hour
            hist[hour] = hist.get(hour, 0) + 1
        return dict(sorted(hist.items()))
