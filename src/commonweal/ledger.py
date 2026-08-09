"""Contribution accounting and fair-share priority.

This is the entire incentive mechanism. Among people who already trust each
other it is sufficient: contribute capacity, get priority when the pool is
contended. No token, no chain, no consensus -- a federation replaces those with
membership, and this table is what membership is worth.

Contribution is measured in **GB-hours of residency**, not requests served. A
peer that holds 62 GB resident all night has done the expensive thing
(committing memory) even if nobody sent it work.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS contributions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id         TEXT    NOT NULL,
    owner           TEXT    NOT NULL,
    resident_gb     REAL    NOT NULL,
    seconds         REAL    NOT NULL,
    recorded_at     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contrib_owner ON contributions(owner);

CREATE TABLE IF NOT EXISTS consumptions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id          TEXT    NOT NULL,
    request_id         TEXT    NOT NULL UNIQUE,
    peer_id            TEXT    NOT NULL,
    prompt_tokens      INTEGER NOT NULL DEFAULT 0,
    completion_tokens  INTEGER NOT NULL DEFAULT 0,
    engine             TEXT    NOT NULL DEFAULT '',
    engine_version     TEXT    NOT NULL DEFAULT '',
    hw_class           TEXT    NOT NULL DEFAULT '',
    recorded_at        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_consume_member ON consumptions(member_id);
"""

# Smoothing so a brand-new member is not starved and a zero denominator cannot
# arise. One GB-hour and one thousand tokens are both "about one small session".
_PRIOR_GB_HOURS = 1.0
_PRIOR_KTOKENS = 1.0


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Balance:
    member_id: str
    gb_hours: float
    ktokens: float
    score: float


class Ledger:
    """SQLite-backed. Postgres only becomes worth it past ~10 peers."""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the coordinator serves requests on a thread
        # pool; writes are short and guarded by SQLite's own locking.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- writes ----------------------------------------------------------

    def record_contribution(
        self, peer_id: str, owner: str, resident_gb: float, seconds: float
    ) -> None:
        """Credit a peer for holding `resident_gb` resident for `seconds`."""
        if seconds <= 0 or resident_gb < 0:
            return
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO contributions (peer_id, owner, resident_gb, seconds, recorded_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (peer_id, owner, float(resident_gb), float(seconds), _now()),
            )
        self._conn.commit()

    def record_consumption(
        self,
        *,
        member_id: str,
        request_id: str,
        peer_id: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        engine: str = "",
        engine_version: str = "",
        hw_class: str = "",
    ) -> None:
        """Record one served request.

        `request_id` is UNIQUE: a retried or replayed delivery must not be
        billed twice, so a duplicate is silently ignored rather than raising.
        """
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "INSERT OR IGNORE INTO consumptions (member_id, request_id, peer_id,"
                " prompt_tokens, completion_tokens, engine, engine_version, hw_class,"
                " recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    member_id,
                    request_id,
                    peer_id,
                    int(prompt_tokens),
                    int(completion_tokens),
                    engine,
                    engine_version,
                    hw_class,
                    _now(),
                ),
            )
        self._conn.commit()

    # -- reads -----------------------------------------------------------

    def balance(self, member_id: str) -> Balance:
        gb_hours = (
            self._conn.execute(
                "SELECT COALESCE(SUM(resident_gb * seconds), 0) / 3600.0 AS v"
                " FROM contributions WHERE owner = ?",
                (member_id,),
            ).fetchone()["v"]
            or 0.0
        )
        tokens = (
            self._conn.execute(
                "SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0) AS v"
                " FROM consumptions WHERE member_id = ?",
                (member_id,),
            ).fetchone()["v"]
            or 0
        )
        ktokens = tokens / 1000.0
        score = (gb_hours + _PRIOR_GB_HOURS) / (ktokens + _PRIOR_KTOKENS)
        return Balance(member_id, gb_hours, ktokens, score)

    def fair_share(self, member_ids: list[str]) -> dict[str, float]:
        """Priority score per member -- higher means served sooner.

        Contributors in surplus outrank heavy consumers. The smoothing priors
        mean a newcomer starts at 1.0 rather than at zero, so joining does not
        require earning credit before you may use the pool at all.
        """
        return {mid: self.balance(mid).score for mid in member_ids}

    def totals(self) -> dict[str, float]:
        contrib = self._conn.execute(
            "SELECT COALESCE(SUM(resident_gb * seconds), 0) / 3600.0 AS v FROM contributions"
        ).fetchone()["v"]
        tokens = self._conn.execute(
            "SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0) AS v FROM consumptions"
        ).fetchone()["v"]
        requests = self._conn.execute("SELECT COUNT(*) AS v FROM consumptions").fetchone()["v"]
        return {
            "gb_hours": float(contrib or 0.0),
            "tokens": int(tokens or 0),
            "requests": int(requests or 0),
        }
