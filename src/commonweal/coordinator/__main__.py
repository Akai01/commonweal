"""Run the coordinator.

    commonweal-coordinator --roster roster.json --admin-key alice=<b64> --port 8080

Admin keys are supplied on the command line (or via config) and never read from
the roster document itself: a roster that vouched for its own signers would be
forgeable by anyone who could write one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from ..ledger import Ledger
from ..measure import ConcurrencyLog
from ..roster import Roster, RosterError
from ..tlsconfig import (
    TLSError,
    add_client_tls_args,
    add_server_tls_args,
    server_tls_kwargs,
    tls_from_args,
)
from .app import Coordinator, CoordinatorConfig, create_app


def _parse_admin_keys(pairs: list[str]) -> dict[str, str]:
    keys = {}
    for pair in pairs:
        member_id, _, pubkey = pair.partition("=")
        if not member_id or not pubkey:
            raise SystemExit(f"--admin-key expects member_id=BASE64, got {pair!r}")
        keys[member_id] = pubkey
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="commonweal-coordinator")
    parser.add_argument("--roster", required=True, help="path to the signed roster")
    parser.add_argument(
        "--admin-key", action="append", default=[], metavar="ID=BASE64",
        help="trusted admin public key, pinned out of band at join time (repeatable)",
    )
    parser.add_argument("--roster-version", type=int, default=None,
                        help="highest roster version already held; rejects rollback")
    parser.add_argument("--ledger", default="commonweal-ledger.db")
    parser.add_argument("--concurrency-log", default="commonweal-concurrency.db",
                        help="where to record observed concurrency samples, reported "
                             "by /v1/concurrency")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--max-queue", type=int, default=32)
    add_server_tls_args(parser)   # inbound HTTPS
    add_client_tls_args(parser)   # outbound relays to peers
    args = parser.parse_args(argv)

    try:
        ssl_kwargs = server_tls_kwargs(args)
        tls = tls_from_args(args)
    except TLSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.admin_key:
        print("error: at least one --admin-key is required to verify the roster",
              file=sys.stderr)
        return 1

    try:
        doc = json.loads(Path(args.roster).read_text(encoding="utf-8"))
        roster = Roster.load(
            doc,
            trusted_admin_keys=_parse_admin_keys(args.admin_key),
            previous_version=args.roster_version,
        )
    except (OSError, json.JSONDecodeError, RosterError) as exc:
        print(f"error: cannot load roster: {exc}", file=sys.stderr)
        return 1

    coordinator = Coordinator(
        roster,
        ledger=Ledger(args.ledger),
        concurrency=ConcurrencyLog(args.concurrency_log),
        config=CoordinatorConfig(max_queue=args.max_queue, tls=tls),
    )
    scheme = "https" if ssl_kwargs else "http"
    if not ssl_kwargs:
        print("warning: serving without TLS; the control plane is in clear", file=sys.stderr)
    print(
        f"commonweal coordinator: federation {roster.federation_id!r} "
        f"(roster v{roster.roster_version}, {len(roster.members)} members, "
        f"{len(roster.peers)} peers) on {scheme}://{args.host}:{args.port}"
    )
    uvicorn.run(
        create_app(coordinator), host=args.host, port=args.port,
        log_level="info", **ssl_kwargs,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
