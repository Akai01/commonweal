"""Run a peer.

    commonweal-peer --roster roster.json --admin-key alice=<b64> \\
                --identity ~/.config/commonweal/identity.json \\
                --peer-id bob-ws --coordinator http://coord:8080 \\
                --engine '{"kind":"openai","base_url":"http://localhost:30000/v1","model":"glm-5.2"}'

The engine is an external process. This daemon speaks HTTP to it and never
contains inference code.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn

from ..client.keys import Identity
from ..engines import build_engine
from ..roster import Roster, RosterError
from ..tlsconfig import (
    TLSError,
    add_client_tls_args,
    add_server_tls_args,
    server_tls_kwargs,
    tls_from_args,
)
from .app import Peer, PeerConfig, create_app
from .heartbeat import heartbeat_loop


def _parse_admin_keys(pairs: list[str]) -> dict[str, str]:
    keys = {}
    for pair in pairs:
        member_id, _, pubkey = pair.partition("=")
        if not member_id or not pubkey:
            raise SystemExit(f"--admin-key expects member_id=BASE64, got {pair!r}")
        keys[member_id] = pubkey
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="commonweal-peer")
    parser.add_argument("--roster", required=True)
    parser.add_argument("--admin-key", action="append", default=[], metavar="ID=BASE64")
    parser.add_argument("--identity", required=True, help="this member's identity.json")
    parser.add_argument("--peer-id", required=True)
    parser.add_argument("--coordinator", default=None,
                        help="coordinator URL; omit to run without heartbeats")
    parser.add_argument("--engine", default='{"kind":"mock"}',
                        help="engine spec as JSON")
    parser.add_argument("--resident-gb", type=float, default=0.0,
                        help="memory held resident, reported for contribution credit")
    parser.add_argument("--hw-class", default="unknown")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9101)
    parser.add_argument(
        "--readiness-window", type=float, default=60.0,
        help="seconds a recent successful request counts as proof of readiness, "
             "before the probe runs again (default: 60)",
    )
    parser.add_argument(
        "--probe-interval", type=float, default=15.0,
        help="minimum seconds between inference probes (default: 15)",
    )
    parser.add_argument(
        "--no-inference-probe", action="store_true",
        help="report readiness from the engine's liveness check alone. Cheaper, "
             "and unable to notice an engine that is listening but cannot serve",
    )
    add_server_tls_args(parser)   # inbound HTTPS from the coordinator
    add_client_tls_args(parser)   # outbound heartbeats
    args = parser.parse_args(argv)

    try:
        ssl_kwargs = server_tls_kwargs(args)
        tls = tls_from_args(args)
    except TLSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.admin_key:
        print("error: at least one --admin-key is required", file=sys.stderr)
        return 1

    try:
        doc = json.loads(Path(args.roster).read_text(encoding="utf-8"))
        roster = Roster.load(doc, trusted_admin_keys=_parse_admin_keys(args.admin_key))
        identity = Identity.load(args.identity)
        engine = build_engine(json.loads(args.engine))
        peer_entry = roster.peer(args.peer_id)
    except (OSError, json.JSONDecodeError, RosterError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if peer_entry.owner != identity.member_id:
        print(
            f"error: peer {args.peer_id!r} is owned by {peer_entry.owner!r}, "
            f"but this identity is {identity.member_id!r}",
            file=sys.stderr,
        )
        return 1

    # The roster is what the coordinator routes on, so a peer whose engine
    # serves something else silently answers for a model it does not run --
    # and every receipt it stamps is then a false provenance claim. Refuse:
    # this is local, certain, and a typo away at any time.
    if peer_entry.model != engine.model:
        print(
            f"error: the roster advertises model {peer_entry.model!r} for peer "
            f"{args.peer_id!r}, but this engine is configured for {engine.model!r}",
            file=sys.stderr,
        )
        return 1

    # The coordinator caps credited residency at the roster's declared capacity,
    # so an over-claim is silently trimmed there. Say so here, where the operator
    # who typed the number can still fix it.
    if peer_entry.capacity_gb > 0 and args.resident_gb > peer_entry.capacity_gb:
        print(
            f"warning: --resident-gb {args.resident_gb:g} exceeds the {peer_entry.capacity_gb:g} "
            f"the roster declares for {args.peer_id!r}; the coordinator will credit only "
            f"the declared figure",
            file=sys.stderr,
        )
    if peer_entry.contributors:
        split = ", ".join(f"{c.member} {c.gb:g} GB" for c in peer_entry.contributors)
        print(f"contribution credited to: {split}", file=sys.stderr)

    # Weaker check, hence a warning: some gateways do not enumerate everything
    # they can serve. But llama-server ignores the request's `model` field
    # entirely and answers with whatever it has loaded, so without this a
    # mismatch is invisible until someone compares outputs across peers.
    offered = asyncio.run(engine.models()) if hasattr(engine, "models") else []
    if offered and engine.model not in offered:
        print(
            f"warning: engine at this peer does not list {engine.model!r} "
            f"(it offers {', '.join(sorted(offered))}); responses may come from a "
            f"different model than the roster claims",
            file=sys.stderr,
        )

    peer = Peer(
        PeerConfig(
            peer_id=args.peer_id,
            hw_class=args.hw_class,
            readiness_window=args.readiness_window,
            probe_interval=args.probe_interval,
            inference_probe=not args.no_inference_probe,
        ),
        roster,
        engine,
        identity.enc_priv,
    )

    @asynccontextmanager
    async def lifespan(app):
        stop = asyncio.Event()
        task = None
        if args.coordinator:
            task = asyncio.create_task(
                heartbeat_loop(
                    args.coordinator,
                    member_id=identity.member_id,
                    peer_id=args.peer_id,
                    signing_key=identity.signing_key,
                    resident_gb=args.resident_gb,
                    readiness=peer.ready,   # the Readiness object, so its reason travels
                    stop=stop,
                    tls=tls,
                )
            )
        try:
            yield
        finally:
            stop.set()
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)

    app = create_app(peer)
    app.router.lifespan_context = lifespan

    scheme = "https" if ssl_kwargs else "http"
    if not ssl_kwargs:
        print("warning: serving without TLS; the control plane is in clear", file=sys.stderr)
    print(
        f"commonweal peer {args.peer_id!r} ({engine.name} {engine.version}, model "
        f"{engine.model}, hw {args.hw_class}) on {scheme}://{args.host}:{args.port}"
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", **ssl_kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
