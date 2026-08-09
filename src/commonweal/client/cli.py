"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from ..proto import b64
from ..tlsconfig import TLSError, add_client_tls_args, tls_from_args
from .client import CommonwealClient, ClientError
from .keys import (
    DEFAULT_IDENTITY_PATH,
    Identity,
    IdentityError,
    keyring_available,
    keyring_backend_name,
)


def _cmd_keygen(args) -> int:
    path = Path(args.identity)
    if path.exists() and not args.force:
        print(f"identity already exists at {path} (use --force to overwrite)", file=sys.stderr)
        return 1
    identity = Identity.generate(args.member_id)
    try:
        identity.save(path, use_keyring=args.keyring)
    except IdentityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.keyring:
        print(f"identity written to {path}")
        print(f"secret keys stored in the OS keychain ({keyring_backend_name()})\n")
    else:
        print(f"identity written to {path}")
        # The same class of statement as the TLS warning on the servers: say what
        # the weaker configuration actually costs, rather than letting a default
        # look like a decision.
        where = ("--keyring stores them in the OS keychain instead"
                 if keyring_available() else
                 "no OS keychain is available on this machine")
        print(f"warning: the secret keys are in that file in the clear; {where}\n",
              file=sys.stderr)
    print("Send this block to a federation admin to be added to the roster:\n")
    print(json.dumps(identity.public_entry(), indent=2))
    return 0


def _cmd_keyring_migrate(args) -> int:
    """Move an existing on-disk identity's secrets into the OS keychain."""
    path = Path(args.identity)
    try:
        if Identity.stored_in_keyring(path):
            print(f"{path} already keeps its secrets in the keychain", file=sys.stderr)
            return 0
        identity = Identity.load(path)
        identity.migrate_to_keyring(path)
    except (OSError, KeyError, ValueError, IdentityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"secrets moved into the OS keychain ({keyring_backend_name()})")
    print(f"{path} now holds only the public block")
    print(
        "note: the old bytes remain recoverable from the disk until it is "
        "overwritten — this raises the floor, it does not erase the past",
        file=sys.stderr,
    )
    return 0


def _cmd_whoami(args) -> int:
    identity = Identity.load(args.identity)
    print(json.dumps(identity.public_entry(), indent=2))
    return 0


def _cmd_roster_init(args) -> int:
    """Emit a draft roster for an admin to fill in and sign."""
    identity = Identity.load(args.identity)
    draft = {
        "v": 1,
        "federation_id": args.federation_id,
        "roster_version": 1,
        "updated": args.updated,
        "admins": [identity.member_id],
        "members": [{**identity.public_entry(), "role": "admin", "joined": args.updated}],
        "peers": [],
        "signatures": [],
    }
    Path(args.out).write_text(json.dumps(draft, indent=2) + "\n", encoding="utf-8")
    print(f"draft roster written to {args.out}")
    print("Add members and peers, bump roster_version, then: commonweal roster sign", file=sys.stderr)
    return 0


def _cmd_roster_sign(args) -> int:
    """Sign a roster draft with this identity's key.

    Signing is what makes a roster authoritative, so this is deliberately a
    separate, deliberate act rather than something that happens on edit.
    """
    from ..crypto import sign_bytes
    from ..roster import Roster, RosterError

    identity = Identity.load(args.identity)
    doc = json.loads(Path(args.roster).read_text(encoding="utf-8"))
    try:
        parsed = Roster.parse(doc)
    except RosterError as exc:
        print(f"error: roster is not well-formed: {exc}", file=sys.stderr)
        return 1
    if identity.member_id not in parsed.admins:
        print(
            f"error: {identity.member_id!r} is not listed in this roster's admins "
            f"({', '.join(parsed.admins)})",
            file=sys.stderr,
        )
        return 1

    doc = parsed.to_dict()
    doc["signatures"] = [sign_bytes(parsed.signed_bytes(), identity.signing_key)]
    Path(args.roster).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"signed roster v{parsed.roster_version} as {identity.member_id!r}")
    print(f"\nDistribute this admin key to members out of band:\n  {identity.member_id}={b64(identity.sign_pub)}")
    return 0


def _cmd_contribute(args) -> int:
    """Attest that this machine is holding its declared share of a peer's memory.

    For a member of a shard group who supplies RAM but does not run the endpoint.
    Without this, contribution is credited on the word of whoever runs the head,
    and a member who goes away is invisible to the coordinator -- an engine
    reports its own failure, not which machine stopped answering.

    Serves no inference and holds no engine. It signs one small statement on a
    timer, which is why it can be a subcommand rather than another daemon.
    """
    import asyncio

    from ..peer.heartbeat import send_heartbeat
    from ..roster import Roster, RosterError

    identity = Identity.load(args.identity)
    keys = {}
    for pair in args.admin_key:
        member_id, _, pubkey = pair.partition("=")
        if not member_id or not pubkey:
            print(f"error: --admin-key expects member_id=BASE64, got {pair!r}", file=sys.stderr)
            return 1
        keys[member_id] = pubkey
    if not keys:
        print("error: at least one --admin-key is required", file=sys.stderr)
        return 1

    try:
        doc = json.loads(Path(args.roster).read_text(encoding="utf-8"))
        roster = Roster.load(doc, trusted_admin_keys=keys)
        peer = roster.peer(args.peer_id)
        tls = tls_from_args(args)
    except (OSError, json.JSONDecodeError, RosterError, TLSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    declared = next((c.gb for c in peer.contributors if c.member == identity.member_id), None)
    if declared is None:
        named = ", ".join(c.member for c in peer.contributors) or "nobody"
        print(
            f"error: the roster does not list {identity.member_id!r} as a contributor to "
            f"{args.peer_id!r} (it lists {named}); an admin has to add you and re-sign",
            file=sys.stderr,
        )
        return 1
    if args.resident_gb > declared:
        print(
            f"warning: claiming {args.resident_gb:g} GB but the roster declares "
            f"{declared:g} for you; the coordinator will credit only the declared figure",
            file=sys.stderr,
        )

    print(
        f"attesting {min(args.resident_gb, declared):g} GB for peer {args.peer_id!r} "
        f"as {identity.member_id!r} every {args.interval:g}s -- Ctrl-C to stop"
    )

    async def run() -> int:
        beats, failures = 0, 0
        while True:
            ok = await send_heartbeat(
                args.coordinator,
                member_id=identity.member_id,
                peer_id=args.peer_id,
                signing_key=identity.signing_key,
                resident_gb=args.resident_gb,
                tls=tls,
            )
            beats += 1
            if ok:
                failures = 0
            else:
                failures += 1
                # Transient coordinator trouble should not stop a member earning;
                # say so and keep beating, and the coordinator's own timeout will
                # drop us if it is not transient.
                print(
                    f"warning: heartbeat {beats} was not accepted "
                    f"({failures} in a row); still attesting",
                    file=sys.stderr,
                )
            await asyncio.sleep(args.interval)

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        print("\nstopped attesting", file=sys.stderr)
        return 0


def _cmd_chat(args) -> int:
    identity = Identity.load(args.identity)
    try:
        client = CommonwealClient(args.coordinator, identity, tls=tls_from_args(args))
    except TLSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    prompt = args.prompt or sys.stdin.read()
    messages = [{"role": "user", "content": prompt}]

    def _warn_if_capped(finish_reason: str) -> None:
        """Say so when the token budget, not the model, ended the answer.

        Reasoning models make this the normal outcome at a modest `--max-tokens`,
        and an answer that stops mid-sentence looks identical to one that
        finished. Stderr, so pipelines keep a clean stdout.
        """
        if finish_reason == "length":
            print(
                f"warning: answer was cut off at --max-tokens {args.max_tokens}; "
                f"re-run with a larger budget for a complete one",
                file=sys.stderr,
            )

    async def run() -> int:
        try:
            if args.quiet:
                result = await client.complete(
                    messages, model=args.model, max_tokens=args.max_tokens,
                    temperature=args.temperature,
                )
                print(result.text)
                # Provenance on stderr so piping stdout stays clean while the
                # user can still see which machine answered -- necessary
                # because a heterogeneous federation cannot promise identical
                # output across peers.
                print(f"[served by {result.served_by()}]", file=sys.stderr)
                _warn_if_capped(result.finish_reason)
            else:
                finish_reason = ""
                async for tag, value in client.events(
                    messages, model=args.model, max_tokens=args.max_tokens,
                    temperature=args.temperature,
                ):
                    if tag == "text":
                        sys.stdout.write(value)
                        sys.stdout.flush()
                    elif tag == "receipt":
                        finish_reason = value.finish_reason
                sys.stdout.write("\n")
                sys.stdout.flush()   # so a piped warning cannot precede it
                _warn_if_capped(finish_reason)
            return 0
        except ClientError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="commonweal", description="Federated inference client")
    parser.add_argument("--identity", default=str(DEFAULT_IDENTITY_PATH))
    sub = parser.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="create a member identity")
    kg.add_argument("member_id")
    kg.add_argument("--force", action="store_true")
    kg.add_argument(
        "--keyring", action="store_true",
        help="store the secret keys in the OS keychain instead of the identity "
             "file. Needs `pip install 'commonweal[keyring]'` and a desktop session; "
             "headless servers usually have no keychain",
    )
    kg.set_defaults(func=_cmd_keygen)

    km = sub.add_parser(
        "keyring-migrate",
        help="move an existing identity's secrets into the OS keychain",
    )
    km.set_defaults(func=_cmd_keyring_migrate)

    wa = sub.add_parser("whoami", help="print this identity's public block")
    wa.set_defaults(func=_cmd_whoami)

    ro = sub.add_parser("roster", help="federation roster administration")
    ro_sub = ro.add_subparsers(dest="roster_command", required=True)

    ri = ro_sub.add_parser("init", help="write a draft roster naming you admin")
    ri.add_argument("federation_id")
    ri.add_argument("--out", default="roster.json")
    ri.add_argument("--updated", default="1970-01-01T00:00:00Z")
    ri.set_defaults(func=_cmd_roster_init)

    rs = ro_sub.add_parser("sign", help="sign a roster draft")
    rs.add_argument("roster")
    rs.set_defaults(func=_cmd_roster_sign)

    co = sub.add_parser(
        "contribute",
        help="attest that this machine holds its share of a shard group's memory",
    )
    co.add_argument("--roster", required=True)
    co.add_argument("--admin-key", action="append", default=[], metavar="ID=BASE64")
    co.add_argument("--peer-id", required=True, help="the shard group you contribute to")
    co.add_argument("--resident-gb", type=float, required=True)
    co.add_argument("--coordinator", default="http://127.0.0.1:8080")
    co.add_argument("--interval", type=float, default=30.0)
    add_client_tls_args(co)
    co.set_defaults(func=_cmd_contribute)

    ch = sub.add_parser("chat", help="send a prompt to the federation")
    ch.add_argument("prompt", nargs="?")
    ch.add_argument("--coordinator", default="http://127.0.0.1:8080")
    ch.add_argument("--model", required=True)
    ch.add_argument("--max-tokens", type=int, default=512)
    ch.add_argument("--temperature", type=float, default=0.7)
    ch.add_argument("-q", "--quiet", action="store_true", help="buffer output, show provenance")
    add_client_tls_args(ch)
    ch.set_defaults(func=_cmd_chat)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("run `commonweal keygen <member-id>` first", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
