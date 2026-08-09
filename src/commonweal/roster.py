"""The signed roster: who is in the federation, and what they run.

This is the trust anchor. Membership -- not cryptography -- is the privacy
boundary of a federation, so everything downstream (who may submit work, whose
peers may receive it, who is owed contribution credit) resolves against this
document.

Two rules matter more than the schema:

1. **Admin keys are supplied externally, never read from the document.** A
   roster that vouched for its own signers would let anyone forge one by
   including their own admin key. You pin the admin keys out of band when you
   join; that hand-off *is* the act of joining.

2. **Version must strictly increase.** Otherwise an attacker who holds an old
   copy can replay it to reinstate an expelled member.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import verify_bytes
from .proto import ProtocolError, canonical, check_version, unb64


class RosterError(Exception):
    """Roster is malformed, unsigned, untrusted, or stale."""


def _req(d: dict[str, Any], key: str, typ: type, where: str) -> Any:
    val = d.get(key)
    if not isinstance(val, typ) or isinstance(val, bool) and typ is int:
        raise RosterError(f"{where}: field {key!r} must be {typ.__name__}")
    return val


@dataclass(frozen=True)
class Member:
    id: str
    sign_pub: str  # base64 Ed25519 public key
    enc_pub: str   # base64 X25519 public key
    role: str = "member"
    joined: str = ""

    @property
    def sign_pub_bytes(self) -> bytes:
        return unb64(self.sign_pub)

    @property
    def enc_pub_bytes(self) -> bytes:
        return unb64(self.enc_pub)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Member:
        mid = _req(d, "id", str, "member")
        return cls(
            id=mid,
            sign_pub=_req(d, "sign_pub", str, f"member {mid}"),
            enc_pub=_req(d, "enc_pub", str, f"member {mid}"),
            role=d.get("role", "member"),
            joined=d.get("joined", ""),
        )


@dataclass(frozen=True)
class Contribution:
    """One member's share of the memory a peer holds resident.

    A replicated peer is one machine with one owner, so this is unnecessary. A
    **shard group** is not: six members can pool memory behind a single endpoint,
    and behind a single `owner`, which is whoever runs the head. Without a way to
    name the others, all the contribution credit goes to the head's owner and the
    five members who supplied the RAM earn nothing -- at which point contributing
    buys no standing and the incentive the ledger exists to create is gone.

    Declared here rather than reported by the peer because the roster is
    admin-signed: the split is something a person vouched for, not something the
    machine holding the head asserts about everyone else.
    """

    member: str
    gb: float

    @classmethod
    def from_dict(cls, d: dict[str, Any], where: str) -> Contribution:
        if not isinstance(d, dict):
            raise RosterError(f"{where}: each contributor must be an object")
        member = _req(d, "member", str, where)
        gb = d.get("gb")
        if not isinstance(gb, (int, float)) or isinstance(gb, bool) or gb <= 0:
            raise RosterError(
                f"{where}: contributor {member!r} needs a positive 'gb'; a zero share "
                f"earns nothing, which is a typo rather than an intent"
            )
        return cls(member=member, gb=float(gb))


@dataclass(frozen=True)
class Peer:
    """A machine -- or a shard group -- contributing capacity.

    `engine`/`engine_version`/`hw_class` exist because a heterogeneous
    federation cannot promise byte-identical output (see ARCHITECTURE §13).
    They are stamped onto every response so a user who sees two different
    answers can tell why.

    `max_concurrent` is the peer's batch capacity, published so the coordinator
    can dispatch concurrently instead of serialising -- batching is the largest
    performance lever available and it belongs to the engine, not to us.

    `contributors` is empty for the ordinary case of one machine owned by one
    member, and lists the split when several members pool memory behind one
    endpoint. `capacity_gb` is then the group's total and must agree with the
    shares: two numbers that should match and don't is the kind of quiet
    inconsistency this project would rather refuse at parse time.
    """

    id: str
    owner: str
    enc_pub: str
    endpoint: str
    model: str
    engine: str = "unknown"
    engine_version: str = "unknown"
    hw_class: str = "unknown"
    capacity_gb: float = 0.0
    max_concurrent: int = 1
    availability: str | None = None   # None == always; else free-form window
    shards: list[list[int]] = field(default_factory=list)  # [] == replicated
    attestation: str | None = None
    contributors: list[Contribution] = field(default_factory=list)  # [] == owner alone

    @property
    def enc_pub_bytes(self) -> bytes:
        return unb64(self.enc_pub)

    def credit_split(self, resident_gb: float) -> list[tuple[str, float]]:
        """Divide observed residency among the members who supplied it.

        The heartbeat is the *evidence* (how much is actually held right now) and
        the roster is the *split* (whose memory it is). So a group reporting less
        than it declared credits everyone proportionally less, which is the
        honest reading: the group is holding less. The case that would be unfair
        -- one member's machine gone, the rest still paying for it -- does not
        arise, because a shard group that loses a shard cannot serve, readiness
        fails, and an unhealthy peer is not credited at all.
        """
        if not self.contributors:
            return [(self.owner, resident_gb)]
        total = sum(c.gb for c in self.contributors)
        if total <= 0:                     # unreachable via from_dict; cheap to be sure
            return []
        return [(c.member, resident_gb * c.gb / total) for c in self.contributors]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Peer:
        pid = _req(d, "id", str, "peer")
        max_conc = d.get("max_concurrent", 1)
        if not isinstance(max_conc, int) or isinstance(max_conc, bool) or max_conc < 1:
            raise RosterError(f"peer {pid}: max_concurrent must be a positive int")

        raw = d.get("contributors") or []
        if not isinstance(raw, list):
            raise RosterError(f"peer {pid}: 'contributors' must be a list")
        contributors = [Contribution.from_dict(c, f"peer {pid}") for c in raw]
        seen = {c.member for c in contributors}
        if len(seen) != len(contributors):
            raise RosterError(f"peer {pid}: a member is listed twice in 'contributors'")

        declared = d.get("capacity_gb")
        if declared is not None and (
            isinstance(declared, bool) or not isinstance(declared, (int, float))
        ):
            # Otherwise `float("lots")` raises ValueError out of a parser whose
            # callers only catch RosterError, turning a bad roster into a
            # traceback instead of a message.
            raise RosterError(f"peer {pid}: capacity_gb must be a number")
        shares = sum(c.gb for c in contributors)
        if contributors and (declared is None or float(declared) == 0.0):
            capacity = shares            # derived, so admins need not write it twice
        else:
            capacity = float(declared or 0.0)
            if contributors and abs(capacity - shares) > 0.01:
                raise RosterError(
                    f"peer {pid}: capacity_gb is {capacity:g} but the contributor shares "
                    f"sum to {shares:g}; one of the two is wrong"
                )

        return cls(
            id=pid,
            owner=_req(d, "owner", str, f"peer {pid}"),
            enc_pub=_req(d, "enc_pub", str, f"peer {pid}"),
            endpoint=_req(d, "endpoint", str, f"peer {pid}"),
            model=_req(d, "model", str, f"peer {pid}"),
            engine=d.get("engine", "unknown"),
            engine_version=d.get("engine_version", "unknown"),
            hw_class=d.get("hw_class", "unknown"),
            capacity_gb=capacity,
            max_concurrent=max_conc,
            availability=d.get("availability"),
            shards=list(d.get("shards", [])),
            attestation=d.get("attestation"),
            contributors=contributors,
        )


@dataclass(frozen=True)
class Roster:
    federation_id: str
    roster_version: int
    updated: str
    admins: list[str]
    members: dict[str, Member]
    peers: dict[str, Peer]
    signatures: list[str]
    v: int = 1

    # -- lookups ---------------------------------------------------------

    def member(self, member_id: str) -> Member:
        try:
            return self.members[member_id]
        except KeyError:
            raise RosterError(f"unknown member {member_id!r}") from None

    def peer(self, peer_id: str) -> Peer:
        try:
            return self.peers[peer_id]
        except KeyError:
            raise RosterError(f"unknown peer {peer_id!r}") from None

    def peers_for_model(self, model: str) -> list[Peer]:
        return [p for p in self.peers.values() if p.model == model]

    # -- serialisation ---------------------------------------------------

    def signed_bytes(self) -> bytes:
        """Canonical bytes the admin signatures cover -- `signatures` excluded."""
        return canonical(self._body())

    def _body(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "federation_id": self.federation_id,
            "roster_version": self.roster_version,
            "updated": self.updated,
            "admins": sorted(self.admins),
            "members": [
                {
                    "id": m.id,
                    "sign_pub": m.sign_pub,
                    "enc_pub": m.enc_pub,
                    "role": m.role,
                    "joined": m.joined,
                }
                for m in sorted(self.members.values(), key=lambda m: m.id)
            ],
            "peers": [
                {
                    "id": p.id,
                    "owner": p.owner,
                    "enc_pub": p.enc_pub,
                    "endpoint": p.endpoint,
                    "model": p.model,
                    "engine": p.engine,
                    "engine_version": p.engine_version,
                    "hw_class": p.hw_class,
                    "capacity_gb": p.capacity_gb,
                    "max_concurrent": p.max_concurrent,
                    "availability": p.availability,
                    "shards": p.shards,
                    "attestation": p.attestation,
                    # Omitted when empty, unlike every other field here. These
                    # bytes are what admin signatures cover, so emitting a new
                    # key unconditionally would invalidate every roster signed
                    # before this field existed. An absent list and an empty one
                    # mean the same thing -- the owner contributed it all -- so
                    # there is no ambiguity to trade for that compatibility.
                    **(
                        {"contributors": [
                            {"member": c.member, "gb": c.gb} for c in p.contributors
                        ]}
                        if p.contributors else {}
                    ),
                }
                for p in sorted(self.peers.values(), key=lambda p: p.id)
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "signatures": list(self.signatures)}

    # -- loading ---------------------------------------------------------

    @classmethod
    def parse(cls, doc: dict[str, Any]) -> Roster:
        """Structural parse only. Does NOT verify signatures -- use `load`."""
        if not isinstance(doc, dict):
            raise RosterError("roster must be an object")
        try:
            check_version(doc.get("v"))
        except ProtocolError as exc:
            raise RosterError(str(exc)) from exc

        rv = doc.get("roster_version")
        if not isinstance(rv, int) or isinstance(rv, bool) or rv < 1:
            raise RosterError("roster_version must be a positive int")

        members = [Member.from_dict(m) for m in doc.get("members", [])]
        peers = [Peer.from_dict(p) for p in doc.get("peers", [])]
        by_member = {m.id: m for m in members}
        if len(by_member) != len(members):
            raise RosterError("duplicate member id")
        by_peer = {p.id: p for p in peers}
        if len(by_peer) != len(peers):
            raise RosterError("duplicate peer id")

        for p in peers:
            if p.owner not in by_member:
                raise RosterError(f"peer {p.id!r} owned by unknown member {p.owner!r}")
            for c in p.contributors:
                # Same rule as `owner`, and for the same reason: contribution
                # credit resolves against this document, so crediting a member
                # it does not list would put GB-hours somewhere unaccountable.
                if c.member not in by_member:
                    raise RosterError(
                        f"peer {p.id!r} credits unknown member {c.member!r}"
                    )

        admins = list(doc.get("admins", []))
        for a in admins:
            if a not in by_member:
                raise RosterError(f"admin {a!r} is not a member")
        if not admins:
            raise RosterError("roster has no admins")

        return cls(
            v=doc["v"],
            federation_id=_req(doc, "federation_id", str, "roster"),
            roster_version=rv,
            updated=doc.get("updated", ""),
            admins=admins,
            members=by_member,
            peers=by_peer,
            signatures=list(doc.get("signatures", [])),
        )

    @classmethod
    def load(
        cls,
        doc: dict[str, Any],
        *,
        trusted_admin_keys: dict[str, str],
        previous_version: int | None = None,
    ) -> Roster:
        """Parse and verify.

        `trusted_admin_keys` maps admin member id -> base64 Ed25519 public key,
        and comes from *local config pinned at join time*. It is deliberately
        not read from `doc`: a self-vouching roster is forgeable by anyone.

        `previous_version` is the highest version already held. A roster at or
        below it is rejected, which is what stops an old copy being replayed to
        reinstate an expelled member.
        """
        roster = cls.parse(doc)

        if previous_version is not None and roster.roster_version <= previous_version:
            raise RosterError(
                f"roster rollback refused: got version {roster.roster_version}, "
                f"already hold {previous_version}"
            )

        if not trusted_admin_keys:
            raise RosterError("no trusted admin keys configured; cannot verify roster")
        if not roster.signatures:
            raise RosterError("roster is unsigned")

        payload = roster.signed_bytes()
        for admin_id, pubkey_b64 in trusted_admin_keys.items():
            for sig in roster.signatures:
                try:
                    verify_bytes(payload, sig, unb64(pubkey_b64))
                except (ProtocolError, ValueError):
                    continue
                if admin_id not in roster.admins:
                    raise RosterError(
                        f"roster signed by {admin_id!r}, who it does not list as an admin"
                    )
                return roster

        raise RosterError("no signature from a trusted admin key")

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        trusted_admin_keys: dict[str, str],
        previous_version: int | None = None,
    ) -> Roster:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.load(
            doc,
            trusted_admin_keys=trusted_admin_keys,
            previous_version=previous_version,
        )
