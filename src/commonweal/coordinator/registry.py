"""Peer liveness and contribution credit.

Peers are declared in the signed roster; the registry tracks which of them are
actually *up* right now. A roster entry is a claim, a heartbeat is evidence.

Contribution is credited on heartbeat, measured as GB-hours of residency held.
That deliberately rewards committing memory rather than serving traffic: a peer
holding 62 GB resident all night has done the expensive and useful thing even
if no request happened to route to it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..ledger import Ledger
from ..roster import Peer, Roster, RosterError
from ..sanitise import sanitise_detail

# A missed heartbeat or two should not evict a peer mid-request; three should.
DEFAULT_HEARTBEAT_TIMEOUT = 90.0
# Guards against a peer that vanishes for hours then heartbeats once, claiming
# the whole gap as residency it may not have held.
MAX_CREDITED_INTERVAL = 300.0


@dataclass
class PeerState:
    peer_id: str
    last_seen: float
    resident_gb: float = 0.0
    in_flight: int = 0
    healthy: bool = True
    consecutive_failures: int = 0
    # What the peer said about its own readiness. Without this the coordinator
    # knows a peer is out but not why, and diagnosing a shard group means
    # curling every peer in it.
    detail: str = ""
    _last_credited: float = field(default=0.0, repr=False)


@dataclass
class Attestation:
    """One contributor saying "my share of this peer's memory is up, right now".

    A shard group's endpoint belongs to whoever runs the head, so the head is the
    only machine that can report *serving* liveness. But it is not the only
    machine contributing, and it cannot honestly speak for the others: an engine
    reports its own failure, not which member's box went away.

    So a declared contributor may beat for itself, signed with its own key. Two
    things fall out of that. Contribution stops being vouched-for by the head and
    becomes attested by the machine that is actually holding the memory. And a
    missing member is simply one whose attestations went stale -- which is the
    question `detail` could not answer, without putting any engine topology into
    the control plane.
    """

    member_id: str
    peer_id: str
    last_seen: float
    resident_gb: float = 0.0
    _last_credited: float = field(default=0.0, repr=False)


class Registry:
    def __init__(
        self,
        roster: Roster,
        ledger: Ledger,
        *,
        heartbeat_timeout: float = DEFAULT_HEARTBEAT_TIMEOUT,
        clock=time.monotonic,
    ):
        self.roster = roster
        self.ledger = ledger
        self.heartbeat_timeout = heartbeat_timeout
        self._clock = clock
        self._state: dict[str, PeerState] = {}
        self._attest: dict[tuple[str, str], Attestation] = {}

    # -- registration / liveness ----------------------------------------

    def _capped(self, peer: Peer, resident_gb: float) -> float:
        """Residency is self-reported; the roster is admin-signed. Trust the roster.

        Without this a peer can beat `resident_gb: 999999` and mint unbounded
        fair-share standing for itself. That matters more now that contribution
        is split across several members: over-reporting would inflate everyone
        the group names. A roster that declares no capacity gets no cap, which is
        a reason to declare one.
        """
        if peer.capacity_gb > 0 and resident_gb > peer.capacity_gb:
            return peer.capacity_gb
        return max(0.0, resident_gb)

    def heartbeat(
        self,
        peer_id: str,
        *,
        resident_gb: float = 0.0,
        healthy: bool = True,
        detail: str = "",
    ) -> None:
        """Record a peer as alive and credit residency since its last beat."""
        peer = self.roster.peer(peer_id)  # raises for peers not on the roster
        now = self._clock()
        resident_gb = self._capped(peer, resident_gb)
        detail = sanitise_detail(detail)
        state = self._state.get(peer_id)

        if state is None:
            self._state[peer_id] = PeerState(
                peer_id=peer_id, last_seen=now, resident_gb=resident_gb,
                healthy=healthy, detail=detail, _last_credited=now,
            )
            self._attest_owner(peer, resident_gb)
            return

        elapsed = min(now - state._last_credited, MAX_CREDITED_INTERVAL)
        # `state.healthy` is still the value the interval just ended was lived
        # under, which is the one that decides whether it is owed.
        creditable = elapsed > 0 and state.resident_gb > 0 and state.healthy
        if elapsed > 0:
            # One row per contributing member. A replicated peer splits to a
            # single row for its owner, so the ordinary case is unchanged.
            for member, share_gb in peer.credit_split(state.resident_gb):
                # A member attesting for itself is paid from its own beat, so
                # leave that interval to it -- otherwise the same memory is paid
                # for twice, once on the head's word and once on the member's.
                if self._attesting(peer_id, member, now):
                    continue
                if creditable:
                    self.ledger.record_contribution(
                        peer_id=peer_id, owner=member,
                        resident_gb=share_gb, seconds=elapsed,
                    )
                # Settle the interval whether or not anything was owed. The two
                # crediting paths must *partition* time, not overlap it: without
                # this, an outage would go unpaid here and then be billed in full
                # by the first attestation after recovery.
                self._mark_credited(peer_id, member, now)
        state.last_seen = now
        state._last_credited = now
        state.resident_gb = resident_gb
        state.healthy = healthy
        state.detail = detail
        if healthy:
            state.consecutive_failures = 0
        self._attest_owner(peer, resident_gb)

    def _attest_owner(self, peer: Peer, resident_gb: float) -> None:
        """The owner's beat also attests to the owner's own share, when it has one.

        Whoever runs the head usually contributes memory as well. Without this
        they would show as not attesting -- reading as "that member's machine is
        gone" for the one machine that is definitely still there. Recorded after
        the credit split, so the split skips them this round and their own
        attestation pays them instead: the same GB-hours either way, once.
        """
        if any(c.member == peer.owner for c in peer.contributors):
            self.attest(peer.id, peer.owner, resident_gb=resident_gb)

    # -- contributor self-attestation ------------------------------------

    def _attesting(self, peer_id: str, member_id: str, now: float) -> bool:
        att = self._attest.get((peer_id, member_id))
        return att is not None and (now - att.last_seen) <= self.heartbeat_timeout

    def _mark_credited(self, peer_id: str, member_id: str, now: float) -> None:
        """Note that this member's residency is paid for up to `now`.

        `last_seen` is untouched: being credited on the head's word is not the
        same as having said anything, and `contributors()` must keep reporting
        this member as not attesting.
        """
        att = self._attest.get((peer_id, member_id))
        if att is None:
            self._attest[(peer_id, member_id)] = Attestation(
                member_id=member_id, peer_id=peer_id, last_seen=0.0, _last_credited=now,
            )
        else:
            att._last_credited = now

    def attest(self, peer_id: str, member_id: str, *, resident_gb: float = 0.0) -> None:
        """Record a contributor holding its own share, and credit it for the gap.

        Deliberately does **not** touch peer liveness or routing. Only the head
        can say whether the group can serve; a contributor saying "my box is up"
        must never be able to keep a broken group in the pool -- that would let
        one member's daemon override the readiness probe of another's engine.

        The claim is capped at the share the admin-signed roster declares for
        this member, for the same reason peer residency is capped at
        `capacity_gb`: the roster is vouched for, the report is not.
        """
        peer = self.roster.peer(peer_id)
        declared = next((c.gb for c in peer.contributors if c.member == member_id), None)
        if declared is None:
            raise RosterError(
                f"member {member_id!r} is not a declared contributor to peer {peer_id!r}"
            )
        resident_gb = min(max(0.0, resident_gb), declared)

        now = self._clock()
        key = (peer_id, member_id)
        att = self._attest.get(key)
        if att is None:
            self._attest[key] = Attestation(
                member_id=member_id, peer_id=peer_id, last_seen=now,
                resident_gb=resident_gb, _last_credited=now,
            )
            return

        # A group that cannot serve credits nobody -- the same rule the head's own
        # beat follows, and the reason one member's outage is not billed to the
        # others. `_last_credited` still advances, so a down period cannot be
        # claimed later once the group comes back.
        serving = self._state.get(peer_id)
        elapsed = min(now - att._last_credited, MAX_CREDITED_INTERVAL)
        if elapsed > 0 and att.resident_gb > 0 and serving is not None and serving.healthy:
            self.ledger.record_contribution(
                peer_id=peer_id, owner=member_id,
                resident_gb=att.resident_gb, seconds=elapsed,
            )
        att.last_seen = now
        att._last_credited = now
        att.resident_gb = resident_gb

    def contributors(self, peer_id: str) -> list[dict]:
        """Per-member state for a shard group: who is attesting, and who stopped.

        This is the answer to "which member left", and it needed no knowledge of
        the engine's topology to get -- only of who said they were up.
        """
        peer = self.roster.peer(peer_id)
        now = self._clock()
        out = []
        for c in peer.contributors:
            att = self._attest.get((peer_id, c.member))
            out.append({
                "member": c.member,
                "declared_gb": c.gb,
                "attesting": self._attesting(peer_id, c.member, now),
                "resident_gb": att.resident_gb if att else 0.0,
                "last_seen_ago": round(now - att.last_seen, 1) if att else None,
            })
        return out

    def mark_failure(self, peer_id: str) -> None:
        """A relay to this peer failed. Two strikes and it stops being offered."""
        state = self._state.get(peer_id)
        if state is None:
            return
        state.consecutive_failures += 1
        if state.consecutive_failures >= 2:
            state.healthy = False
            state.detail = f"{state.consecutive_failures} consecutive relay failures"

    def is_live(self, peer_id: str) -> bool:
        state = self._state.get(peer_id)
        if state is None or not state.healthy:
            return False
        return (self._clock() - state.last_seen) <= self.heartbeat_timeout

    def live_peers(self, model: str | None = None) -> list[Peer]:
        peers = (
            self.roster.peers_for_model(model) if model else list(self.roster.peers.values())
        )
        return [p for p in peers if self.is_live(p.id)]

    # -- capacity --------------------------------------------------------

    def state(self, peer_id: str) -> PeerState:
        state = self._state.get(peer_id)
        if state is None:
            state = PeerState(peer_id=peer_id, last_seen=0.0, healthy=False)
            self._state[peer_id] = state
        return state

    def has_capacity(self, peer: Peer) -> bool:
        return self.is_live(peer.id) and self.state(peer.id).in_flight < peer.max_concurrent

    def acquire_slot(self, peer_id: str) -> None:
        self.state(peer_id).in_flight += 1

    def release_slot(self, peer_id: str) -> None:
        state = self.state(peer_id)
        state.in_flight = max(0, state.in_flight - 1)

    def snapshot(self) -> list[dict]:
        out = []
        for peer in self.roster.peers.values():
            st = self.state(peer.id)
            out.append({
                "peer_id": peer.id,
                "owner": peer.owner,
                "model": peer.model,
                "engine": peer.engine,
                "hw_class": peer.hw_class,
                "live": self.is_live(peer.id),
                # `live` says whether we will route here; `detail` says why not,
                # in the peer's own words.
                "detail": st.detail,
                "in_flight": st.in_flight,
                "max_concurrent": peer.max_concurrent,
                "resident_gb": st.resident_gb,
                "capacity_gb": peer.capacity_gb,
                # Who is actually being credited. A member should be able to see
                # that their machine is earning them standing without reading the
                # roster and the ledger side by side.
                "contributors": self.contributors(peer.id),
            })
        return out
