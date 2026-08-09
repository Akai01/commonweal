"""Contribution credit when several members pool memory behind one endpoint.

A shard group has one endpoint, one `owner` -- whoever runs the head -- and up to
`n` members who supplied the RAM. Credited naively, the head's owner earns
everything and the other members earn nothing, at which point contributing buys
no standing and the ledger stops being an incentive. That accounting problem --
not cryptography -- was Phase B's actual design work.
"""

from __future__ import annotations

import pytest

import secrets
import time

import httpx

from commonweal.coordinator import Coordinator, create_app as create_coordinator
from commonweal.coordinator.auth import sign_request
from commonweal.coordinator.registry import MAX_CREDITED_INTERVAL, Registry
from commonweal.ledger import Ledger
from commonweal.roster import Roster, RosterError

from .conftest import Identity, build_roster
from .harness import free_port, serve

GROUP = [("alice", 128.0), ("bob", 128.0), ("carol", 64.0)]

# The registry refuses to credit more than this from one interval, so a peer that
# vanishes for hours and beats once cannot claim the whole gap. Expectations below
# are written in terms of it rather than around it.
BEAT = MAX_CREDITED_INTERVAL
HOURS = BEAT / 3600.0


def _entry(**over) -> dict:
    base = {
        "id": "lab-group", "owner": "alice", "enc_pub": "AA==",
        "endpoint": "http://127.0.0.1:9101", "model": "glm-5.2",
        "engine": "llama.cpp-rpc", "engine_version": "b10242", "hw_class": "pooled",
        "max_concurrent": 2,
    }
    return {**base, **over}


def _roster(entry: dict, members=("alice", "bob", "carol")) -> Roster:
    ids = {m: Identity(m) for m in members}
    entry = {**entry, "enc_pub": ids[entry["owner"]].enc_pub}
    doc = build_roster(ids, admins=["alice"], peers=[entry])
    # build_roster bypasses Peer.from_dict, so parse explicitly to get validation.
    return Roster.parse(Roster.parse(doc).to_dict())


def _registry(roster: Roster, clock) -> tuple[Registry, Ledger]:
    ledger = Ledger()
    return Registry(roster, ledger, clock=clock), ledger


# --- the split ----------------------------------------------------------

def test_credit_is_divided_by_declared_share():
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    peer = _roster(_entry(contributors=contributors)).peer("lab-group")

    split = dict(peer.credit_split(320.0))
    assert split == {"alice": 128.0, "bob": 128.0, "carol": 64.0}
    assert sum(split.values()) == pytest.approx(320.0)


def test_partial_residency_is_divided_proportionally():
    """The heartbeat is the evidence, the roster is the split. A group holding
    half of what it declared credits everyone half."""
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    peer = _roster(_entry(contributors=contributors)).peer("lab-group")

    split = dict(peer.credit_split(160.0))
    assert split == {"alice": 64.0, "bob": 64.0, "carol": 32.0}


def test_a_peer_without_contributors_credits_its_owner_alone():
    """The ordinary replicated case must be untouched."""
    peer = _roster(_entry(capacity_gb=128.0)).peer("lab-group")
    assert peer.credit_split(128.0) == [("alice", 128.0)]


async def test_every_member_of_a_group_earns_standing():
    """The point of all of this. Three members pool memory; all three end up with
    fair-share credit, not just the one running the head."""
    now = [1000.0]
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    roster = _roster(_entry(contributors=contributors))
    registry, ledger = _registry(roster, lambda: now[0])

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    now[0] += BEAT
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)

    assert ledger.balance("alice").gb_hours == pytest.approx(128.0 * HOURS)
    assert ledger.balance("bob").gb_hours == pytest.approx(128.0 * HOURS)
    assert ledger.balance("carol").gb_hours == pytest.approx(64.0 * HOURS)
    assert ledger.totals()["gb_hours"] == pytest.approx(320.0 * HOURS)

    # And it shows up as priority, which is the only thing credit is for.
    shares = ledger.fair_share(["alice", "bob", "carol"])
    assert shares["bob"] > 1.0, "a contributor must outrank a newcomer"
    assert shares["alice"] == pytest.approx(shares["bob"])
    assert shares["carol"] < shares["bob"]


async def test_group_that_cannot_serve_is_not_credited():
    """Readiness and accounting interlock: an unhealthy shard group earns nothing,
    which is what stops one member's outage from being billed to the others."""
    now = [1000.0]
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    registry, ledger = _registry(
        _roster(_entry(contributors=contributors)), lambda: now[0]
    )

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=False)
    now[0] += BEAT
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=False)

    assert ledger.totals()["gb_hours"] == pytest.approx(0.0)
    for member, _ in GROUP:
        assert ledger.balance(member).gb_hours == pytest.approx(0.0)


# --- self-reported residency is not trusted past the roster --------------

async def test_over_reported_residency_is_capped_at_declared_capacity():
    """Residency is self-reported and the roster is admin-signed, so the roster
    wins. Otherwise a peer beats `resident_gb: 999999` and mints standing."""
    now = [1000.0]
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    registry, ledger = _registry(
        _roster(_entry(contributors=contributors)), lambda: now[0]
    )

    registry.heartbeat("lab-group", resident_gb=999_999.0)
    now[0] += BEAT
    registry.heartbeat("lab-group", resident_gb=999_999.0)

    assert ledger.totals()["gb_hours"] == pytest.approx(320.0 * HOURS)
    assert registry.state("lab-group").resident_gb == pytest.approx(320.0)


async def test_no_declared_capacity_means_no_cap():
    """Documented consequence: declaring capacity is what buys the protection."""
    now = [1000.0]
    registry, ledger = _registry(_roster(_entry()), lambda: now[0])

    registry.heartbeat("lab-group", resident_gb=500.0)
    now[0] += BEAT
    registry.heartbeat("lab-group", resident_gb=500.0)

    assert ledger.balance("alice").gb_hours == pytest.approx(500.0 * HOURS)


async def test_negative_residency_is_floored():
    now = [1000.0]
    registry, ledger = _registry(_roster(_entry(capacity_gb=128.0)), lambda: now[0])
    registry.heartbeat("lab-group", resident_gb=-50.0)
    now[0] += BEAT
    registry.heartbeat("lab-group", resident_gb=-50.0)
    assert ledger.totals()["gb_hours"] == pytest.approx(0.0)


# --- self-attestation: a contributor speaking for itself ----------------
#
# The head runs the endpoint, so only the head can report whether the group can
# serve. It cannot honestly speak for the other members' machines, and an engine
# reports its own failure rather than which box went away. So contributors attest
# for themselves, and "which member left" becomes "whose attestations stopped".

def _group_registry(clock) -> tuple[Registry, Ledger, Roster]:
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    roster = _roster(_entry(contributors=contributors))
    ledger = Ledger()
    return Registry(roster, ledger, clock=clock), ledger, roster


async def test_attestation_credits_the_member_who_made_it():
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    registry.attest("lab-group", "carol", resident_gb=64.0)
    now[0] += BEAT
    registry.attest("lab-group", "carol", resident_gb=64.0)

    assert ledger.balance("carol").gb_hours == pytest.approx(64.0 * HOURS)
    # bob neither attested nor was credited by a second head beat.
    assert ledger.balance("bob").gb_hours == pytest.approx(0.0)


async def test_attestation_alone_earns_nothing_until_the_group_serves():
    """A contributor cannot earn on a group that has never been shown to serve.
    Committing memory to a pool nobody can reach is not a contribution yet."""
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    registry.attest("lab-group", "carol", resident_gb=64.0)
    now[0] += BEAT
    registry.attest("lab-group", "carol", resident_gb=64.0)

    assert ledger.balance("carol").gb_hours == pytest.approx(0.0)


async def test_attestation_cannot_make_a_broken_group_routable():
    """The load-bearing rule. One member's daemon must not be able to override
    another member's readiness probe -- otherwise a contributor could keep a dead
    shard group in the pool by simply staying online."""
    now = [1000.0]
    registry, _, _ = _group_registry(lambda: now[0])

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=False,
                       detail="inference probe failed")
    assert registry.is_live("lab-group") is False

    registry.attest("lab-group", "carol", resident_gb=64.0)
    registry.attest("lab-group", "bob", resident_gb=128.0)

    assert registry.is_live("lab-group") is False, "attesting must not restore routing"
    assert registry.state("lab-group").detail == "inference probe failed"


async def test_attested_share_is_not_also_credited_from_the_head():
    """The same memory must not be paid for twice -- once on the head's word and
    once on the member's own."""
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    registry.attest("lab-group", "carol", resident_gb=64.0)
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    now[0] += BEAT
    registry.attest("lab-group", "carol", resident_gb=64.0)
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)

    # carol is credited once, from her own attestation.
    assert ledger.balance("carol").gb_hours == pytest.approx(64.0 * HOURS)
    # alice and bob do not attest, so the head still vouches for them.
    assert ledger.balance("bob").gb_hours == pytest.approx(128.0 * HOURS)
    assert ledger.totals()["gb_hours"] == pytest.approx(320.0 * HOURS)


async def test_attestation_is_capped_at_the_declared_share():
    """Self-reported, so the admin-signed roster bounds it -- the same rule that
    caps a peer's residency at `capacity_gb`."""
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    registry.attest("lab-group", "carol", resident_gb=999_999.0)
    now[0] += BEAT
    registry.attest("lab-group", "carol", resident_gb=999_999.0)

    assert ledger.balance("carol").gb_hours == pytest.approx(64.0 * HOURS)


async def test_a_member_who_is_not_a_declared_contributor_cannot_attest():
    now = [1000.0]
    registry, _, _ = _group_registry(lambda: now[0])
    with pytest.raises(RosterError, match="not a declared contributor"):
        registry.attest("lab-group", "mallory", resident_gb=64.0)


async def test_contributor_status_names_who_stopped():
    """The question `detail` could not answer, obtained without the control plane
    knowing anything about the engine's topology."""
    now = [1000.0]
    registry, _, _ = _group_registry(lambda: now[0])

    for member, gb in GROUP:
        registry.attest("lab-group", member, resident_gb=gb)
    assert all(c["attesting"] for c in registry.contributors("lab-group"))

    # carol's machine goes away; the others keep beating.
    now[0] += registry.heartbeat_timeout + 1
    for member, gb in GROUP:
        if member != "carol":
            registry.attest("lab-group", member, resident_gb=gb)

    status = {c["member"]: c for c in registry.contributors("lab-group")}
    assert status["carol"]["attesting"] is False
    assert status["bob"]["attesting"] is True
    assert status["alice"]["attesting"] is True
    assert status["carol"]["last_seen_ago"] > registry.heartbeat_timeout


async def test_a_contributor_that_stops_attesting_falls_back_to_the_head():
    """Otherwise a member who shuts down their attestation daemon but leaves the
    memory committed would silently stop earning."""
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    registry.attest("lab-group", "carol", resident_gb=64.0)
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)

    now[0] += registry.heartbeat_timeout + 1        # carol's attestation goes stale
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)

    assert ledger.balance("carol").gb_hours > 0.0


async def test_an_outage_is_not_credited_and_is_not_claimable_afterwards():
    """A finished interval is credited with the health it had *during* it, so the
    beat that reports a break still pays for the good time before it. What must
    not happen is the outage itself being paid for -- then or retroactively once
    the group returns."""
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    def beat(healthy: bool) -> None:
        now[0] += BEAT
        registry.heartbeat("lab-group", resident_gb=320.0, healthy=healthy)
        registry.attest("lab-group", "carol", resident_gb=64.0)

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    beat(healthy=False)          # pays for the healthy interval that just ended
    baseline = ledger.totals()["gb_hours"]
    assert baseline > 0.0

    beat(healthy=False)          # this interval was down: nothing owed
    beat(healthy=True)           # still down at its start: nothing owed
    assert ledger.totals()["gb_hours"] == pytest.approx(baseline), (
        "the outage was billed"
    )

    beat(healthy=True)           # serving again, so crediting resumes
    assert ledger.totals()["gb_hours"] > baseline


async def test_resuming_attestation_does_not_re_bill_what_the_head_covered():
    """The head's split and a member's own attestation must partition time. If
    resuming picked up from the last attestation, the overlap would be paid twice."""
    now = [1000.0]
    registry, ledger, _ = _group_registry(lambda: now[0])

    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    registry.attest("lab-group", "carol", resident_gb=64.0)

    # carol's daemon stops; the head vouches for her for one interval.
    now[0] += registry.heartbeat_timeout + 1
    registry.heartbeat("lab-group", resident_gb=320.0, healthy=True)
    after_fallback = ledger.balance("carol").gb_hours
    assert after_fallback > 0.0

    # She resumes immediately. Nothing new is owed for the interval just paid.
    registry.attest("lab-group", "carol", resident_gb=64.0)
    assert ledger.balance("carol").gb_hours == pytest.approx(after_fallback)


def test_stats_snapshot_reports_contributor_liveness():
    now = [1000.0]
    registry, _, _ = _group_registry(lambda: now[0])
    registry.heartbeat("lab-group", resident_gb=320.0)
    registry.attest("lab-group", "bob", resident_gb=128.0)

    row = next(r for r in registry.snapshot() if r["peer_id"] == "lab-group")
    status = {c["member"]: c for c in row["contributors"]}
    assert status["bob"]["attesting"] is True
    assert status["carol"]["attesting"] is False
    assert status["carol"]["declared_gb"] == pytest.approx(64.0)


# --- validation ---------------------------------------------------------

def test_capacity_is_derived_from_the_shares_when_omitted():
    peer = _roster(_entry(contributors=[{"member": m, "gb": gb} for m, gb in GROUP]))
    assert peer.peer("lab-group").capacity_gb == pytest.approx(320.0)


def test_capacity_disagreeing_with_the_shares_is_refused():
    with pytest.raises(RosterError, match="sum to"):
        _roster(_entry(
            capacity_gb=999.0,
            contributors=[{"member": m, "gb": gb} for m, gb in GROUP],
        ))


def test_crediting_a_non_member_is_refused():
    """Same rule as `owner`: credit resolves against the roster, so a name it
    does not list would send GB-hours somewhere unaccountable."""
    with pytest.raises(RosterError, match="unknown member 'mallory'"):
        _roster(_entry(contributors=[{"member": "mallory", "gb": 128.0}]))


def test_zero_share_is_refused():
    with pytest.raises(RosterError, match="positive 'gb'"):
        _roster(_entry(contributors=[{"member": "bob", "gb": 0.0}]))


def test_duplicate_contributor_is_refused():
    with pytest.raises(RosterError, match="listed twice"):
        _roster(_entry(contributors=[
            {"member": "bob", "gb": 64.0}, {"member": "bob", "gb": 64.0},
        ]))


def test_a_non_numeric_capacity_is_a_roster_error_not_a_traceback():
    """Callers of the parser only catch RosterError, so a bad value has to arrive
    as one -- `commonweal roster sign` should print a message, not a stack trace."""
    with pytest.raises(RosterError, match="capacity_gb must be a number"):
        _roster(_entry(capacity_gb="lots"))
    with pytest.raises(RosterError, match="capacity_gb must be a number"):
        _roster(_entry(capacity_gb=True))


def test_contributors_must_be_a_list_of_objects():
    with pytest.raises(RosterError, match="must be a list"):
        _roster(_entry(contributors="alice"))
    with pytest.raises(RosterError, match="must be an object"):
        _roster(_entry(contributors=["alice"]))


# --- over the real endpoint ---------------------------------------------

async def test_the_heartbeat_endpoint_accepts_owner_and_contributor_differently():
    """One signed endpoint, two roles, decided by the roster rather than by a
    flag the caller sets."""
    ids = {m: Identity(m) for m in ("alice", "bob", "carol")}
    entry = {
        "id": "lab-group", "owner": "bob", "enc_pub": ids["bob"].enc_pub,
        "endpoint": "http://127.0.0.1:9101", "model": "glm-5.2",
        "engine": "llama.cpp-rpc", "engine_version": "b10242", "hw_class": "pooled",
        "max_concurrent": 2,
        "contributors": [{"member": m, "gb": gb} for m, gb in GROUP],
    }
    doc = build_roster(ids, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": ids["alice"].sign_pub})
    coordinator = Coordinator(roster, ledger=Ledger())

    async def beat(url, who: str, gb: float) -> httpx.Response:
        signed = sign_request(
            who, {"peer_id": "lab-group", "resident_gb": gb, "healthy": True},
            ids[who].signing_key, nonce=secrets.token_urlsafe(12), ts=time.time(),
        )
        async with httpx.AsyncClient(timeout=10) as c:
            return await c.post(f"{url}/v1/peers/heartbeat", json=signed)

    async with serve(create_coordinator(coordinator), free_port()) as url:
        owner = await beat(url, "bob", 320.0)
        assert owner.status_code == 200 and owner.json()["role"] == "owner"

        contributor = await beat(url, "carol", 64.0)
        assert contributor.status_code == 200
        assert contributor.json()["role"] == "contributor"

        # A member of the federation who is neither is refused, so being on the
        # roster is not by itself permission to speak for someone's hardware.
        stranger = Identity("mallory")
        ids["mallory"] = stranger
        refused = await beat(url, "mallory", 999.0)
        assert refused.status_code in (401, 403)

        status = {c["member"]: c for c in coordinator.registry.contributors("lab-group")}
        assert status["carol"]["attesting"] is True
        assert status["bob"]["attesting"] is True     # the owner contributes too
        assert status["alice"]["attesting"] is False


# --- signature compatibility --------------------------------------------

def test_a_roster_without_contributors_signs_exactly_as_before():
    """These bytes are what admin signatures cover. Emitting a new key for every
    peer would invalidate every roster signed before the field existed, so the
    key is omitted when empty -- an absent list and an empty one mean the same
    thing anyway."""
    doc = _roster(_entry(capacity_gb=128.0)).to_dict()
    assert "contributors" not in doc["peers"][0]


def test_contributors_survive_a_round_trip_and_are_covered_by_the_signature():
    contributors = [{"member": m, "gb": gb} for m, gb in GROUP]
    original = _roster(_entry(contributors=contributors))

    reparsed = Roster.parse(original.to_dict())
    assert [(c.member, c.gb) for c in reparsed.peer("lab-group").contributors] == GROUP
    assert reparsed.signed_bytes() == original.signed_bytes()

    # Inflating one member's share is caught before signatures even come up: it no
    # longer agrees with the declared capacity.
    tampered = original.to_dict()
    tampered["peers"][0]["contributors"][0]["gb"] = 512.0
    with pytest.raises(RosterError, match="sum to"):
        Roster.parse(tampered)

    # Adjust both to stay self-consistent and the change is still not free -- it
    # moves the bytes the admin signature covers.
    tampered["peers"][0]["capacity_gb"] = 704.0
    assert Roster.parse(tampered).signed_bytes() != original.signed_bytes()
