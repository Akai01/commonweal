import pytest

from commonweal.roster import Roster, RosterError

from .conftest import Identity, build_roster


def test_load_verified_roster(federation):
    doc, admin_keys, _ = federation
    roster = Roster.load(doc, trusted_admin_keys=admin_keys)
    assert roster.federation_id == "test-lab"
    assert roster.member("bob").id == "bob"
    assert roster.peer("bob-ws").max_concurrent == 4


def test_rollback_is_refused(federation):
    """An old roster must not be replayable -- otherwise anyone holding a stale
    copy can reinstate an expelled member."""
    doc, admin_keys, _ = federation
    with pytest.raises(RosterError, match="rollback refused"):
        Roster.load(doc, trusted_admin_keys=admin_keys, previous_version=5)


def test_same_version_is_refused(federation):
    doc, admin_keys, _ = federation
    with pytest.raises(RosterError, match="rollback refused"):
        Roster.load(doc, trusted_admin_keys=admin_keys, previous_version=1)


def test_newer_version_accepted(alice, bob, peer_entry):
    ids = {"alice": alice, "bob": bob}
    doc = build_roster(ids, admins=["alice"], peers=[peer_entry], version=9)
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub}, previous_version=8)
    assert roster.roster_version == 9


def test_unsigned_roster_refused(federation):
    doc, admin_keys, _ = federation
    doc["signatures"] = []
    with pytest.raises(RosterError, match="unsigned"):
        Roster.load(doc, trusted_admin_keys=admin_keys)


def test_signature_from_untrusted_key_refused(alice, bob, peer_entry):
    """Signed by a real key -- but not one we pinned at join time."""
    ids = {"alice": alice, "bob": bob}
    doc = build_roster(ids, admins=["alice"], peers=[peer_entry], signers=[bob])
    with pytest.raises(RosterError, match="no signature from a trusted admin"):
        Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})


def test_self_vouching_admin_is_forgery(bob, peer_entry):
    """The core forgery case: an attacker builds a roster naming themselves
    admin and signs it. It parses fine and is internally consistent -- and must
    still be refused, because admin keys come from local config, not the doc."""
    mallory = Identity("mallory")
    ids = {"mallory": mallory, "bob": bob}
    doc = build_roster(ids, admins=["mallory"], peers=[peer_entry])
    Roster.parse(doc)  # structurally valid
    with pytest.raises(RosterError, match="no signature from a trusted admin"):
        Roster.load(doc, trusted_admin_keys={"alice": Identity("alice").sign_pub})


def test_tampered_body_fails_verification(federation):
    doc, admin_keys, _ = federation
    doc["peers"][0]["endpoint"] = "http://attacker.example"
    with pytest.raises(RosterError, match="no signature from a trusted admin"):
        Roster.load(doc, trusted_admin_keys=admin_keys)


def test_added_member_fails_verification(federation, alice, bob):
    doc, admin_keys, _ = federation
    mallory = Identity("mallory")
    doc["members"].append(
        {"id": "mallory", "sign_pub": mallory.sign_pub, "enc_pub": mallory.enc_pub,
         "role": "member", "joined": ""}
    )
    with pytest.raises(RosterError, match="no signature from a trusted admin"):
        Roster.load(doc, trusted_admin_keys=admin_keys)


def test_no_trusted_keys_configured(federation):
    doc, _, _ = federation
    with pytest.raises(RosterError, match="no trusted admin keys"):
        Roster.load(doc, trusted_admin_keys={})


def test_peer_with_unknown_owner_refused(alice, bob, peer_entry):
    ids = {"alice": alice, "bob": bob}
    orphan = {**peer_entry, "id": "ghost-ws", "owner": "nobody"}
    doc = build_roster(ids, admins=["alice"], peers=[orphan])
    with pytest.raises(RosterError, match="unknown member 'nobody'"):
        Roster.parse(doc)


def test_admin_not_a_member_refused(alice, bob, peer_entry):
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[peer_entry])
    doc["admins"] = ["ghost"]
    with pytest.raises(RosterError, match="admin 'ghost' is not a member"):
        Roster.parse(doc)


def test_roster_with_no_admins_refused(alice, bob, peer_entry):
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[peer_entry])
    doc["admins"] = []
    with pytest.raises(RosterError, match="no admins"):
        Roster.parse(doc)


def test_signed_bytes_exclude_signatures(federation):
    doc, admin_keys, _ = federation
    roster = Roster.load(doc, trusted_admin_keys=admin_keys)
    assert b"signatures" not in roster.signed_bytes()


def test_roundtrip_preserves_verification(federation):
    doc, admin_keys, _ = federation
    roster = Roster.load(doc, trusted_admin_keys=admin_keys)
    again = Roster.load(roster.to_dict(), trusted_admin_keys=admin_keys)
    assert again.signed_bytes() == roster.signed_bytes()


def test_peers_for_model(federation):
    doc, admin_keys, _ = federation
    roster = Roster.load(doc, trusted_admin_keys=admin_keys)
    assert [p.id for p in roster.peers_for_model("mock-1b")] == ["bob-ws"]
    assert roster.peers_for_model("other") == []
