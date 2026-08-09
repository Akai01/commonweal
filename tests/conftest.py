"""Shared fixtures: a small federation with real keys."""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from commonweal.crypto import new_encryption_keypair, new_signing_keypair, sign_bytes
from commonweal.proto import b64
from commonweal.roster import Roster


class Identity:
    def __init__(self, member_id: str):
        self.id = member_id
        sign_seed, sign_pub = new_signing_keypair()
        enc_priv, enc_pub = new_encryption_keypair()
        self.signing_key = SigningKey(sign_seed)
        self.sign_pub = b64(sign_pub)
        self.enc_priv = enc_priv
        self.enc_pub = b64(enc_pub)


def build_roster(
    identities: dict[str, Identity],
    *,
    admins: list[str],
    peers: list[dict],
    version: int = 1,
    signers: list[Identity] | None = None,
) -> dict:
    body_source = Roster(
        federation_id="test-lab",
        roster_version=version,
        updated="2026-08-02T00:00:00Z",
        admins=admins,
        members={
            i.id: __import__("commonweal.roster", fromlist=["Member"]).Member(
                id=i.id, sign_pub=i.sign_pub, enc_pub=i.enc_pub
            )
            for i in identities.values()
        },
        peers={
            p["id"]: __import__("commonweal.roster", fromlist=["Peer"]).Peer.from_dict(p)
            for p in peers
        },
        signatures=[],
    )
    payload = body_source.signed_bytes()
    to_sign = signers if signers is not None else [identities[a] for a in admins]
    doc = body_source.to_dict()
    doc["signatures"] = [sign_bytes(payload, s.signing_key) for s in to_sign]
    return doc


@pytest.fixture
def alice() -> Identity:
    return Identity("alice")


@pytest.fixture
def bob() -> Identity:
    return Identity("bob")


@pytest.fixture
def peer_entry(bob: Identity) -> dict:
    return {
        "id": "bob-ws",
        "owner": "bob",
        "enc_pub": bob.enc_pub,
        "endpoint": "http://127.0.0.1:9101",
        "model": "mock-1b",
        "engine": "mock",
        "engine_version": "0",
        "hw_class": "test",
        "capacity_gb": 8.0,
        "max_concurrent": 4,
    }


@pytest.fixture
def federation(alice: Identity, bob: Identity, peer_entry: dict):
    """(roster_doc, trusted_admin_keys, identities)"""
    ids = {"alice": alice, "bob": bob}
    doc = build_roster(ids, admins=["alice"], peers=[peer_entry])
    return doc, {"alice": alice.sign_pub}, ids
