"""Where a member's secret keys live, and what happens when that place is absent.

A `0600` file is readable by root, by anything running as you, and by whatever
syncs your home directory. The OS keychain is better. But peers and coordinators
run headless, where there is usually no keychain at all, so the feature has to
be optional and has to fail in a way that never quietly downgrades the guarantee
someone asked for.

These use a fake backend rather than the machine's real keychain: a test suite
that writes to your login keyring is a test suite with side effects, and one that
passes only on a desktop is worse than no test.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from commonweal.client import keys as keymod
from commonweal.client.keys import Identity, IdentityError


class FakeKeyring:
    """Stands in for the `keyring` module surface we actually use."""

    def __init__(self, *, backend_name: str = "fake.Keyring", fail_write: bool = False):
        self.store: dict[tuple[str, str], str] = {}
        self.fail_write = fail_write
        self._backend = type(backend_name, (), {})()

    def get_keyring(self):
        return self._backend

    def set_password(self, service: str, user: str, secret: str) -> None:
        if self.fail_write:
            raise RuntimeError("keychain is locked")
        self.store[(service, user)] = secret

    def get_password(self, service: str, user: str) -> str | None:
        return self.store.get((service, user))


@pytest.fixture
def fake_keyring(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setattr(keymod, "_keyring", lambda: kr)
    return kr


@pytest.fixture
def no_keyring(monkeypatch):
    monkeypatch.setattr(keymod, "_keyring", lambda: None)


# --- the file form, which must keep working -----------------------------

def test_file_identity_round_trips(tmp_path, no_keyring):
    path = tmp_path / "identity.json"
    original = Identity.generate("alice")
    original.save(path)

    loaded = Identity.load(path)
    assert loaded.member_id == "alice"
    assert loaded.sign_seed == original.sign_seed
    assert loaded.enc_priv == original.enc_priv
    assert Identity.stored_in_keyring(path) is False


def test_file_identity_is_created_mode_600(tmp_path, no_keyring):
    path = tmp_path / "identity.json"
    Identity.generate("alice").save(path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_an_identity_written_before_this_change_still_loads(tmp_path, no_keyring):
    """Backwards compatibility is the point: nobody should have to regenerate an
    identity and ask an admin to re-add them because storage changed."""
    original = Identity.generate("bob")
    legacy = {
        "member_id": "bob",
        "sign_seed": keymod.b64(original.sign_seed),
        "sign_pub": keymod.b64(original.sign_pub),
        "enc_priv": keymod.b64(original.enc_priv),
        "enc_pub": keymod.b64(original.enc_pub),
    }
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(legacy))

    loaded = Identity.load(path)
    assert loaded.sign_seed == original.sign_seed
    assert loaded.enc_priv == original.enc_priv


# --- the keychain form --------------------------------------------------

def test_keyring_identity_round_trips(tmp_path, fake_keyring):
    path = tmp_path / "identity.json"
    original = Identity.generate("carol")
    original.save(path, use_keyring=True)

    assert Identity.stored_in_keyring(path) is True
    loaded = Identity.load(path)
    assert loaded.sign_seed == original.sign_seed
    assert loaded.enc_priv == original.enc_priv


def test_no_secret_material_is_left_in_the_file(tmp_path, fake_keyring):
    """The whole point. If the secrets are still on disk, nothing was gained."""
    path = tmp_path / "identity.json"
    identity = Identity.generate("carol")
    identity.save(path, use_keyring=True)

    raw = path.read_text()
    assert keymod.b64(identity.sign_seed) not in raw
    assert keymod.b64(identity.enc_priv) not in raw
    # ...and the public block is still there, so `whoami` and joining still work
    # without unlocking anything.
    doc = json.loads(raw)
    assert doc["sign_pub"] and doc["enc_pub"] and doc["member_id"] == "carol"
    assert "sign_seed" not in doc and "enc_priv" not in doc


def test_the_public_file_is_still_mode_600(tmp_path, fake_keyring):
    """It holds no secret, but a public block anyone can rewrite is a way to
    point a member at an identity that is not theirs."""
    path = tmp_path / "identity.json"
    Identity.generate("carol").save(path, use_keyring=True)
    assert oct(path.stat().st_mode & 0o777) == "0o600"


# --- failure must never downgrade silently ------------------------------

def test_asking_for_a_keychain_that_does_not_exist_is_an_error(tmp_path, no_keyring):
    """Not a fallback to the file. Someone who asked for the keychain and got a
    0600 file would believe they had a guarantee they do not have."""
    path = tmp_path / "identity.json"
    with pytest.raises(IdentityError, match="no usable OS keychain"):
        Identity.generate("dave").save(path, use_keyring=True)
    assert not path.exists(), "nothing should be written when the request failed"


def test_a_failing_keychain_write_leaves_no_file(tmp_path, monkeypatch):
    kr = FakeKeyring(fail_write=True)
    monkeypatch.setattr(keymod, "_keyring", lambda: kr)
    path = tmp_path / "identity.json"
    with pytest.raises(IdentityError, match="could not write to the OS keychain"):
        Identity.generate("dave").save(path, use_keyring=True)
    assert not path.exists()


def test_loading_a_keychain_identity_without_a_keychain_explains_itself(tmp_path, fake_keyring, monkeypatch):
    path = tmp_path / "identity.json"
    Identity.generate("erin").save(path, use_keyring=True)

    monkeypatch.setattr(keymod, "_keyring", lambda: None)
    with pytest.raises(IdentityError, match="keeps its secrets in the OS keychain"):
        Identity.load(path)


def test_a_missing_keychain_entry_is_not_mistaken_for_a_corrupt_file(tmp_path, fake_keyring):
    """The file survived a backup and the secret did not -- a real way to lose a
    key. Say that, rather than raising a JSON error about the file."""
    path = tmp_path / "identity.json"
    Identity.generate("erin").save(path, use_keyring=True)
    fake_keyring.store.clear()

    with pytest.raises(IdentityError, match="no keychain entry for member 'erin'"):
        Identity.load(path)


# --- migration ----------------------------------------------------------

def test_migration_moves_the_secrets_and_keeps_the_identity_usable(tmp_path, fake_keyring):
    path = tmp_path / "identity.json"
    original = Identity.generate("frank")
    original.save(path)                       # the old way
    assert keymod.b64(original.sign_seed) in path.read_text()

    Identity.load(path).migrate_to_keyring(path)

    assert keymod.b64(original.sign_seed) not in path.read_text()
    reloaded = Identity.load(path)
    assert reloaded.sign_seed == original.sign_seed
    assert reloaded.enc_priv == original.enc_priv
    # Same identity: the roster entry an admin already holds is still valid.
    assert reloaded.public_entry() == original.public_entry()


# --- detection ----------------------------------------------------------

def test_a_broken_backend_counts_as_no_backend(monkeypatch):
    """`keyring` installed but unusable is the common headless case, and it must
    not raise out of a availability check."""
    fake = types.ModuleType("keyring")

    def explode():
        raise RuntimeError("no D-Bus session")

    fake.get_keyring = explode
    fail_mod = types.ModuleType("keyring.backends.fail")
    fail_mod.Keyring = type("Keyring", (), {})
    monkeypatch.setitem(sys.modules, "keyring", fake)
    monkeypatch.setitem(sys.modules, "keyring.backends.fail", fail_mod)

    assert keymod._keyring() is None
    assert keymod.keyring_available() is False
    assert keymod.keyring_backend_name() == "none"


def test_availability_is_false_when_keyring_is_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)   # import raises
    assert keymod.keyring_available() is False
