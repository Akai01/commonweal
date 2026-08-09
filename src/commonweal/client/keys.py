"""Member identity: an Ed25519 signing key and an X25519 encryption key.

Two places to keep the secret halves, and the right one depends on the machine:

* **A `0600` file.** Portable, works everywhere, survives a headless server with
  no session bus. Readable by root, by anything running as you, and by whatever
  syncs your home directory to a cloud.
* **The OS keychain.** Encrypted at rest, unlocked by your login. Available on a
  desktop; usually *not* on the headless boxes that run peers and coordinators,
  which is why it is opt-in rather than the default.

So the file always exists and always holds the public block -- `commonweal whoami`
and the block you hand an admin must work without unlocking anything. What moves
into the keychain is only the two secrets.

A keyring failure is never resolved by quietly writing the secret to disk
instead: an operator who asked for the keychain and got a file would have a
weaker guarantee than they think they have.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey

from ..crypto import new_encryption_keypair, new_signing_keypair
from ..proto import b64, unb64

DEFAULT_IDENTITY_PATH = Path.home() / ".config" / "commonweal" / "identity.json"

# One entry per member id. Two identities sharing a member id would collide, but
# that is already meaningless -- a member id is what the roster resolves against.
KEYRING_SERVICE = "commonweal"

# Marker in the file where the secrets would otherwise sit.
_IN_KEYRING = "keyring"


class IdentityError(Exception):
    """Identity could not be stored or retrieved."""


def _keyring():
    """The `keyring` module, or None if it is not installed or has no backend.

    Absence is normal, not exceptional: `keyring` is an optional dependency and a
    headless server is a supported place to run this.
    """
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except ImportError:
        return None
    try:
        backend = keyring.get_keyring()
    except Exception:                      # a broken backend is an absent one
        return None
    if isinstance(backend, FailKeyring):
        return None
    return keyring


def keyring_available() -> bool:
    """True if this machine can actually store a secret in an OS keychain."""
    return _keyring() is not None


def keyring_backend_name() -> str:
    kr = _keyring()
    if kr is None:
        return "none"
    backend = kr.get_keyring()
    return f"{backend.__class__.__module__}.{backend.__class__.__name__}"


@dataclass
class Identity:
    member_id: str
    sign_seed: bytes
    sign_pub: bytes
    enc_priv: bytes
    enc_pub: bytes

    @property
    def signing_key(self) -> SigningKey:
        return SigningKey(self.sign_seed)

    def public_entry(self) -> dict:
        """The block to hand an admin when joining a federation."""
        return {
            "id": self.member_id,
            "sign_pub": b64(self.sign_pub),
            "enc_pub": b64(self.enc_pub),
        }

    @classmethod
    def generate(cls, member_id: str) -> Identity:
        sign_seed, sign_pub = new_signing_keypair()
        enc_priv, enc_pub = new_encryption_keypair()
        return cls(member_id, sign_seed, sign_pub, enc_priv, enc_pub)

    # -- storage ---------------------------------------------------------

    def _secret_blob(self) -> str:
        return json.dumps({"sign_seed": b64(self.sign_seed), "enc_priv": b64(self.enc_priv)})

    def save(self, path: str | Path = DEFAULT_IDENTITY_PATH, *, use_keyring: bool = False) -> Path:
        """Write the identity. Secrets go to the keychain only if asked for.

        The keychain write happens *before* the file is written, so a failure
        leaves nothing half-stored and nothing on disk claiming to be in a
        keychain it never reached.
        """
        path = Path(path)
        payload = {
            "member_id": self.member_id,
            "sign_pub": b64(self.sign_pub),
            "enc_pub": b64(self.enc_pub),
        }

        if use_keyring:
            kr = _keyring()
            if kr is None:
                raise IdentityError(
                    "no usable OS keychain on this machine (a headless server "
                    "usually has none). Install the optional dependency with "
                    "`pip install 'commonweal[keyring]'`, or omit --keyring to keep "
                    "the secrets in a 0600 file"
                )
            try:
                kr.set_password(KEYRING_SERVICE, self.member_id, self._secret_blob())
            except Exception as exc:
                raise IdentityError(f"could not write to the OS keychain: {exc}") from exc
            payload["secrets"] = _IN_KEYRING
        else:
            payload["sign_seed"] = b64(self.sign_seed)
            payload["enc_priv"] = b64(self.enc_priv)

        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create with restrictive mode from the start rather than chmod-ing
        # after: a world-readable window, however brief, is still a window. Kept
        # even for the keychain form, because a public block that anyone can
        # rewrite is a way to point a member at the wrong identity.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return path

    @classmethod
    def load(cls, path: str | Path = DEFAULT_IDENTITY_PATH) -> Identity:
        """Read an identity in either form. The file says which it is."""
        path = Path(path)
        doc = json.loads(path.read_text(encoding="utf-8"))
        member_id = doc["member_id"]

        if doc.get("secrets") == _IN_KEYRING:
            kr = _keyring()
            if kr is None:
                raise IdentityError(
                    f"{path} keeps its secrets in the OS keychain, but this machine "
                    f"has none available. Install `pip install 'commonweal[keyring]'`, or "
                    f"unlock the session that holds it"
                )
            blob = kr.get_password(KEYRING_SERVICE, member_id)
            if blob is None:
                raise IdentityError(
                    f"no keychain entry for member {member_id!r} under service "
                    f"{KEYRING_SERVICE!r}. The identity file survived but the secret "
                    f"did not; generate a new identity and ask an admin to re-add you"
                )
            secrets = json.loads(blob)
        else:
            secrets = doc

        return cls(
            member_id=member_id,
            sign_seed=unb64(secrets["sign_seed"]),
            sign_pub=unb64(doc["sign_pub"]),
            enc_priv=unb64(secrets["enc_priv"]),
            enc_pub=unb64(doc["enc_pub"]),
        )

    @classmethod
    def stored_in_keyring(cls, path: str | Path = DEFAULT_IDENTITY_PATH) -> bool:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        return doc.get("secrets") == _IN_KEYRING

    def migrate_to_keyring(self, path: str | Path = DEFAULT_IDENTITY_PATH) -> Path:
        """Move an on-disk identity's secrets into the keychain.

        Rewrites the file without them. The old bytes are still recoverable from
        the disk until it is overwritten -- this raises the floor, it does not
        erase history, and saying otherwise would be the kind of claim this
        project refuses to make.
        """
        return self.save(path, use_keyring=True)
