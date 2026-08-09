"""Sealing, unsealing, and identity signatures.

Construction: a fresh 32-byte master secret per request, sealed to one named
recipient with an X25519 sealed box; payload and response chunks encrypted with
AES-256-GCM under keys derived from that master.

Why hybrid rather than a bare sealed box: responses stream. A derived session
key lets every chunk be authenticated independently without asymmetric work per
chunk.

Why two derived keys: request and response must never share a (key, nonce)
pair. Deriving `req`/`resp` keys from one master makes that structural instead
of a convention someone can break later.

We do NOT implement primitives here -- PyNaCl is libsodium, `cryptography`
provides AES-NI-backed AES-GCM. Hand-rolled curve arithmetic is how projects
earn CVEs.
"""

from __future__ import annotations

import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.exceptions import CryptoError as NaClCryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from .proto import Envelope, ProtocolError, b64, unb64

MASTER_LEN = 32
NONCE_LEN = 12
_INFO_REQUEST = b"commonweal/v1/request"
_INFO_RESPONSE = b"commonweal/v1/response"


class SealError(Exception):
    """Decryption or authentication failed. Never recoverable -- abort."""


def _derive(master: bytes, info: bytes) -> bytes:
    if len(master) != MASTER_LEN:
        raise SealError(f"master secret must be {MASTER_LEN} bytes, got {len(master)}")
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(master)


def _chunk_nonce(seq: int) -> bytes:
    """Counter nonce: unique per key by construction, so no nonce is carried.

    A reordered or replayed chunk therefore fails authentication rather than
    decrypting to a plausible-looking result.
    """
    if seq < 0 or seq >= 1 << (8 * NONCE_LEN):
        raise SealError(f"chunk sequence {seq} out of range")
    return seq.to_bytes(NONCE_LEN, "big")


# --------------------------------------------------------------------------
# requests
# --------------------------------------------------------------------------

def seal_request(
    payload: bytes,
    recipient_enc_pub: bytes,
    *,
    request_id: str,
    sender: str,
    ts: float | None = None,
) -> tuple[Envelope, bytes]:
    """Seal `payload` to one recipient.

    Returns the envelope and the master secret, which the caller retains in
    order to open the response stream. `ts` defaults to now and ends up inside
    the signed bytes, which is what lets a recipient refuse a captured envelope
    replayed later.
    """
    master = secrets.token_bytes(MASTER_LEN)
    iv = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_derive(master, _INFO_REQUEST)).encrypt(iv, payload, None)
    sealed_key = SealedBox(PublicKey(recipient_enc_pub)).encrypt(master)
    envelope = Envelope(
        request_id=request_id,
        sealed_key=b64(sealed_key),
        iv=b64(iv),
        ciphertext=b64(ciphertext),
        sender=sender,
        ts=time.time() if ts is None else ts,
    )
    return envelope, master


def unseal_request(envelope: Envelope, recipient_enc_priv: PrivateKey) -> tuple[bytes, bytes]:
    """Open an envelope addressed to us. Returns (payload, master secret)."""
    try:
        master = SealedBox(recipient_enc_priv).decrypt(unb64(envelope.sealed_key))
    except (NaClCryptoError, ValueError) as exc:
        raise SealError("sealed key is not openable by this peer") from exc
    try:
        payload = AESGCM(_derive(master, _INFO_REQUEST)).decrypt(
            unb64(envelope.iv), unb64(envelope.ciphertext), None
        )
    except Exception as exc:  # cryptography raises InvalidTag
        raise SealError("request failed authentication") from exc
    return payload, master


# --------------------------------------------------------------------------
# streamed responses
# --------------------------------------------------------------------------

def seal_chunk(data: bytes, master: bytes, seq: int) -> str:
    key = _derive(master, _INFO_RESPONSE)
    return b64(AESGCM(key).encrypt(_chunk_nonce(seq), data, None))


def unseal_chunk(ciphertext: str, master: bytes, seq: int) -> bytes:
    key = _derive(master, _INFO_RESPONSE)
    try:
        return AESGCM(key).decrypt(_chunk_nonce(seq), unb64(ciphertext), None)
    except Exception as exc:
        raise SealError(f"response chunk {seq} failed authentication") from exc


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------

def sign_envelope(envelope: Envelope, signing_key: SigningKey) -> Envelope:
    sig = signing_key.sign(envelope.signed_bytes()).signature
    return Envelope(
        request_id=envelope.request_id,
        sealed_key=envelope.sealed_key,
        iv=envelope.iv,
        ciphertext=envelope.ciphertext,
        sender=envelope.sender,
        ts=envelope.ts,
        sig=b64(sig),
        v=envelope.v,
    )


def verify_envelope(envelope: Envelope, verify_key: bytes) -> None:
    """Raise unless `envelope` carries a valid signature from `verify_key`."""
    if envelope.sig is None:
        raise ProtocolError("envelope is unsigned")
    try:
        VerifyKey(verify_key).verify(envelope.signed_bytes(), unb64(envelope.sig))
    except (NaClCryptoError, ValueError) as exc:
        raise ProtocolError(f"bad signature from sender {envelope.sender!r}") from exc


def sign_bytes(payload: bytes, signing_key: SigningKey) -> str:
    return b64(signing_key.sign(payload).signature)


def verify_bytes(payload: bytes, sig: str, verify_key: bytes) -> None:
    try:
        VerifyKey(verify_key).verify(payload, unb64(sig))
    except (NaClCryptoError, ValueError) as exc:
        raise ProtocolError("bad signature") from exc


# --------------------------------------------------------------------------
# key generation
# --------------------------------------------------------------------------

def new_signing_keypair() -> tuple[bytes, bytes]:
    """(private seed, public key) for Ed25519 identity."""
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def new_encryption_keypair() -> tuple[bytes, bytes]:
    """(private, public) for X25519 sealed boxes."""
    sk = PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)
