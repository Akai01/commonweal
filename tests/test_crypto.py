import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from commonweal.crypto import (
    SealError,
    new_encryption_keypair,
    new_signing_keypair,
    seal_chunk,
    seal_request,
    sign_envelope,
    unseal_chunk,
    unseal_request,
    verify_envelope,
)
from commonweal.proto import Envelope, ProtocolError, b64, unb64


def _peer():
    priv, pub = new_encryption_keypair()
    return PrivateKey(priv), pub


def test_seal_unseal_roundtrip():
    priv, pub = _peer()
    env, master = seal_request(b"hello world", pub, request_id="r1", sender="alice")
    payload, master2 = unseal_request(env, priv)
    assert payload == b"hello world"
    assert master2 == master


def test_envelope_carries_no_plaintext():
    priv, pub = _peer()
    secret = b"the launch code is 1234"
    env, _ = seal_request(secret, pub, request_id="r1", sender="alice")
    blob = repr(env.to_dict()).encode()
    assert secret not in blob
    assert b"launch" not in blob


def test_wrong_recipient_cannot_open():
    _, pub = _peer()
    other_priv, _ = _peer()
    env, _ = seal_request(b"secret", pub, request_id="r1", sender="alice")
    with pytest.raises(SealError, match="not openable"):
        unseal_request(env, other_priv)


def test_tampered_ciphertext_fails_authentication():
    priv, pub = _peer()
    env, _ = seal_request(b"secret", pub, request_id="r1", sender="alice")
    raw = bytearray(unb64(env.ciphertext))
    raw[0] ^= 0x01
    tampered = Envelope(**{**env.to_dict(), "ciphertext": b64(bytes(raw))})
    with pytest.raises(SealError, match="failed authentication"):
        unseal_request(tampered, priv)


def test_chunk_roundtrip_and_ordering():
    _, pub = _peer()
    _, master = seal_request(b"x", pub, request_id="r1", sender="alice")
    sealed = [seal_chunk(f"tok{i}".encode(), master, i) for i in range(4)]
    assert [unseal_chunk(c, master, i) for i, c in enumerate(sealed)] == [
        b"tok0",
        b"tok1",
        b"tok2",
        b"tok3",
    ]


def test_reordered_chunk_fails():
    """A counter nonce means a chunk decoded at the wrong position cannot
    authenticate -- reordering surfaces as an error, not as scrambled output."""
    _, pub = _peer()
    _, master = seal_request(b"x", pub, request_id="r1", sender="alice")
    c0 = seal_chunk(b"first", master, 0)
    with pytest.raises(SealError, match="chunk 1 failed"):
        unseal_chunk(c0, master, 1)


def test_request_and_response_keys_are_separated():
    """Request and response derive distinct keys, so a request ciphertext can
    never be replayed into the response stream."""
    priv, pub = _peer()
    env, master = seal_request(b"payload", pub, request_id="r1", sender="alice")
    with pytest.raises(SealError):
        unseal_chunk(env.ciphertext, master, 0)


def test_sign_and_verify():
    sk_seed, vk = new_signing_keypair()
    sk = SigningKey(sk_seed)
    _, pub = _peer()
    env, _ = seal_request(b"payload", pub, request_id="r1", sender="alice")
    signed = sign_envelope(env, sk)
    verify_envelope(signed, vk)


def test_signature_covers_ciphertext():
    sk_seed, vk = new_signing_keypair()
    sk = SigningKey(sk_seed)
    _, pub = _peer()
    env, _ = seal_request(b"payload", pub, request_id="r1", sender="alice")
    signed = sign_envelope(env, sk)
    swapped = Envelope(**{**signed.to_dict(), "ciphertext": b64(b"different")})
    with pytest.raises(ProtocolError, match="bad signature"):
        verify_envelope(swapped, vk)


def test_signature_from_other_member_rejected():
    sk_seed, _ = new_signing_keypair()
    _, other_vk = new_signing_keypair()
    _, pub = _peer()
    env, _ = seal_request(b"payload", pub, request_id="r1", sender="alice")
    signed = sign_envelope(env, SigningKey(sk_seed))
    with pytest.raises(ProtocolError, match="bad signature"):
        verify_envelope(signed, other_vk)


def test_unsigned_envelope_rejected():
    _, pub = _peer()
    env, _ = seal_request(b"payload", pub, request_id="r1", sender="alice")
    _, vk = new_signing_keypair()
    with pytest.raises(ProtocolError, match="unsigned"):
        verify_envelope(env, vk)
