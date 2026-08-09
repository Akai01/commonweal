import pytest

from commonweal.proto import Chunk, Envelope, ProtocolError, Receipt, canonical, check_version


def test_canonical_is_key_order_independent():
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})


def test_canonical_is_utf8_not_escaped():
    assert "ü".encode() in canonical({"k": "ü"})


def test_canonical_rejects_nan():
    with pytest.raises(ValueError):
        canonical({"k": float("nan")})


def test_version_rejects_unknown():
    with pytest.raises(ProtocolError, match="unsupported protocol version"):
        check_version(999)


def test_version_rejects_bool():
    """`True` is an int in Python; it must not pass as version 1."""
    with pytest.raises(ProtocolError, match="must be an int"):
        check_version(True)


def _envelope_dict(**over):
    base = {
        "v": 1,
        "request_id": "r1",
        "sealed_key": "AA==",
        "iv": "AA==",
        "ciphertext": "AA==",
        "sender": "alice",
        "ts": 1785000000.0,
    }
    return {**base, **over}


def test_envelope_roundtrip():
    env = Envelope.from_dict(_envelope_dict())
    assert Envelope.from_dict(env.to_dict()) == env


def test_envelope_signed_bytes_exclude_sig():
    unsigned = Envelope.from_dict(_envelope_dict())
    signed = Envelope.from_dict(_envelope_dict(sig="ZZZZ"))
    assert unsigned.signed_bytes() == signed.signed_bytes()


def test_envelope_rejects_missing_field():
    d = _envelope_dict()
    del d["sender"]
    with pytest.raises(ProtocolError, match="'sender'"):
        Envelope.from_dict(d)


def test_envelope_rejects_empty_field():
    with pytest.raises(ProtocolError, match="'request_id'"):
        Envelope.from_dict(_envelope_dict(request_id=""))


def test_envelope_omits_sig_when_absent():
    assert "sig" not in Envelope.from_dict(_envelope_dict()).to_dict()


def test_envelope_rejects_missing_ts():
    """An envelope without a signed clock would be replayable forever."""
    d = _envelope_dict()
    del d["ts"]
    with pytest.raises(ProtocolError, match="'ts'"):
        Envelope.from_dict(d)


def test_envelope_rejects_bool_ts():
    with pytest.raises(ProtocolError, match="'ts'"):
        Envelope.from_dict(_envelope_dict(ts=True))


def test_envelope_ts_is_signed():
    """`ts` must be inside the signed bytes -- otherwise a relay could refresh
    a captured envelope's clock and replay it as new."""
    early = Envelope.from_dict(_envelope_dict(ts=1785000000.0))
    late = Envelope.from_dict(_envelope_dict(ts=1785000001.0))
    assert early.signed_bytes() != late.signed_bytes()


def test_envelope_keeps_int_ts_unconverted():
    """Coercing an int `ts` to float would change its canonical encoding and
    invalidate the sender's signature."""
    env = Envelope.from_dict(_envelope_dict(ts=1785000000))
    assert env.to_dict()["ts"] == 1785000000
    assert isinstance(env.to_dict()["ts"], int)


def test_chunk_roundtrip():
    c = Chunk.from_dict({"v": 1, "request_id": "r1", "seq": 3, "ciphertext": "AA==", "final": True})
    assert c.seq == 3 and c.final is True
    assert Chunk.from_dict(c.to_dict()) == c


def test_chunk_rejects_negative_seq():
    with pytest.raises(ProtocolError, match="'seq'"):
        Chunk.from_dict({"v": 1, "request_id": "r1", "seq": -1, "ciphertext": "AA=="})


def test_receipt_roundtrip():
    r = Receipt.from_dict({
        "v": 1, "request_id": "r1", "prompt_tokens": 11, "completion_tokens": 7,
        "engine": "llama.cpp", "engine_version": "b10242", "hw_class": "cpu",
        "finish_reason": "length",
    })
    assert r.finish_reason == "length"
    assert Receipt.from_dict(r.to_dict()) == r


def test_receipt_from_an_older_peer_still_parses():
    """A peer running an older build omits fields a newer client knows about.

    The counts are what the ledger needs, so an absent `finish_reason` must
    degrade to "unknown" rather than refuse the frame -- members upgrade on
    their own schedule.
    """
    r = Receipt.from_dict({
        "v": 1, "request_id": "r1", "prompt_tokens": 11, "completion_tokens": 7,
    })
    assert r.finish_reason == ""
    assert r.completion_tokens == 7


def test_receipt_ignores_a_non_string_finish_reason():
    r = Receipt.from_dict({"v": 1, "request_id": "r1", "finish_reason": 17})
    assert r.finish_reason == ""


def test_receipt_rejects_negative_counts():
    with pytest.raises(ProtocolError, match="'completion_tokens'"):
        Receipt.from_dict({"v": 1, "request_id": "r1", "completion_tokens": -1})
