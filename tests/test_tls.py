"""The federation over real HTTPS, end to end.

Payload sealing already protects content. TLS covers what sealing cannot: the
control plane -- leases, heartbeats, roster fetches -- and traffic analysis.
These tests exist so that claim is verified rather than asserted.
"""

from __future__ import annotations

import secrets
import ssl
import time

import httpx
import pytest
import uvicorn

from commonweal.client import CommonwealClient, Identity as ClientIdentity
from commonweal.coordinator import Coordinator, create_app as create_coordinator
from commonweal.coordinator.app import CoordinatorConfig
from commonweal.coordinator.auth import sign_request
from commonweal.engines import MockEngine
from commonweal.ledger import Ledger
from commonweal.peer import Peer, PeerConfig, create_app as create_peer
from commonweal.roster import Roster
from commonweal.tlsconfig import TLSConfig, TLSError

from .certs import make_ca, make_server_cert
from .conftest import Identity, build_roster
from .harness import free_port


@pytest.fixture
def ca(tmp_path):
    ca_path, ca_key, ca_cert = make_ca(tmp_path)
    return ca_path, ca_key, ca_cert, tmp_path


# --- the fixtures themselves -------------------------------------------

def test_generated_chain_verifies_under_strict_x509(ca):
    """The test CA must satisfy RFC 5280, not merely the laxest verifier available.

    Python 3.13 turns on `ssl.VERIFY_X509_STRICT` by default and OpenSSL then
    refuses a leaf with no Authority Key Identifier. That broke CI on 3.13 while
    every 3.12 machine passed, which is the worst shape a fixture bug can take:
    invisible until it is someone else's problem. Forcing the flag here means any
    interpreter catches it.
    """
    ca_path, ca_key, ca_cert, tmp = ca
    cert, key = make_server_cert(tmp, "strict-check", ca_key, ca_cert)

    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.create_default_context(cafile=str(ca_path))
    client.verify_flags |= ssl.VERIFY_X509_STRICT

    s_in, s_out, c_in, c_out = (ssl.MemoryBIO() for _ in range(4))
    s = server.wrap_bio(s_in, s_out, server_side=True)
    c = client.wrap_bio(c_in, c_out, server_hostname="localhost")

    # Pump the handshake through the memory BIOs; no sockets, no ports.
    for _ in range(16):
        for obj, out, peer_in in ((c, c_out, s_in), (s, s_out, c_in)):
            try:
                obj.do_handshake()
            except ssl.SSLWantReadError:
                pass
            peer_in.write(out.read())
        if c.cipher() and s.cipher():
            break

    assert c.cipher() is not None, "strict verification rejected the generated chain"


# --- TLSConfig unit behaviour ------------------------------------------

def test_missing_ca_file_is_rejected():
    with pytest.raises(TLSError, match="no such file"):
        TLSConfig(ca_bundle="/nonexistent/ca.pem")


def test_client_cert_requires_key(ca):
    ca_path, ca_key, ca_cert, tmp = ca
    cert, _ = make_server_cert(tmp, "client", ca_key, ca_cert)
    with pytest.raises(TLSError, match="requires --client-key"):
        TLSConfig(client_cert=str(cert))


def test_verify_builds_context_from_ca_bundle(ca):
    ca_path, *_ = ca
    assert isinstance(TLSConfig(ca_bundle=str(ca_path)).verify(), ssl.SSLContext)
    # Unconfigured falls back to the system trust store, not to "no checking".
    assert TLSConfig().verify() is True


def test_insecure_disables_verification(ca):
    """The one setting here that downgrades a security property."""
    ca_path, *_ = ca
    assert TLSConfig(ca_bundle=str(ca_path), insecure=True).verify() is False


def test_client_cert_is_loaded_into_context(ca):
    ca_path, ca_key, ca_cert, tmp = ca
    cert, key = make_server_cert(tmp, "mtls-client", ca_key, ca_cert)
    cfg = TLSConfig(ca_bundle=str(ca_path), client_cert=str(cert), client_key=str(key))
    assert isinstance(cfg.verify(), ssl.SSLContext)
    assert cfg.enabled is True


# --- full federation over HTTPS ----------------------------------------

async def _serve_tls(app, port, certfile, keyfile):
    import asyncio

    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="error",
        ssl_certfile=str(certfile), ssl_keyfile=str(keyfile),
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(300):
        if server.started:
            break
        await asyncio.sleep(0.02)
    else:
        raise RuntimeError("TLS server did not start")
    return server, task


async def test_full_federation_over_https(ca):
    ca_path, ca_key, ca_cert, tmp = ca
    coord_cert, coord_key = make_server_cert(tmp, "coordinator", ca_key, ca_cert)
    peer_cert, peer_key = make_server_cert(tmp, "peer", ca_key, ca_cert)

    alice, bob = Identity("alice"), Identity("bob")
    peer_port, coord_port = free_port(), free_port()
    entry = {
        "id": "bob-ws", "owner": "bob", "enc_pub": bob.enc_pub,
        "endpoint": f"https://127.0.0.1:{peer_port}", "model": "mock-1b",
        "engine": "mock", "engine_version": "0", "hw_class": "tls-test",
        "capacity_gb": 8.0, "max_concurrent": 2,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})

    tls = TLSConfig(ca_bundle=str(ca_path))
    coordinator = Coordinator(roster, ledger=Ledger(), config=CoordinatorConfig(tls=tls))
    peer = Peer(PeerConfig("bob-ws", hw_class="tls-test"), roster, MockEngine(), bob.enc_priv)

    psrv, ptask = await _serve_tls(create_peer(peer), peer_port, peer_cert, peer_key)
    csrv, ctask = await _serve_tls(
        create_coordinator(coordinator), coord_port, coord_cert, coord_key
    )
    coord_url = f"https://127.0.0.1:{coord_port}"
    try:
        beat = sign_request(
            "bob", {"peer_id": "bob-ws", "resident_gb": 8.0, "healthy": True},
            bob.signing_key, nonce=secrets.token_urlsafe(12), ts=time.time(),
        )
        async with httpx.AsyncClient(timeout=10, **tls.httpx_kwargs()) as c:
            resp = await c.post(f"{coord_url}/v1/peers/heartbeat", json=beat)
        assert resp.status_code == 200

        client = CommonwealClient(
            coord_url,
            ClientIdentity(
                member_id="alice", sign_seed=bytes(alice.signing_key),
                sign_pub=bytes(alice.signing_key.verify_key),
                enc_priv=alice.enc_priv, enc_pub=b"",
            ),
            roster=roster,
            timeout=30.0,
            tls=tls,
        )
        result = await client.complete(
            [{"role": "user", "content": "over tls"}], model="mock-1b"
        )
        assert result.text
        assert result.hw_class == "tls-test"
        assert coordinator.ledger.totals()["requests"] == 1
    finally:
        for srv, task in ((csrv, ctask), (psrv, ptask)):
            srv.should_exit = True
            try:
                import asyncio
                await asyncio.wait_for(task, timeout=5)
            except (TimeoutError, Exception):
                task.cancel()


async def test_untrusted_certificate_is_refused(ca):
    """A server whose cert is not signed by our pinned CA must be rejected.

    Without this, --ca-bundle would be decorative."""
    ca_path, ca_key, ca_cert, tmp = ca
    rogue_dir = tmp / "rogue-ca"
    rogue_dir.mkdir()
    _, other_key, other_cert = make_ca(rogue_dir)
    srv_cert, srv_key = make_server_cert(rogue_dir, "rogue", other_key, other_cert)

    from commonweal.engines import MockEngine as _M
    alice, bob = Identity("alice"), Identity("bob")
    port = free_port()
    entry = {
        "id": "bob-ws", "owner": "bob", "enc_pub": bob.enc_pub,
        "endpoint": f"https://127.0.0.1:{port}", "model": "mock-1b",
        "engine": "mock", "engine_version": "0", "hw_class": "t",
        "capacity_gb": 1.0, "max_concurrent": 1,
    }
    doc = build_roster({"alice": alice, "bob": bob}, admins=["alice"], peers=[entry])
    roster = Roster.load(doc, trusted_admin_keys={"alice": alice.sign_pub})
    peer = Peer(PeerConfig("bob-ws"), roster, _M(), bob.enc_priv)

    srv, task = await _serve_tls(create_peer(peer), port, srv_cert, srv_key)
    try:
        # Verifying against the *original* CA must fail against this rogue cert.
        good = TLSConfig(ca_bundle=str(ca_path))
        with pytest.raises((httpx.ConnectError, ssl.SSLError, httpx.HTTPError)):
            async with httpx.AsyncClient(timeout=10, **good.httpx_kwargs()) as c:
                await c.get(f"https://127.0.0.1:{port}/health")
    finally:
        srv.should_exit = True
        try:
            import asyncio
            await asyncio.wait_for(task, timeout=5)
        except (TimeoutError, Exception):
            task.cancel()
