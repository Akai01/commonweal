"""Generate a throwaway CA and server certificates for TLS tests.

Untested TLS is worse than no TLS: it looks like a security property and is
not one. These fixtures let the full federation run over real HTTPS, so the
certificate plumbing is exercised rather than merely written.

The certificates are RFC 5280-conformant rather than minimal, because the
minimum stopped verifying. Python 3.13 enables `ssl.VERIFY_X509_STRICT` by
default, and OpenSSL then rejects a chain whose leaf has no Authority Key
Identifier -- §4.2.1.1 requires one on every certificate that is not a
self-signed CA, and §4.2.1.2 requires a Subject Key Identifier on the CA.
Older defaults tolerated their absence; a fixture that only validates under
lenient settings is a fixture that will fail on someone else's machine.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

_EPOCH = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(directory: Path) -> tuple[Path, ed25519.Ed25519PrivateKey, x509.Certificate]:
    key = ed25519.Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("commonweal-test-ca"))
        .issuer_name(_name("commonweal-test-ca"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_EPOCH)
        .not_valid_after(_EPOCH + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            # What a CA is allowed to do. Without it, strict verification has to
            # infer the CA's authority from BasicConstraints alone.
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, None)
    )
    path = directory / "ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path, key, cert


def make_server_cert(
    directory: Path, name: str, ca_key, ca_cert
) -> tuple[Path, Path]:
    key = ed25519.Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_EPOCH)
        .not_valid_after(_EPOCH + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        # The extension whose absence broke CI: it names which key signed this
        # certificate, so a verifier can build the chain without guessing.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            # Both, because the same helper issues the mutual-TLS client
            # certificates; a serverAuth-only leaf would be refused as a client.
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(ca_key, None)
    )
    cert_path = directory / f"{name}.pem"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path
