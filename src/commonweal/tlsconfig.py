"""Transport security for every hop.

Payload sealing already protects request and response *content* from the
network and from the coordinator. TLS covers what sealing cannot: the control
plane (leases, heartbeats, roster fetches) travels in clear otherwise, and
without it traffic analysis is trivial for anyone on the path.

`insecure=True` exists for local development and is deliberately loud -- it is
the one setting here that silently downgrades a security property.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path


class TLSError(Exception):
    """TLS configuration is unusable."""


@dataclass(frozen=True)
class TLSConfig:
    """Client-side TLS settings, threaded into every outbound httpx call."""

    ca_bundle: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    insecure: bool = False

    def __post_init__(self) -> None:
        for label, path in (
            ("--ca-bundle", self.ca_bundle),
            ("--client-cert", self.client_cert),
            ("--client-key", self.client_key),
        ):
            if path and not Path(path).exists():
                raise TLSError(f"{label}: no such file: {path}")
        if self.client_cert and not self.client_key:
            raise TLSError("--client-cert requires --client-key")
        if self.client_key and not self.client_cert:
            raise TLSError("--client-key requires --client-cert")

    @property
    def cert(self) -> tuple[str, str] | None:
        """Our client certificate, for mutual TLS."""
        if self.client_cert and self.client_key:
            return (self.client_cert, self.client_key)
        return None

    def verify(self) -> bool | ssl.SSLContext:
        """What httpx should validate the server certificate against.

        Returns a real `SSLContext` rather than a path: httpx deprecated
        `verify=<str>`, and building the context here is also where a client
        certificate gets attached for mutual TLS.
        """
        if self.insecure:
            return False
        if not self.enabled:
            return True
        context = ssl.create_default_context(cafile=self.ca_bundle) if self.ca_bundle \
            else ssl.create_default_context()
        if self.cert is not None:
            context.load_cert_chain(self.client_cert, self.client_key)
        return context

    def httpx_kwargs(self) -> dict:
        return {"verify": self.verify()}

    @property
    def enabled(self) -> bool:
        return bool(self.ca_bundle or self.cert)


DEFAULT_TLS = TLSConfig()


def add_client_tls_args(parser) -> None:
    parser.add_argument("--ca-bundle", default=None,
                        help="CA bundle used to verify server certificates")
    parser.add_argument("--client-cert", default=None, help="client certificate (mutual TLS)")
    parser.add_argument("--client-key", default=None, help="client private key (mutual TLS)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip certificate verification (development only)")


def tls_from_args(args) -> TLSConfig:
    return TLSConfig(
        ca_bundle=getattr(args, "ca_bundle", None),
        client_cert=getattr(args, "client_cert", None),
        client_key=getattr(args, "client_key", None),
        insecure=getattr(args, "insecure", False),
    )


def add_server_tls_args(parser) -> None:
    parser.add_argument("--tls-cert", default=None, help="server certificate (enables HTTPS)")
    parser.add_argument("--tls-key", default=None, help="server private key")
    parser.add_argument("--tls-client-ca", default=None,
                        help="require and verify client certificates against this CA (mutual TLS)")


def server_tls_kwargs(args) -> dict:
    """uvicorn keyword arguments for the configured server-side TLS."""
    if not args.tls_cert and not args.tls_key:
        return {}
    if not (args.tls_cert and args.tls_key):
        raise TLSError("--tls-cert and --tls-key must be given together")
    for label, path in (("--tls-cert", args.tls_cert), ("--tls-key", args.tls_key)):
        if not Path(path).exists():
            raise TLSError(f"{label}: no such file: {path}")

    kwargs = {"ssl_certfile": args.tls_cert, "ssl_keyfile": args.tls_key}
    if args.tls_client_ca:
        if not Path(args.tls_client_ca).exists():
            raise TLSError(f"--tls-client-ca: no such file: {args.tls_client_ca}")
        kwargs["ssl_ca_certs"] = args.tls_client_ca
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    return kwargs
