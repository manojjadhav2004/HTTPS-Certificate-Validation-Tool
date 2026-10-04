"""TLS connection helpers.

verified_handshake() is the real validation path: it uses a default SSL context
(certificate chain AND hostname verification stay ON).

fetch_for_inspection() exists only so a certificate can still be *displayed* after
the verified handshake was refused (expired, wrong host, unknown CA ...). Its result
is never used for the trust decision.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Optional


class NetworkError(Exception):
    """Connection-level problem (DNS, timeout, refused, TLS could not start)."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class HandshakeResult:
    verified: bool = False
    verify_code: Optional[int] = None
    verify_message: Optional[str] = None
    error: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    der: Optional[bytes] = None


def make_verified_context(ca_file: Optional[str] = None) -> ssl.SSLContext:
    """Default context: system trust store, chain + hostname verification enabled.
    A private CA file is *added* to the trust store (it does not replace it)."""
    context = ssl.create_default_context()
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    return context


def _open_socket(host: str, port: int, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror as exc:
        raise NetworkError("dns", f"Could not resolve host '{host}': {exc.strerror or exc}") from exc
    except TimeoutError as exc:
        raise NetworkError("timeout", f"Connection to {host}:{port} timed out after {timeout:g} seconds.") from exc
    except ConnectionRefusedError as exc:
        raise NetworkError("refused", f"Connection refused by {host}:{port} (nothing is listening on that port).") from exc
    except OSError as exc:
        raise NetworkError("network", f"Could not connect to {host}:{port}: {exc}") from exc


def verified_handshake(context: ssl.SSLContext, host: str, port: int, timeout: float) -> HandshakeResult:
    """TLS handshake with full verification. Verification failures are recorded in
    the result (not raised) so the individual checks can explain them."""
    sock = _open_socket(host, port, timeout)
    result = HandshakeResult()
    tls = None
    try:
        tls = context.wrap_socket(sock, server_hostname=host)
        result.verified = True
        result.tls_version = tls.version()
        cipher = tls.cipher()
        result.cipher = cipher[0] if cipher else None
        result.der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        result.verify_code = exc.verify_code
        result.verify_message = exc.verify_message
        result.error = str(exc)
    except ssl.SSLError as exc:
        result.error = str(exc)
    except TimeoutError as exc:
        raise NetworkError("timeout", f"TLS handshake with {host}:{port} timed out after {timeout:g} seconds.") from exc
    except OSError as exc:
        raise NetworkError("network", f"Connection to {host}:{port} failed during the TLS handshake: {exc}") from exc
    finally:
        try:
            (tls or sock).close()
        except OSError:
            pass
    return result


def fetch_for_inspection(host: str, port: int, timeout: float):
    """Fetch the server certificate WITHOUT trusting it, for display/analysis only.

    Never used for the trust decision: the trust verdict comes only from
    verified_handshake(). Returns (der_bytes, tls_version, cipher_name).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # inspection-only socket, see module docstring
    try:
        # let the weak-key lab certificate be read instead of being refused outright
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    sock = _open_socket(host, port, timeout)
    tls = None
    try:
        tls = context.wrap_socket(sock, server_hostname=host)
        cipher = tls.cipher()
        return tls.getpeercert(binary_form=True), tls.version(), (cipher[0] if cipher else None)
    except ssl.SSLError as exc:
        raise NetworkError("tls", f"TLS handshake with {host}:{port} failed: {exc}") from exc
    except TimeoutError as exc:
        raise NetworkError("timeout", f"TLS handshake with {host}:{port} timed out after {timeout:g} seconds.") from exc
    except OSError as exc:
        raise NetworkError("network", f"Connection to {host}:{port} failed during the TLS handshake: {exc}") from exc
    finally:
        try:
            (tls or sock).close()
        except OSError:
            pass
