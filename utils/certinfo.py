"""Reads fields out of an X.509 certificate using the 'cryptography' library."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from models import CertificateInfo

DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def load_certificate(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der)


def get_common_name(cert: x509.Certificate) -> Optional[str]:
    values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(values[0].value) if values else None


def get_san_values(cert: x509.Certificate) -> tuple[list, list]:
    """Return (dns_names, ip_address_strings) from the Subject Alternative Name."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):
        return [], []
    dns_names = list(ext.value.get_values_for_type(x509.DNSName))
    ips = [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    return dns_names, ips


def get_public_key_info(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        return "Unknown", None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, None


def get_signature_algorithm_name(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    return getattr(oid, "_name", None) or oid.dotted_string


def get_signature_hash_name(cert: x509.Certificate) -> Optional[str]:
    """'sha256', 'sha1', 'md5' ... or None (e.g. Ed25519 has no separate hash)."""
    try:
        algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return None
    return algorithm.name if algorithm is not None else None


def _format_serial(number: int) -> str:
    text = format(number, "X")
    if len(text) % 2:
        text = "0" + text
    return ":".join(text[i:i + 2] for i in range(0, len(text), 2))


def build_certificate_info(cert: x509.Certificate, now: datetime) -> CertificateInfo:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    dns_names, ips = get_san_values(cert)
    key_type, key_size = get_public_key_info(cert)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=_format_serial(cert.serial_number),
        valid_from=not_before.strftime(DATE_FORMAT),
        valid_until=not_after.strftime(DATE_FORMAT),
        days_remaining=int((not_after - now).total_seconds() / 86400),
        common_name=get_common_name(cert),
        subject_alt_names=[f"DNS:{d}" for d in dns_names] + [f"IP:{i}" for i in ips],
        public_key_type=key_type,
        public_key_size=key_size,
        signature_algorithm=get_signature_algorithm_name(cert),
        sha256_fingerprint=":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)),
    )


def _dns_match(host: str, pattern: str) -> bool:
    if "*" not in pattern:
        return host == pattern
    labels = pattern.split(".")
    # only a single, whole left-most label wildcard (*.example.com), never *.com
    if labels[0] != "*" or len(labels) < 3 or any("*" in label for label in labels[1:]):
        return False
    host_labels = host.split(".")
    return len(host_labels) == len(labels) and host_labels[1:] == labels[1:] and host_labels[0] != ""


def hostname_matches(host: str, dns_names: list, ip_names: list) -> Optional[str]:
    """Return the matching SAN entry (e.g. 'DNS:*.example.com') or None.
    The Common Name is deliberately ignored, like modern browsers do (RFC 6125)."""
    host = host.lower().rstrip(".")
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    if host_ip is not None:
        for entry in ip_names:
            try:
                if ipaddress.ip_address(entry) == host_ip:
                    return f"IP:{entry}"
            except ValueError:
                continue
        return None
    for pattern in dns_names:
        if _dns_match(host, pattern.lower().rstrip(".")):
            return f"DNS:{pattern}"
    return None
