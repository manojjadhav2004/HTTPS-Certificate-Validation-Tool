#!/usr/bin/env python3
"""Generates the private Root CA and all lab server certificates (pure Python, no openssl.exe needed).

    python lab/generate_certs.py            (creates missing/old files)
    python lab/generate_certs.py --force    (always recreate)

The private keys are written next to the certificates. They are for the lab only.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from lab.scenarios import SCENARIOS  # noqa: E402
from utils.paths import CERT_DIR  # noqa: E402

STALE_AFTER_DAYS = 5  # the near-expiry/expired certificates are relative to "now"


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CCS Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _key(bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _save(directory: Path, stem: str, cert: x509.Certificate, key=None) -> None:
    (directory / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        (directory / f"{stem}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))


def _make_root(now: datetime):
    key = _key(2048)
    name = _name("CCS Lab Root CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_server_cert(key, sans, not_before, not_after, issuer_cert=None, issuer_key=None):
    """Server certificate. If no issuer is given the certificate signs itself (self-signed)."""
    subject = _name(sans[0])
    issuer_name = issuer_cert.subject if issuer_cert else subject
    signing_key = issuer_key if issuer_key else key
    names = []
    for entry in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            names.append(x509.DNSName(entry))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def _needs_generation(directory: Path) -> bool:
    files = [directory / "root_ca.pem", directory / "root_ca.key"]
    for scenario in SCENARIOS:
        if scenario.serve:
            files += [directory / f"{scenario.cert_name}.pem", directory / f"{scenario.cert_name}.key"]
    if not all(f.is_file() for f in files):
        return True
    oldest = min(f.stat().st_mtime for f in files)
    return (time.time() - oldest) > STALE_AFTER_DAYS * 86400


def generate_all(force: bool = False, directory: Path = CERT_DIR, verbose: bool = False) -> bool:
    """Create the CA and all server certificates. Returns True if files were (re)created."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if not force and not _needs_generation(directory):
        return False

    now = datetime.now(timezone.utc)
    root_cert, root_key = _make_root(now)
    _save(directory, "root_ca", root_cert, root_key)

    local = ["localhost", "127.0.0.1", "::1"]
    day = timedelta(days=1)
    specs = {
        # name: (sans, key bits, not_before, not_after, signed_by_root)
        "valid": (local, 2048, now - day, now + 365 * day, True),
        "near_expiry": (local, 2048, now - 355 * day, now + 10 * day + timedelta(hours=12), True),
        "expired": (local, 2048, now - 400 * day, now - 5 * day, True),
        "wrong_hostname": (["wrong.example.com"], 2048, now - day, now + 365 * day, True),
        "self_signed": (local, 2048, now - day, now + 365 * day, False),
        "weak_rsa": (local, 1024, now - day, now + 365 * day, True),
    }
    for stem, (sans, bits, not_before, not_after, by_root) in specs.items():
        key = _key(bits)
        if by_root:
            cert = _make_server_cert(key, sans, not_before, not_after, root_cert, root_key)
        else:
            cert = _make_server_cert(key, sans, not_before, not_after)
        _save(directory, stem, cert, key)
        if verbose:
            print(f"  created {stem}.pem / {stem}.key  (RSA {bits}, SAN: {', '.join(sans)})")
    if verbose:
        print("  created root_ca.pem / root_ca.key")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the lab Root CA and test certificates.")
    parser.add_argument("--force", action="store_true", help="recreate everything even if files exist")
    args = parser.parse_args()
    print(f"Writing certificates to {CERT_DIR}")
    created = generate_all(force=args.force, verbose=True)
    print("Done." if created else "Certificates already exist and are recent. Use --force to recreate them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
