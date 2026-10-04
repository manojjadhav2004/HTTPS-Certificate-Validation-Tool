"""The seven independent security checks and the final verdict logic."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

from models import FAIL, NOT_SECURE, PASS, SECURE, WARN, WARNING, CertificateInfo, CheckResult
from utils.certinfo import (
    DATE_FORMAT,
    get_public_key_info,
    get_san_values,
    get_signature_algorithm_name,
    get_signature_hash_name,
    hostname_matches,
)
from utils.connection import HandshakeResult

EXPIRY_WARNING_DAYS = 30

# OpenSSL X509_V_ERR_* codes we care about
TIME_CODES = {9, 10}  # not yet valid, expired
NAME_CODES = {62, 63, 64}  # hostname / email / IP mismatch
WEAK_CODES = {66, 67, 68}  # key too small / digest too weak for the security level
UNTRUSTED_TEXT = {
    18: "the server's certificate is self-signed and not in the trust store",
    19: "a self-signed root in the chain is not in the trust store",
    20: "the issuing CA is not in the trust store (unknown CA)",
    21: "the certificate signature could not be verified (issuer unknown)",
    2: "the issuer certificate could not be found",
    27: "the certificate is not trusted",
    28: "the certificate was rejected",
    7: "the certificate signature is invalid",
}


@dataclass
class CheckContext:
    host: str
    cert: x509.Certificate
    info: CertificateInfo
    handshake: HandshakeResult
    tls_version: Optional[str]
    now: datetime


def check_validity(c: CheckContext) -> CheckResult:
    name = "Certificate Validity"
    not_before, not_after = c.cert.not_valid_before_utc, c.cert.not_valid_after_utc
    if c.now < not_before:
        return CheckResult(name, FAIL, f"Certificate is not valid yet (starts {not_before.strftime(DATE_FORMAT)}).")
    if c.now > not_after:
        days_ago = abs(c.info.days_remaining)
        return CheckResult(name, FAIL, f"Certificate expired on {not_after.strftime(DATE_FORMAT)} ({days_ago} day(s) ago).")
    days = c.info.days_remaining
    if days <= EXPIRY_WARNING_DAYS:
        left = f"{days} day(s)" if days >= 1 else "less than 1 day"
        return CheckResult(name, WARN, f"Certificate expires soon: {left} left (until {not_after.strftime(DATE_FORMAT)}).")
    return CheckResult(name, PASS, f"Valid until {not_after.strftime(DATE_FORMAT)} ({days} days remaining).")


def check_hostname(c: CheckContext) -> CheckResult:
    name = "Hostname Match"
    dns_names, ips = get_san_values(c.cert)
    match = hostname_matches(c.host, dns_names, ips)
    if match is None or c.handshake.verify_code in NAME_CODES:
        if not dns_names and not ips:
            detail = "Certificate has no Subject Alternative Name (modern clients ignore the Common Name)."
        else:
            listed = ", ".join(c.info.subject_alt_names)
            detail = f"'{c.host}' is not covered by the certificate (SAN: {listed})."
        return CheckResult(name, FAIL, detail)
    return CheckResult(name, PASS, f"'{c.host}' matches Subject Alternative Name {match}.")


def check_trust(c: CheckContext) -> CheckResult:
    name = "Certificate Trust"
    hs = c.handshake
    if hs.verified:
        return CheckResult(name, PASS, "OpenSSL built a valid chain to a root in the trust store.")
    code, message = hs.verify_code, hs.verify_message
    if code in TIME_CODES:
        leaf_ok = c.cert.not_valid_before_utc <= c.now <= c.cert.not_valid_after_utc
        if leaf_ok:
            return CheckResult(name, FAIL, f"A certificate higher up in the chain is expired or not yet valid ({message}).")
        return CheckResult(name, PASS, "The chain leads to a trusted root; the handshake was stopped later "
                                       "because of the validity dates (see Certificate Validity).")
    if code in NAME_CODES:
        return CheckResult(name, PASS, "The chain leads to a trusted root; the handshake was stopped later "
                                       "because of the hostname (see Hostname Match).")
    if code in WEAK_CODES:
        return CheckResult(name, FAIL, f"OpenSSL rejected the chain because a key or digest in it is too weak ({message}).")
    if code in UNTRUSTED_TEXT:
        return CheckResult(name, FAIL, f"Not trusted: {UNTRUSTED_TEXT[code]} (OpenSSL: {message}). "
                                       "For a private CA use --ca-file.")
    if code is not None:
        return CheckResult(name, FAIL, f"Chain verification failed: {message}.")
    return CheckResult(name, FAIL, f"No verified TLS handshake was possible: {hs.error}")


def check_self_signed(c: CheckContext) -> CheckResult:
    name = "Self-Signed Check"
    if c.cert.subject != c.cert.issuer:
        return CheckResult(name, PASS, "Certificate was issued by a different party than its subject.")
    try:
        c.cert.verify_directly_issued_by(c.cert)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return CheckResult(name, WARN, "Subject and issuer are the same but the signature does not verify with its own key.")
    if c.handshake.verified:
        return CheckResult(name, WARN, "Certificate is self-signed, but it was explicitly trusted (it is in the trust store in use).")
    return CheckResult(name, FAIL, "Certificate is self-signed: it vouches for itself, so no CA has verified it.")


def check_key_strength(c: CheckContext) -> CheckResult:
    name = "Key Strength"
    key_type, size = get_public_key_info(c.cert)
    label = f"{key_type} {size}-bit" if size else key_type
    if key_type == "RSA":
        if size < 2048:
            return CheckResult(name, FAIL, f"{label} key is too weak (minimum 2048 bits).")
        return CheckResult(name, PASS, f"{label} key is strong enough.")
    if key_type.startswith("EC"):
        if size < 224:
            return CheckResult(name, FAIL, f"{label} key is too weak.")
        if size < 256:
            return CheckResult(name, WARN, f"{label} key is below the commonly used 256-bit curves.")
        return CheckResult(name, PASS, f"{label} key is strong enough.")
    if key_type in ("Ed25519", "Ed448"):
        return CheckResult(name, PASS, f"{label} key is strong.")
    if key_type == "DSA":
        if size < 2048:
            return CheckResult(name, FAIL, f"{label} key is too weak.")
        return CheckResult(name, WARN, f"{label} is a legacy certificate key type.")
    return CheckResult(name, WARN, f"Key type '{label}' could not be assessed.")


def check_signature_algorithm(c: CheckContext) -> CheckResult:
    name = "Signature Algorithm"
    algo = get_signature_algorithm_name(c.cert)
    hash_name = get_signature_hash_name(c.cert)
    if hash_name in ("md2", "md4", "md5", "sha1"):
        return CheckResult(name, FAIL, f"{algo} uses {hash_name.upper()}, which is broken/deprecated for certificates.")
    if hash_name in ("sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"):
        return CheckResult(name, PASS, f"{algo} uses {hash_name.upper()}.")
    if hash_name is None and algo.lower() in ("ed25519", "ed448"):
        return CheckResult(name, PASS, f"{algo} is a modern signature scheme.")
    return CheckResult(name, WARN, f"Signature algorithm '{algo}' could not be assessed as strong.")


def check_tls_version(c: CheckContext) -> CheckResult:
    name = "TLS Version"
    version = c.tls_version
    if version == "TLSv1.3":
        return CheckResult(name, PASS, "TLS 1.3 negotiated (current version).")
    if version == "TLSv1.2":
        return CheckResult(name, PASS, "TLS 1.2 negotiated (acceptable; TLS 1.3 is preferred).")
    if version in ("TLSv1.1", "TLSv1", "SSLv3", "SSLv2"):
        return CheckResult(name, FAIL, f"{version} is deprecated and insecure.")
    return CheckResult(name, WARN, "Negotiated TLS version could not be determined.")


def run_all_checks(c: CheckContext) -> list:
    return [
        check_validity(c),
        check_hostname(c),
        check_trust(c),
        check_self_signed(c),
        check_key_strength(c),
        check_signature_algorithm(c),
        check_tls_version(c),
    ]


def decide_verdict(checks: list) -> tuple[str, list]:
    statuses = {check.status for check in checks}
    if FAIL in statuses:
        verdict = NOT_SECURE
    elif WARN in statuses:
        verdict = WARNING
    else:
        verdict = SECURE
    reasons = [f"[{ch.status}] {ch.name}: {ch.detail}" for ch in checks if ch.status != PASS]
    return verdict, reasons or [f"All {len(checks)} checks passed."]
