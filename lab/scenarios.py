"""The test scenarios of the local HTTPS laboratory (shared by all lab scripts and the tests)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from models import NOT_SECURE, SECURE, WARNING

HOST = "localhost"


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    port: int
    cert_name: str  # file name stem in lab/certificates
    expected_verdict: str
    expected_check: Optional[tuple]  # (check name, status) that must show up
    use_ca: bool = True  # pass the lab Root CA with --ca-file?
    serve: bool = True  # False = re-uses another scenario's server


SCENARIOS = [
    Scenario("valid", "Valid certificate (signed by lab Root CA)", 4443, "valid", SECURE, None),
    Scenario("near_expiry", "Near-expiry certificate (10 days left)", 4444, "near_expiry", WARNING,
             ("Certificate Validity", "WARN")),
    Scenario("expired", "Expired certificate", 4445, "expired", NOT_SECURE, ("Certificate Validity", "FAIL")),
    Scenario("wrong_hostname", "Wrong-hostname certificate", 4446, "wrong_hostname", NOT_SECURE,
             ("Hostname Match", "FAIL")),
    Scenario("self_signed", "Self-signed certificate", 4447, "self_signed", NOT_SECURE,
             ("Self-Signed Check", "FAIL")),
    Scenario("weak_rsa", "Weak RSA 1024-bit certificate", 4448, "weak_rsa", NOT_SECURE, ("Key Strength", "FAIL")),
    # Same server as "valid", but the Root CA is not given -> the CA is unknown
    Scenario("untrusted_ca", "Valid certificate, Root CA NOT trusted", 4443, "valid", NOT_SECURE,
             ("Certificate Trust", "FAIL"), use_ca=False, serve=False),
]
