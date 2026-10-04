"""Data classes shared by the CLI, the Flask dashboard and the tests."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

# Result of a single check
PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

# Final verdicts
SECURE = "SECURE"
WARNING = "WARNING"
NOT_SECURE = "NOT SECURE"

DISCLAIMER = (
    "SECURE only means the server's certificate is valid for this host under the "
    "configured PKI trust model (system trust store plus any --ca-file). It does not "
    "prove the website itself is trustworthy or legitimate, and this tool cannot "
    "detect every man-in-the-middle attack (for example, one that uses a certificate "
    "issued by a CA that you already trust)."
)


@dataclass
class CheckResult:
    name: str
    status: str  # PASS / WARN / FAIL
    detail: str


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    serial_number: str
    valid_from: str
    valid_until: str
    days_remaining: int
    common_name: Optional[str]
    subject_alt_names: list
    public_key_type: str
    public_key_size: Optional[int]
    signature_algorithm: str
    sha256_fingerprint: str


@dataclass
class ValidationReport:
    target: str
    port: int
    checked_at: str
    handshake_verified: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    certificate: Optional[CertificateInfo] = None
    checks: list = field(default_factory=list)
    verdict: Optional[str] = None  # None when no verdict could be given
    reasons: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    error: Optional[dict] = None  # {"kind": ..., "message": ...}
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return asdict(self)
