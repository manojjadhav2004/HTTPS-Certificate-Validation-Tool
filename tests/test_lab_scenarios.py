"""Certificate scenarios, tested against the local HTTPS lab (no internet needed)."""
import pytest

from cert_validator import validate
from conftest import check_status
from lab.scenarios import HOST, SCENARIOS


def test_valid_certificate(lab_servers, ca_file):
    report = validate(HOST, 4443, ca_file=ca_file)
    assert report.error is None
    assert report.verdict == "SECURE"
    assert all(c.status == "PASS" for c in report.checks)
    assert len(report.checks) == 7
    assert report.handshake_verified is True
    assert report.tls_version in ("TLSv1.2", "TLSv1.3")
    cert = report.certificate
    assert cert.common_name == "localhost"
    assert "DNS:localhost" in cert.subject_alt_names
    assert cert.public_key_type == "RSA" and cert.public_key_size == 2048
    assert len(cert.sha256_fingerprint.split(":")) == 32


def test_near_expiry_certificate_warns(lab_servers, ca_file):
    report = validate(HOST, 4444, ca_file=ca_file)
    assert check_status(report, "Certificate Validity") == "WARN"
    assert report.verdict == "WARNING"
    assert 0 < report.certificate.days_remaining <= 30


def test_expired_certificate(lab_servers, ca_file):
    report = validate(HOST, 4445, ca_file=ca_file)
    assert check_status(report, "Certificate Validity") == "FAIL"
    assert report.verdict == "NOT SECURE"
    assert report.certificate.days_remaining < 0
    assert report.handshake_verified is False
    assert any("expired" in r for r in report.reasons)


def test_hostname_mismatch(lab_servers, ca_file):
    report = validate(HOST, 4446, ca_file=ca_file)
    assert check_status(report, "Hostname Match") == "FAIL"
    assert check_status(report, "Certificate Validity") == "PASS"
    assert report.verdict == "NOT SECURE"


def test_self_signed_certificate(lab_servers, ca_file):
    report = validate(HOST, 4447, ca_file=ca_file)
    assert check_status(report, "Self-Signed Check") == "FAIL"
    assert check_status(report, "Certificate Trust") == "FAIL"
    assert report.verdict == "NOT SECURE"


def test_weak_rsa_key(lab_servers, ca_file):
    report = validate(HOST, 4448, ca_file=ca_file)
    assert report.certificate.public_key_size == 1024
    assert check_status(report, "Key Strength") == "FAIL"
    assert report.verdict == "NOT SECURE"


def test_untrusted_ca(lab_servers):
    """Valid certificate, but the private Root CA was not supplied -> not trusted."""
    report = validate(HOST, 4443)
    assert check_status(report, "Certificate Trust") == "FAIL"
    assert report.verdict == "NOT SECURE"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_every_scenario_matches_expectation(lab_servers, ca_file, scenario):
    report = validate(HOST, scenario.port, ca_file=ca_file if scenario.use_ca else None)
    assert report.verdict == scenario.expected_verdict
    if scenario.expected_check:
        name, status = scenario.expected_check
        assert check_status(report, name) == status
