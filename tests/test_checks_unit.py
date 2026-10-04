"""Unit tests for hostname matching and the safety rule 'never disable verification'."""
import re

import pytest

from models import FAIL, NOT_SECURE, PASS, SECURE, WARN, WARNING, CheckResult
from utils.certinfo import hostname_matches
from utils.checks import decide_verdict
from utils.paths import PROJECT_ROOT


@pytest.mark.parametrize("host,dns,ips,ok", [
    ("example.com", ["example.com"], [], True),
    ("EXAMPLE.com", ["example.com"], [], True),
    ("www.example.com", ["*.example.com"], [], True),
    ("example.com", ["*.example.com"], [], False),          # wildcard needs one extra label
    ("a.b.example.com", ["*.example.com"], [], False),      # wildcard covers one label only
    ("evil.com", ["*.com"], [], False),                     # no wildcard on a public suffix level
    ("www.example.com", ["w*.example.com"], [], False),     # partial wildcards are rejected
    ("other.com", ["example.com"], [], False),
    ("127.0.0.1", ["localhost"], ["127.0.0.1"], True),
    ("127.0.0.1", ["127.0.0.1"], [], False),                # IP must match an IP SAN, not a DNS SAN
    ("::1", [], ["::1"], True),
    ("example.com", [], [], False),                         # no SAN -> CN is ignored
])
def test_hostname_matching(host, dns, ips, ok):
    assert (hostname_matches(host, dns, ips) is not None) == ok


def _checks(*statuses):
    return [CheckResult(f"c{i}", s, "x") for i, s in enumerate(statuses)]


def test_verdict_rules():
    assert decide_verdict(_checks(PASS, PASS))[0] == SECURE
    assert decide_verdict(_checks(PASS, WARN))[0] == WARNING
    assert decide_verdict(_checks(WARN, FAIL, PASS))[0] == NOT_SECURE


def test_verdict_gives_reasons():
    verdict, reasons = decide_verdict(_checks(PASS, FAIL))
    assert len(reasons) == 1 and "[FAIL] c1" in reasons[0]


def test_validation_path_never_disables_verification():
    """The validator and its verified handshake must not turn verification off."""
    forbidden = ["_create_unverified_context", "check_hostname = False", "verify_mode = ssl.CERT_NONE"]
    for relative in ("cert_validator.py", "app.py"):
        text = (PROJECT_ROOT / relative).read_text()
        assert not any(word in text for word in forbidden), relative
    connection = (PROJECT_ROOT / "utils" / "connection.py").read_text()
    assert "_create_unverified_context" not in connection
    # CERT_NONE may appear only once: in the clearly marked inspection-only function
    assert len(re.findall(r"CERT_NONE", connection)) == 1
    verified_part = connection.split("def verified_handshake")[1].split("def fetch_for_inspection")[0]
    assert "CERT_NONE" not in verified_part
    assert "check_hostname" not in verified_part
