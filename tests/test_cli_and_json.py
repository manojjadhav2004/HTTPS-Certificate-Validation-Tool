import json
import subprocess
import sys

from cert_validator import main
from utils.paths import LAB_CA_PATH, PROJECT_ROOT


def test_json_output_in_process(lab_servers, capsys):
    code = main(["localhost", "--port", "4443", "--ca-file", str(LAB_CA_PATH), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["verdict"] == "SECURE"
    assert data["port"] == 4443
    assert [c["name"] for c in data["checks"]] == [
        "Certificate Validity", "Hostname Match", "Certificate Trust", "Self-Signed Check",
        "Key Strength", "Signature Algorithm", "TLS Version",
    ]
    assert {c["status"] for c in data["checks"]} <= {"PASS", "WARN", "FAIL"}
    for field in ("subject", "issuer", "serial_number", "valid_from", "valid_until", "days_remaining",
                  "common_name", "subject_alt_names", "public_key_type", "public_key_size",
                  "signature_algorithm", "sha256_fingerprint"):
        assert field in data["certificate"]
    assert data["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert "does not prove" in data["disclaimer"]


def test_cli_as_a_real_process(lab_servers):
    result = subprocess.run(
        [sys.executable, "cert_validator.py", "localhost", "--port", "4445",
         "--ca-file", str(LAB_CA_PATH), "--json"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 2  # NOT SECURE
    assert json.loads(result.stdout)["verdict"] == "NOT SECURE"
    assert "Traceback" not in result.stderr


def test_text_output_has_final_verdict(lab_servers, capsys):
    main(["localhost", "--port", "4444", "--ca-file", str(LAB_CA_PATH)])
    out = capsys.readouterr().out
    assert "[WARN] Certificate Validity" in out
    assert "[PASS] Hostname Match" in out
    assert "FINAL VERDICT: WARNING" in out


def test_error_exit_code_and_json(capsys):
    code = main(["localhost", "--port", "1", "--json", "--timeout", "2"])
    data = json.loads(capsys.readouterr().out)
    assert code == 3
    assert data["verdict"] is None
    assert data["error"]["kind"] in ("refused", "timeout", "network")
