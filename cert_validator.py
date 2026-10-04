#!/usr/bin/env python3
"""HTTPS Certificate Validation Tool - command line interface and library.

Examples:
    python cert_validator.py google.com
    python cert_validator.py example.com --port 443
    python cert_validator.py localhost --port 4443 --ca-file lab/certificates/root_ca.pem
    python cert_validator.py google.com --json

Exit codes: 0 SECURE, 1 WARNING, 2 NOT SECURE, 3 no verdict (error).
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

from models import ValidationReport
from utils.certinfo import build_certificate_info, load_certificate
from utils.checks import CheckContext, decide_verdict, run_all_checks
from utils.connection import NetworkError, fetch_for_inspection, make_verified_context, verified_handshake
from utils.report_text import render_text
from utils.target import InvalidTargetError, parse_target

DEFAULT_TIMEOUT = 8.0
EXIT_CODES = {"SECURE": 0, "WARNING": 1, "NOT SECURE": 2}


def _fail(report: ValidationReport, kind: str, message: str) -> ValidationReport:
    report.error = {"kind": kind, "message": message}
    return report


def validate(target, port=None, ca_file=None, timeout=DEFAULT_TIMEOUT, now=None) -> ValidationReport:
    """Validate the HTTPS certificate of `target`. Never raises for network/TLS/input problems;
    they are returned in report.error instead."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        host, port_number = parse_target(target, port)
    except InvalidTargetError as exc:
        shown = str(target)[:200]
        return _fail(ValidationReport(shown, port if isinstance(port, int) else 0, stamp), "invalid_input", str(exc))

    report = ValidationReport(target=host, port=port_number, checked_at=stamp)

    if ca_file is not None and not Path(ca_file).is_file():
        return _fail(report, "ca_file", f"CA file not found: {ca_file}")
    try:
        context = make_verified_context(ca_file)
    except (OSError, ssl.SSLError) as exc:
        return _fail(report, "ca_file", f"Could not load CA file '{ca_file}': {exc}")

    # 1) The real validation: full verification stays enabled.
    try:
        handshake = verified_handshake(context, host, port_number, timeout)
    except NetworkError as exc:
        return _fail(report, exc.kind, exc.message)

    der, tls_version, cipher = handshake.der, handshake.tls_version, handshake.cipher
    report.handshake_verified = handshake.verified

    # 2) Verified handshake was refused: still fetch the certificate (display only).
    if der is None:
        try:
            der, tls_version, cipher = fetch_for_inspection(host, port_number, timeout)
        except NetworkError as exc:
            message = f"TLS handshake failed: {handshake.error}" if exc.kind == "tls" and handshake.error else exc.message
            return _fail(report, exc.kind, message)
        report.notes.append(
            "The verified handshake was refused, so the certificate was fetched on a separate connection "
            "that does not verify certificates. It is used only to show details; the trust result comes "
            "from the verified handshake."
        )

    try:
        cert = load_certificate(der)
        info = build_certificate_info(cert, now)
    except ValueError as exc:
        return _fail(report, "certificate", f"The server sent a certificate that could not be parsed: {exc}")

    report.tls_version, report.cipher, report.certificate = tls_version, cipher, info
    context_for_checks = CheckContext(host, cert, info, handshake, tls_version, now)
    report.checks = run_all_checks(context_for_checks)
    report.verdict, report.reasons = decide_verdict(report.checks)
    return report


def exit_code_for(report: ValidationReport) -> int:
    return EXIT_CODES.get(report.verdict, 3)


def _timeout_value(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a number") from None
    if not 0 < value <= 60:
        raise argparse.ArgumentTypeError("timeout must be between 0 and 60 seconds")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the HTTPS (X.509) certificate of a server.")
    parser.add_argument("target", help="hostname or https:// URL, e.g. example.com")
    parser.add_argument("--port", type=int, default=None, help="TLS port (default 443)")
    parser.add_argument("--ca-file", default=None, help="extra trusted CA certificate (PEM), e.g. the lab Root CA")
    parser.add_argument("--timeout", type=_timeout_value, default=DEFAULT_TIMEOUT, help="network timeout in seconds (default 8)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # avoid UnicodeEncodeError on Windows consoles
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    report = validate(args.target, args.port, args.ca_file, args.timeout)
    print(json.dumps(report.to_dict(), indent=2) if args.json else render_text(report))
    return exit_code_for(report)


if __name__ == "__main__":
    sys.exit(main())
