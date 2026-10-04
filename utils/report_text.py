"""Plain-text rendering of a ValidationReport for the CLI."""
from models import ValidationReport

LINE = "=" * 66


def _row(label: str, value) -> str:
    return f"  {label:<22}: {value}"


def render_text(report: ValidationReport) -> str:
    where = f"{report.target}:{report.port}" if report.port else report.target
    out = [LINE, f"HTTPS Certificate Validation: {where}", LINE]
    if report.error:
        out.append(f"ERROR ({report.error['kind']}): {report.error['message']}")
        out.append("No verdict could be given because the certificate could not be checked.")
        return "\n".join(out)

    cert = report.certificate
    out.append("CERTIFICATE")
    out.append(_row("Subject", cert.subject))
    out.append(_row("Issuer", cert.issuer))
    out.append(_row("Serial number", cert.serial_number))
    out.append(_row("Valid from", cert.valid_from))
    out.append(_row("Valid until", cert.valid_until))
    out.append(_row("Days remaining", cert.days_remaining))
    out.append(_row("Common name", cert.common_name or "-"))
    out.append(_row("Subject alt. names", ", ".join(cert.subject_alt_names) or "-"))
    size = f"{cert.public_key_size} bits" if cert.public_key_size else "unknown size"
    out.append(_row("Public key", f"{cert.public_key_type}, {size}"))
    out.append(_row("Signature algorithm", cert.signature_algorithm))
    out.append(_row("SHA-256 fingerprint", cert.sha256_fingerprint))
    out.append("")
    out.append("TLS")
    out.append(_row("Negotiated version", report.tls_version or "unknown"))
    out.append(_row("Cipher suite", report.cipher or "unknown"))
    out.append(_row("Verified handshake", "yes" if report.handshake_verified else "no"))
    out.append("")
    out.append("SECURITY CHECKS")
    for check in report.checks:
        out.append(f"[{check.status}] {check.name}")
        out.append(f"       {check.detail}")
    out.append("")
    out.append(f"FINAL VERDICT: {report.verdict}")
    out.append("Reasons:")
    out.extend(f"  - {reason}" for reason in report.reasons)
    for note in report.notes:
        out.append(f"Note: {note}")
    out.append("")
    out.append(f"Limits: {report.disclaimer}")
    return "\n".join(out)
