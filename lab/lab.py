#!/usr/bin/env python3
"""Runs every lab scenario through the validator and compares expected vs actual results.

    python lab/lab.py

It starts the lab servers itself (or uses them if they are already running).
Exit code 0 = every scenario matched what was expected.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cert_validator import validate  # noqa: E402
from lab.generate_certs import generate_all  # noqa: E402
from lab.scenarios import HOST, SCENARIOS  # noqa: E402
from lab.serve import start_servers, stop_servers  # noqa: E402
from utils.paths import LAB_CA_PATH  # noqa: E402


def run_scenario(scenario):
    ca = str(LAB_CA_PATH) if scenario.use_ca else None
    return validate(HOST, scenario.port, ca_file=ca, timeout=8)


def main() -> int:
    if generate_all():
        print("Generated fresh lab certificates.")
    servers = start_servers(skip_busy=True)
    try:
        rows, all_ok = [], True
        for scenario in SCENARIOS:
            report = run_scenario(scenario)
            actual_check = "-"
            check_ok = True
            if scenario.expected_check:
                name, expected_status = scenario.expected_check
                found = next((c.status for c in report.checks if c.name == name), None)
                actual_check = f"{name}={found}"
                check_ok = found == expected_status
            verdict_ok = report.verdict == scenario.expected_verdict
            ok = verdict_ok and check_ok
            all_ok &= ok
            expected_check = f"{scenario.expected_check[0]}={scenario.expected_check[1]}" if scenario.expected_check else "-"
            rows.append((scenario, report, expected_check, actual_check, ok))

        print()
        print(f"{'Scenario':<42}{'Port':<6}{'Expected':<12}{'Actual':<12}{'Result'}")
        print("-" * 80)
        for scenario, report, _, _, ok in rows:
            actual = report.verdict or "ERROR"
            print(f"{scenario.title:<42}{scenario.port:<6}{scenario.expected_verdict:<12}{actual:<12}{'OK' if ok else 'MISMATCH'}")
        print()
        for scenario, report, expected_check, actual_check, ok in rows:
            print(f"- {scenario.title}")
            print(f"    expected check: {expected_check} | actual check: {actual_check}")
            if report.error:
                print(f"    error: {report.error['message']}")
            for reason in report.reasons:
                if not reason.startswith("All "):
                    print(f"    {reason}")
        print()
        print("All scenarios matched the expected results." if all_ok else "Some scenarios did NOT match - see above.")
        return 0 if all_ok else 1
    finally:
        stop_servers(servers)


if __name__ == "__main__":
    sys.exit(main())
