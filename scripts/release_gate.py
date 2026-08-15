from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--report-only",
        action="store_true",
    )

    parser.add_argument(
        "--software-only",
        action="store_true",
    )

    args = parser.parse_args()

    required_software = [
        "src/ddf/commercial/production_readiness.py",
        "alembic/versions/c42e9b9a4f21_production_readiness_state.py",
        "deploy/production/Dockerfile",
        "deploy/k8s/ddf-production.yaml",
        "deploy/helm/ddf/Chart.yaml",
        "deploy/terraform/main.tf",
        "deploy/alerts/ddf-prometheus-rules.yaml",
        "docs/COMMERCIAL_READINESS.md",
        "docs/OPERATIONS.md",
        "docs/INCIDENT_RESPONSE.md",
    ]

    missing_software = [
        item
        for item in required_software
        if not (ROOT / item).exists()
    ]

    if missing_software:
        print("SOFTWARE GATE: FAIL")

        for item in missing_software:
            print("MISSING:", item)

        if not args.report_only:
            raise SystemExit(1)

        return

    print("SOFTWARE GATE: PASS")

    if args.software_only:
        return

    data = json.loads(
        (ROOT / "release-gates.json").read_text()
    )

    pending: list[str] = []

    for gate in data["required_external_gates"]:
        evidence = ROOT / gate["evidence"]

        passed = (
            gate["status"] == "passed"
            and evidence.exists()
        )

        print(
            f"{gate['id']}: "
            f"{'PASS' if passed else 'PENDING'}"
        )

        if not passed:
            pending.append(
                gate["id"]
            )

    if pending:
        print()
        print(
            "STABLE RELEASE GATE: BLOCKED"
        )

        print(
            "Pending:",
            ", ".join(
                pending
            ),
        )

        if not args.report_only:
            raise SystemExit(1)

        return

    print(
        "STABLE RELEASE GATE: PASS"
    )


if __name__ == "__main__":
    main()
