from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GATES = ROOT / "release-gates.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())

    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")

    return value


def validate_evidence(
    gate_id: str,
    path: Path,
) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if not path.exists():
        return False, ["evidence file is missing"]

    try:
        evidence = load_json(path)
    except Exception as exc:
        return False, [f"invalid JSON: {exc}"]

    if evidence.get("gate_id") != gate_id:
        errors.append("gate_id mismatch")

    if evidence.get("status") != "passed":
        errors.append("evidence status is not passed")

    reviewer = str(evidence.get("reviewer", "")).strip()

    if not reviewer:
        errors.append("reviewer is missing")

    approved_at = str(evidence.get("approved_at", "")).strip()

    if not approved_at:
        errors.append("approved_at is missing")
    else:
        try:
            datetime.fromisoformat(
                approved_at.replace("Z", "+00:00")
            )
        except ValueError:
            errors.append("approved_at is not ISO-8601")

    commit = str(evidence.get("commit", "")).strip()

    if len(commit) != 40:
        errors.append("commit must be a full Git SHA")

    artifacts = evidence.get("artifacts")

    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifacts must contain at least one item")
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"artifact {index} is invalid")
                continue

            relative = artifact.get("path")
            expected = artifact.get("sha256")

            if not isinstance(relative, str) or not relative:
                errors.append(f"artifact {index} path missing")
                continue

            artifact_path = ROOT / relative

            if not artifact_path.exists():
                errors.append(
                    f"artifact missing: {relative}"
                )
                continue

            actual = sha256(artifact_path)

            if actual != expected:
                errors.append(
                    f"artifact checksum mismatch: {relative}"
                )

    return not errors, errors


def status() -> int:
    gates = load_json(GATES)
    failed = False

    print("EXTERNAL RELEASE EVIDENCE")
    print("=" * 72)

    for gate in gates["required_external_gates"]:
        gate_id = gate["id"]
        path = ROOT / gate["evidence"]

        ok, errors = validate_evidence(
            gate_id,
            path,
        )

        print(
            f"{gate_id}: "
            f"{'PASS' if ok else 'PENDING/FAIL'}"
        )

        for error in errors:
            print(f"  - {error}")

        if not ok:
            failed = True

    print("=" * 72)

    if failed:
        print("STABLE v1.0.0: BLOCKED")
        return 1

    print("STABLE v1.0.0: EXTERNAL EVIDENCE PASS")
    return 0


def template(gate_id: str) -> None:
    gates = load_json(GATES)

    gate = next(
        (
            item
            for item in gates["required_external_gates"]
            if item["id"] == gate_id
        ),
        None,
    )

    if gate is None:
        raise SystemExit(f"Unknown gate: {gate_id}")

    path = ROOT / gate["evidence"]

    if path.exists():
        raise SystemExit(
            f"Refusing to overwrite existing {path}"
        )

    payload = {
        "gate_id": gate_id,
        "status": "pending",
        "reviewer": "",
        "approved_at": "",
        "commit": "",
        "summary": "",
        "artifacts": [],
        "created_at": datetime.now(UTC).isoformat(),
    }

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(payload, indent=2) + "\n"
    )

    print(path.relative_to(ROOT))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    sub.add_parser("status")

    template_parser = sub.add_parser(
        "template"
    )
    template_parser.add_argument(
        "gate_id"
    )

    args = parser.parse_args()

    if args.command == "status":
        raise SystemExit(status())

    if args.command == "template":
        template(args.gate_id)


if __name__ == "__main__":
    main()
