from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "release-evidence/ddf.spdx.json"


def git_sha() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()


packages = []

for distribution in sorted(
    metadata.distributions(),
    key=lambda item: (
        item.metadata.get("Name", "").lower()
    ),
):
    name = distribution.metadata.get("Name")

    if not name:
        continue

    version = distribution.version

    packages.append(
        {
            "SPDXID": (
                "SPDXRef-Package-"
                + hashlib.sha256(
                    f"{name}=={version}".encode()
                ).hexdigest()[:16]
            ),
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:pypi/{name.lower()}@{version}"
                    ),
                }
            ],
        }
    )

document = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "DDF stable-release candidate SBOM",
    "documentNamespace": (
        "https://arkstride.com/ddf/spdx/"
        + git_sha()
    ),
    "creationInfo": {
        "created": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "creators": [
            "Tool: DDF generate_spdx_sbom.py"
        ],
    },
    "packages": packages,
}

OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True,
)

OUTPUT.write_text(
    json.dumps(document, indent=2) + "\n"
)

print(OUTPUT)
print("packages:", len(packages))
print(
    "sha256:",
    hashlib.sha256(
        OUTPUT.read_bytes()
    ).hexdigest(),
)
