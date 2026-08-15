import tomllib
from pathlib import Path

EXPECTED_RELEASE_VERSION = "1.0.0rc5"


def test_project_release_identity() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text())

    assert data["project"]["version"] == EXPECTED_RELEASE_VERSION
