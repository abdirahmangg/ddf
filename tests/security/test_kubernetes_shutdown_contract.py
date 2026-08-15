from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/k8s/ddf-production.yaml"


def ddf_deployment() -> dict:
    documents = list(yaml.safe_load_all(MANIFEST.read_text()))

    for document in documents:
        if not isinstance(document, dict):
            continue

        if document.get("kind") != "Deployment":
            continue

        containers = (
            document
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )

        if any(
            container.get("name") == "ddf"
            for container in containers
        ):
            return document

    raise AssertionError("DDF Deployment not found")


def test_ddf_deployment_has_graceful_shutdown_contract() -> None:
    deployment = ddf_deployment()

    strategy = deployment["spec"]["strategy"]

    assert strategy["type"] == "RollingUpdate"
    assert strategy["rollingUpdate"]["maxUnavailable"] == 0
    assert strategy["rollingUpdate"]["maxSurge"] == 1

    pod_spec = deployment["spec"]["template"]["spec"]

    assert pod_spec["enableServiceLinks"] is False
    assert pod_spec["terminationGracePeriodSeconds"] >= 30

    ddf = next(
        container
        for container in pod_spec["containers"]
        if container.get("name") == "ddf"
    )

    command = ddf["lifecycle"]["preStop"]["exec"]["command"]

    assert command == ["sh", "-c", "sleep 8"]
