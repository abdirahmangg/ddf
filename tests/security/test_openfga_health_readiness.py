from __future__ import annotations

from typing import Any

import httpx
import pytest

from ddf.commercial import production_readiness as readiness


class FakeResponse:
    def __init__(self, success: bool) -> None:
        self.is_success = success


class FakeClient:
    success = True
    fail = False
    requested_url: str | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        return None

    async def get(self, url: str) -> FakeResponse:
        type(self).requested_url = url

        if type(self).fail:
            raise httpx.ConnectError("unreachable")

        return FakeResponse(type(self).success)


@pytest.fixture(autouse=True)
def clean_openfga_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable in (
        "DDF_OPENFGA_URL",
        "DDF_OPENFGA_API_URL",
        "OPENFGA_API_URL",
    ):
        monkeypatch.delenv(variable, raising=False)


@pytest.mark.asyncio
async def test_openfga_probe_is_none_when_unconfigured() -> None:
    assert await readiness._probe_openfga_readiness() is None


@pytest.mark.asyncio
async def test_openfga_probe_uses_configured_api_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DDF_OPENFGA_API_URL",
        "http://openfga:8080",
    )
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

    FakeClient.success = True
    FakeClient.fail = False
    FakeClient.requested_url = None

    assert await readiness._probe_openfga_readiness() is True
    assert FakeClient.requested_url == "http://openfga:8080/healthz"


@pytest.mark.asyncio
async def test_openfga_probe_fails_closed_when_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DDF_OPENFGA_URL",
        "http://openfga:8080",
    )
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

    FakeClient.fail = True

    assert await readiness._probe_openfga_readiness() is False
