from types import SimpleNamespace

import pytest

from ddf.commercial.capabilities import mint_capability


class FakeSession:
    async def get(self, _model, _key):
        return SimpleNamespace(tenant_id="tenant-a")


@pytest.mark.asyncio
async def test_mint_capability_rejects_authenticated_principal_mismatch():
    principal = SimpleNamespace(
        tenant_id="tenant-a",
        subject="agent:attacker",
    )
    request = SimpleNamespace(
        authority_id="ddf:authority:test",
        actor="agent:buyer",
    )

    with pytest.raises(
        ValueError,
        match="authenticated principal does not match capability actor",
    ):
        await mint_capability(
            FakeSession(),
            principal=principal,
            request=request,
        )
