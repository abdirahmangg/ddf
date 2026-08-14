"""Regression coverage for signed commercial authority canonicalization."""

from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from ddf.authority.models import Authority, AuthorityConstraints, AuthorityProof
from ddf.authorization.service import AuthorizationService
from ddf.commercial.crypto import LocalSigningProvider
from ddf.crypto.canonical import CanonicalSerializer


@pytest.mark.asyncio
async def test_signed_authority_with_datetimes_verifies_from_json_canonical_form():
    provider = LocalSigningProvider(
        SigningKey.generate(),
        "commercial-authority-json-regression",
    )

    now = datetime.now(UTC)

    authority = Authority(
        actor="agent:buyer",
        sponsor="user:alice",
        actions=["purchase"],
        resources=["vendor/dell/*"],
        purposes=["procurement"],
        constraints=AuthorityConstraints(
            max_amount=2000,
            delegation_depth_remaining=2,
        ),
        authority_path=[
            "user:alice",
            "agent:buyer",
        ],
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        holder_public_key=provider.public_key_b64,
    )

    payload = authority.model_dump(mode="json")
    payload["proof"] = None

    assert isinstance(payload["issued_at"], str)
    assert isinstance(payload["expires_at"], str)

    canonical = CanonicalSerializer.serialize_authority_for_signing(payload)

    authority.proof = AuthorityProof(
        algorithm="Ed25519",
        key_id=provider.key_id,
        signature=await provider.sign(canonical),
        public_key=provider.public_key_b64,
    )

    AuthorizationService.verify_authority_signature(authority)
