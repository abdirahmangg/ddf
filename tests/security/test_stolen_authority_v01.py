"""Mandatory DDF stolen-authority proof-of-possession test."""

import base64
from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from ddf.api.errors import ProofOfPossessionError
from ddf.authority.models import (
    Authority,
    AuthorizationRequest,
)
from ddf.authorization.service import AuthorizationService


def _public_key(key: SigningKey) -> str:
    return base64.b64encode(bytes(key.verify_key)).decode("ascii")


def test_copied_authority_wrong_private_key_is_denied():
    holder_key = SigningKey.generate()
    attacker_key = SigningKey.generate()

    now = datetime.now(UTC)

    authority = Authority(
        actor="agent:buyer",
        sponsor="user:alice@example.com",
        actions=["purchase"],
        resources=["vendor/*"],
        purposes=["procurement"],
        authority_path=[
            "user:alice@example.com",
            "agent:buyer",
        ],
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        holder_public_key=_public_key(holder_key),
    )

    unsigned_request = AuthorizationRequest(
        actor="agent:buyer",
        action="purchase",
        resource="vendor/dell/order/1",
        purpose="procurement",
        authority_id=authority.authority_id,
        context={"amount": 100},
    )

    message = AuthorizationService.request_proof_message(unsigned_request)

    attacker_signature = base64.b64encode(attacker_key.sign(message).signature).decode("ascii")

    request = unsigned_request.model_copy(
        update={
            "context": {
                "amount": 100,
                "proof_of_possession": {
                    "public_key": _public_key(attacker_key),
                    "signature": attacker_signature,
                },
            }
        }
    )

    with pytest.raises(ProofOfPossessionError):
        AuthorizationService.verify_proof_of_possession(
            request=request,
            authority=authority,
        )
