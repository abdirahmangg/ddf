"""Security-focused tests for the commercial trust-plane primitives."""

import base64
from datetime import UTC, datetime

from nacl.signing import SigningKey

from ddf.commercial.crypto import (
    canonical_json,
    request_message,
    verify_ed25519,
)
from ddf.commercial.intent import compile_intent


def test_signed_request_message_verifies() -> None:
    key = SigningKey.generate()

    public = base64.b64encode(bytes(key.verify_key)).decode("ascii")

    message = request_message(
        method="POST",
        path="/v1/commercial/grants",
        timestamp=datetime.now(UTC).isoformat(),
        nonce="nonce-1234567890123456",
        body=b'{"actor":"agent:test"}',
    )

    signature = base64.b64encode(key.sign(message).signature).decode("ascii")

    assert verify_ed25519(
        public,
        message,
        signature,
    )


def test_signature_fails_for_changed_message() -> None:
    key = SigningKey.generate()

    public = base64.b64encode(bytes(key.verify_key)).decode("ascii")

    signature = base64.b64encode(key.sign(b"original").signature).decode("ascii")

    assert not verify_ed25519(
        public,
        b"modified",
        signature,
    )


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_rule_intent_compiler() -> None:
    proposal = compile_intent("purchase £1500 vendor/dell/order/9281 for procurement")

    assert proposal.action == "purchase"
    assert proposal.resource == "vendor/dell/order/9281"
    assert proposal.purpose == "procurement"
    assert proposal.amount == 1500
    assert proposal.currency == "GBP"


def test_rule_intent_requires_explicit_scope() -> None:
    try:
        compile_intent("buy something")
    except ValueError:
        pass
    else:
        raise AssertionError("underspecified natural-language intent must fail closed")
