"""Cryptographic primitives and KMS/HSM signing abstraction."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from functools import lru_cache
from typing import Any, Protocol

import httpx
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def request_message(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    body_hash = sha256_hex(body)
    return (f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}").encode()


def verify_ed25519(
    public_key_b64: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    try:
        VerifyKey(base64.b64decode(public_key_b64)).verify(
            message,
            base64.b64decode(signature_b64),
        )
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


class SigningProvider(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def public_key_b64(self) -> str: ...

    async def sign(self, message: bytes) -> str: ...


class LocalSigningProvider:
    def __init__(self, key: SigningKey, key_id: str):
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self._key.verify_key)).decode("ascii")

    async def sign(self, message: bytes) -> str:
        return base64.b64encode(self._key.sign(message).signature).decode("ascii")


class RemoteSigningProvider:
    """Adapter for a KMS/HSM bridge exposing POST /sign."""

    def __init__(
        self,
        *,
        url: str,
        key_id: str,
        public_key_b64: str,
        token: str = "",
    ):
        self.url = url.rstrip("/")
        self._key_id = key_id
        self._public_key_b64 = public_key_b64
        self.token = token

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_b64(self) -> str:
        return self._public_key_b64

    async def sign(self, message: bytes) -> str:
        headers = {"content-type": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{self.url}/sign",
                headers=headers,
                json={
                    "algorithm": "Ed25519",
                    "key_id": self.key_id,
                    "message": base64.b64encode(message).decode("ascii"),
                },
            )
            response.raise_for_status()
            signature_value = response.json().get("signature")

        if not isinstance(signature_value, str):
            raise RuntimeError("remote signer returned an invalid signature payload")

        signature = signature_value

        if not verify_ed25519(self.public_key_b64, message, signature):
            raise RuntimeError("remote signer returned a signature that does not verify")

        return signature


@lru_cache(maxsize=1)
def get_system_signer() -> SigningProvider:
    provider = os.getenv("DDF_SYSTEM_SIGNING_PROVIDER", "local").lower()
    key_id = os.getenv("DDF_SYSTEM_SIGNING_KEY_ID", "ddf:key:system")

    if provider == "remote":
        url = os.getenv("DDF_SYSTEM_SIGNING_REMOTE_URL", "")
        public_key = os.getenv("DDF_SYSTEM_SIGNING_PUBLIC_KEY", "")
        if not url or not public_key:
            raise RuntimeError(
                "remote signer requires DDF_SYSTEM_SIGNING_REMOTE_URL "
                "and DDF_SYSTEM_SIGNING_PUBLIC_KEY"
            )

        return RemoteSigningProvider(
            url=url,
            key_id=key_id,
            public_key_b64=public_key,
            token=os.getenv("DDF_SYSTEM_SIGNING_REMOTE_TOKEN", ""),
        )

    private_key = os.getenv("DDF_SYSTEM_SIGNING_PRIVATE_KEY", "")
    development = os.getenv("DDF_DEVELOPMENT_MODE", "false").lower() in {"1", "true", "yes", "on"}

    if private_key:
        raw = base64.b64decode(private_key)
        return LocalSigningProvider(SigningKey(raw), key_id)

    if development:
        return LocalSigningProvider(SigningKey.generate(), key_id)

    raise RuntimeError(
        "production signing key is not configured; set "
        "DDF_SYSTEM_SIGNING_PRIVATE_KEY or use remote KMS/HSM signing"
    )
