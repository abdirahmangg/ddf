"""Verification of EAT JWTs used to bind runtime posture to capability checks."""

import base64
import hashlib
import json
import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError


@dataclass(frozen=True)
class RuntimePostureResult:
    """Result of EAT and runtime-context verification."""

    allowed: bool
    reasons: tuple[str, ...]
    posture_score: float | None = None


class EATVerifier:
    """Verify signed EAT JWTs against configured issuer keys and freshness policy."""

    def __init__(
        self,
        *,
        trusted_issuers: dict[str, Ed25519PublicKey],
        minimum_posture_score: float = 0.8,
        maximum_age_seconds: int = 300,
    ) -> None:
        if not math.isfinite(minimum_posture_score) or not 0 <= minimum_posture_score <= 1:
            raise ValueError("minimum posture score must be between 0 and 1")
        if maximum_age_seconds <= 0:
            raise ValueError("maximum attestation age must be positive")
        self.trusted_issuers = trusted_issuers
        self.minimum_posture_score = minimum_posture_score
        self.maximum_age_seconds = maximum_age_seconds

    @classmethod
    def from_env(cls) -> "EATVerifier":
        """Load issuer public keys and policy from environment variables."""
        encoded_keys = os.getenv("DDF_EAT_TRUSTED_KEYS", "{}")
        try:
            raw_keys = json.loads(encoded_keys)
        except json.JSONDecodeError as exc:
            raise ValueError("DDF_EAT_TRUSTED_KEYS must be a JSON object") from exc
        if not isinstance(raw_keys, dict):
            raise ValueError("DDF_EAT_TRUSTED_KEYS must be a JSON object")

        trusted_issuers: dict[str, Ed25519PublicKey] = {}
        for issuer, encoded_key in raw_keys.items():
            if not isinstance(issuer, str) or not isinstance(encoded_key, str):
                raise ValueError("EAT issuer keys must map string issuers to base64 keys")
            try:
                key_bytes = base64.b64decode(encoded_key, validate=True)
                trusted_issuers[issuer] = Ed25519PublicKey.from_public_bytes(key_bytes)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid Ed25519 EAT key for issuer {issuer}") from exc

        try:
            minimum_posture_score = float(os.getenv("DDF_MIN_POSTURE_SCORE", "0.8"))
            maximum_age_seconds = int(os.getenv("DDF_ATTESTATION_MAX_AGE_SECONDS", "300"))
        except ValueError as exc:
            raise ValueError("invalid runtime posture policy configuration") from exc

        return cls(
            trusted_issuers=trusted_issuers,
            minimum_posture_score=minimum_posture_score,
            maximum_age_seconds=maximum_age_seconds,
        )

    def verify(
        self,
        *,
        token: str | None,
        runtime_context: dict[str, Any],
        now: datetime | None = None,
    ) -> RuntimePostureResult:
        """Verify signature, EAT claims, context binding, posture, and freshness."""
        if not token:
            return RuntimePostureResult(False, ("attestation_missing",))

        try:
            untrusted_claims = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_aud": False,
                },
                algorithms=["EdDSA"],
            )
        except InvalidTokenError:
            return RuntimePostureResult(False, ("attestation_invalid",))

        issuer = untrusted_claims.get("iss")
        key = self.trusted_issuers.get(issuer) if isinstance(issuer, str) else None
        if key is None:
            return RuntimePostureResult(False, ("attestation_issuer_untrusted",))

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["EdDSA"],
                issuer=issuer,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "iss",
                        "ueid",
                        "nonce",
                        "ddf_hardware_enclave",
                        "ddf_posture_score",
                        "ddf_runtime_context_hash",
                    ],
                    "verify_aud": False,
                },
            )
        except ExpiredSignatureError:
            return RuntimePostureResult(False, ("attestation_stale",))
        except InvalidTokenError:
            return RuntimePostureResult(False, ("attestation_invalid",))

        issued_at = claims["iat"]
        if not isinstance(issued_at, (int, float)) or isinstance(issued_at, bool):
            return RuntimePostureResult(False, ("attestation_invalid",))
        current_time = (now or datetime.now(UTC)).timestamp()
        if issued_at > current_time or current_time - issued_at > self.maximum_age_seconds:
            return RuntimePostureResult(False, ("attestation_stale",))

        if claims["ddf_hardware_enclave"] is not True:
            return RuntimePostureResult(False, ("hardware_enclave_unverified",))

        score = claims["ddf_posture_score"]
        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not math.isfinite(score)
        ):
            return RuntimePostureResult(False, ("attestation_invalid",))
        score = float(score)
        if not 0 <= score <= 1:
            return RuntimePostureResult(False, ("attestation_invalid",))

        try:
            context_bytes = json.dumps(
                runtime_context,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            return RuntimePostureResult(False, ("runtime_context_invalid",))
        context_hash = hashlib.sha256(context_bytes).hexdigest()
        if claims["ddf_runtime_context_hash"] != context_hash:
            return RuntimePostureResult(False, ("runtime_context_unbound",), score)
        if score < self.minimum_posture_score:
            return RuntimePostureResult(False, ("posture_below_threshold",), score)

        return RuntimePostureResult(True, (), score)
