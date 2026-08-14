"""Authority signature verification for DDF.

Combines canonical serialization, hashing, and Ed25519 verification.
"""

from datetime import datetime

from ddf.api.errors import SignatureVerificationError
from ddf.authority.models import Authority
from ddf.crypto.canonical import CanonicalSerializer
from ddf.crypto.signing import Verifier


class AuthorityVerifier:
    """Verifies DDF authority signatures."""

    @staticmethod
    def verify_authority(authority: Authority) -> bool:
        """
        Verify an authority's signature.

        Args:
            authority: Authority to verify

        Returns:
            True if signature is valid

        Raises:
            SignatureVerificationError: If signature is invalid or missing
        """
        if not authority.proof:
            raise SignatureVerificationError("Authority has no proof/signature")

        if authority.proof.algorithm != "Ed25519":
            raise SignatureVerificationError(f"Unsupported algorithm: {authority.proof.algorithm}")

        # Get the canonical bytes (without proof) for verification
        authority_dict = authority.model_dump()

        # Convert datetime objects to ISO format strings for JSON serialization
        if isinstance(authority_dict.get("issued_at"), datetime):
            authority_dict["issued_at"] = authority_dict["issued_at"].isoformat()
        if isinstance(authority_dict.get("expires_at"), datetime):
            authority_dict["expires_at"] = authority_dict["expires_at"].isoformat()

        canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(authority_dict)

        # Verify the signature
        return Verifier.verify_signature(
            public_key_b64=authority.holder_public_key,
            message=canonical_bytes,
            signature_b64=authority.proof.signature,
        )

    @staticmethod
    def verify_request_proof(
        public_key_b64: str,
        actor: str,
        authority_id: str,
        method: str,
        path: str,
        body_hash: str,
        timestamp: str,
        nonce: str,
        signature_b64: str,
    ) -> bool:
        """
        Verify a request proof (proof-of-possession).

        Args:
            public_key_b64: Base64-encoded public key (from authority)
            actor: Actor making the request
            authority_id: Authority being used
            method: HTTP method
            path: Request path
            body_hash: SHA-256 hash of request body
            timestamp: ISO 8601 timestamp
            nonce: Replay prevention nonce
            signature_b64: Base64-encoded signature

        Returns:
            True if proof is valid

        Raises:
            SignatureVerificationError: If verification fails
        """
        # Serialize the request proof
        canonical_bytes = CanonicalSerializer.serialize_request_proof(
            actor=actor,
            authority_id=authority_id,
            method=method,
            path=path,
            body_hash=body_hash,
            timestamp=timestamp,
            nonce=nonce,
        )

        # Verify
        return Verifier.verify_signature(
            public_key_b64=public_key_b64,
            message=canonical_bytes,
            signature_b64=signature_b64,
        )
