"""Canonical JSON serialization for DDF authority documents.

For cryptographic signing to work reliably, the JSON must be deterministic.
This module ensures consistent serialization across all systems.
"""

import json
from typing import Any


class CanonicalSerializer:
    """Serializes data to canonical (deterministic) JSON."""

    @staticmethod
    def serialize(data: Any) -> bytes:
        """
        Serialize data to canonical JSON bytes.

        Canonical JSON:
        - No whitespace
        - Sorted dictionary keys
        - Compact representation
        - Deterministic across Python versions

        Args:
            data: Data to serialize (typically a Pydantic model dict)

        Returns:
            UTF-8 encoded bytes
        """
        # Use separators to remove all whitespace, and sort_keys for determinism
        json_str = json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
        )
        return json_str.encode("utf-8")

    @staticmethod
    def serialize_authority_for_signing(authority_dict: dict[str, Any]) -> bytes:
        """
        Serialize an authority for signing.

        Excludes the signature/proof field (which would create circular dependency).

        Args:
            authority_dict: Authority as dict (from model_dump())

        Returns:
            Canonical bytes ready for signing
        """
        # Create a copy and remove proof if present
        signing_data = dict(authority_dict)
        signing_data.pop("proof", None)

        return CanonicalSerializer.serialize(signing_data)

    @staticmethod
    def serialize_request_proof(
        actor: str,
        authority_id: str,
        method: str,
        path: str,
        body_hash: str,
        timestamp: str,
        nonce: str,
    ) -> bytes:
        """
        Serialize a request proof for signing.

        Used for proof-of-possession during authorization.

        Args:
            actor: Actor making the request
            authority_id: Authority being exercised
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body_hash: SHA-256 hash of request body (hex)
            timestamp: ISO 8601 timestamp
            nonce: Random nonce for replay prevention

        Returns:
            Canonical bytes ready for signing
        """
        proof_dict = {
            "actor": actor,
            "authority_id": authority_id,
            "method": method,
            "path": path,
            "body_hash": body_hash,
            "timestamp": timestamp,
            "nonce": nonce,
        }

        return CanonicalSerializer.serialize(proof_dict)
