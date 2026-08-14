"""Tests for cryptographic signing and verification."""

import base64
from datetime import UTC, datetime, timedelta

import pytest

from ddf.api.errors import SignatureVerificationError
from ddf.authority.models import Authority, AuthorityProof
from ddf.crypto.canonical import CanonicalSerializer
from ddf.crypto.hashing import Hasher
from ddf.crypto.signing import Ed25519Key, Verifier
from ddf.crypto.verification import AuthorityVerifier


class TestCanonicalSerialization:
    """Test deterministic JSON serialization."""

    def test_canonical_format(self):
        """Test that canonical format removes whitespace and sorts keys."""
        data = {"z": 1, "a": 2, "m": {"y": 3, "x": 4}}
        canonical = CanonicalSerializer.serialize(data)

        # Should be compact (no spaces)
        assert b" " not in canonical
        assert b"\n" not in canonical

        # Should maintain order when deserialized
        import json

        decoded = json.loads(canonical.decode("utf-8"))
        assert decoded == data

    def test_canonical_deterministic(self):
        """Test that canonical serialization is deterministic."""
        data = {"z": 1, "a": 2, "m": {"y": 3, "x": 4}}

        result1 = CanonicalSerializer.serialize(data)
        result2 = CanonicalSerializer.serialize(data)

        assert result1 == result2

    def test_authority_serialization_excludes_proof(self):
        """Test that authority serialization excludes the proof field."""
        now = datetime.now(UTC)
        authority_dict = {
            "version": "ddf/0.1",
            "authority_id": "ddf:authority:test",
            "actor": "agent:test",
            "sponsor": "user:alice",
            "actions": ["purchase"],
            "resources": ["vendor/*"],
            "purposes": ["procurement"],
            "authority_path": ["user:alice"],
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "holder_public_key": "test_key",
            "proof": {
                "algorithm": "Ed25519",
                "key_id": "key:1",
                "signature": "sig123",
            },
        }

        canonical = CanonicalSerializer.serialize_authority_for_signing(authority_dict)

        # Should not contain the signature
        assert b"sig123" not in canonical
        assert b"proof" not in canonical

    def test_request_proof_serialization(self):
        """Test request proof serialization."""
        canonical = CanonicalSerializer.serialize_request_proof(
            actor="agent:test",
            authority_id="ddf:authority:123",
            method="POST",
            path="/v1/authorize",
            body_hash="abc123",
            timestamp="2026-08-13T12:00:00Z",
            nonce="nonce123",
        )

        assert b"agent:test" in canonical
        assert b"POST" in canonical
        assert b"abc123" in canonical


class TestHashing:
    """Test SHA-256 hashing."""

    def test_hash_bytes(self):
        """Test hashing bytes."""
        data = b"test data"
        hash_result = Hasher.hash_bytes(data)

        # Should return hex string
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA-256 is 256 bits = 64 hex chars

    def test_hash_string(self):
        """Test hashing strings."""
        data = "test string"
        hash_result = Hasher.hash_string(data)

        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_hash_deterministic(self):
        """Test that hashing is deterministic."""
        data = b"test"

        result1 = Hasher.hash_bytes(data)
        result2 = Hasher.hash_bytes(data)

        assert result1 == result2

    def test_hash_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = Hasher.hash_bytes(b"data1")
        hash2 = Hasher.hash_bytes(b"data2")

        assert hash1 != hash2


class TestEd25519Keys:
    """Test Ed25519 key generation and management."""

    def test_generate_key(self):
        """Test generating a new key pair."""
        key = Ed25519Key.generate()

        assert key.key_id.startswith("ddf:key:")
        assert len(key.verify_key_b64) > 0
        assert len(key.signing_key_bytes) == 32  # Ed25519 private key is 32 bytes

    def test_key_serialization(self):
        """Test key serialization and base64 encoding."""
        key = Ed25519Key.generate()

        # Public key should be valid base64
        public_b64 = key.verify_key_b64
        decoded = base64.b64decode(public_b64)
        assert len(decoded) == 32  # Ed25519 public key is 32 bytes

    def test_load_from_bytes(self):
        """Test loading key from private bytes."""
        original_key = Ed25519Key.generate()
        private_bytes = original_key.signing_key_bytes

        # Load from bytes
        loaded_key = Ed25519Key.from_private_bytes(private_bytes)

        # Should have same public key
        assert loaded_key.verify_key_b64 == original_key.verify_key_b64

    def test_sign_and_verify(self):
        """Test signing and verification."""
        key = Ed25519Key.generate()
        message = b"test message"

        signature_b64 = key.sign(message)

        # Signature should be valid base64
        signature_bytes = base64.b64decode(signature_b64)
        assert len(signature_bytes) == 64  # Ed25519 signature is 64 bytes

    def test_custom_key_id(self):
        """Test using a custom key ID."""
        key = Ed25519Key.generate(key_id="ddf:key:custom")

        assert key.key_id == "ddf:key:custom"


class TestSignatureVerification:
    """Test signature verification."""

    def test_verify_valid_signature(self):
        """Test verifying a valid signature."""
        key = Ed25519Key.generate()
        message = b"test message"
        signature_b64 = key.sign(message)

        # Should verify successfully
        result = Verifier.verify_signature(
            public_key_b64=key.verify_key_b64,
            message=message,
            signature_b64=signature_b64,
        )
        assert result is True

    def test_verify_invalid_signature(self):
        """Test that invalid signature fails verification."""
        key = Ed25519Key.generate()
        message = b"test message"

        # Sign with original message
        signature_b64 = key.sign(message)

        # Try to verify with different message
        with pytest.raises(SignatureVerificationError):
            Verifier.verify_signature(
                public_key_b64=key.verify_key_b64,
                message=b"different message",
                signature_b64=signature_b64,
            )

    def test_verify_wrong_key(self):
        """Test that verification fails with wrong key."""
        key1 = Ed25519Key.generate()
        key2 = Ed25519Key.generate()

        message = b"test message"
        signature_b64 = key1.sign(message)

        # Try to verify with different key
        with pytest.raises(SignatureVerificationError):
            Verifier.verify_signature(
                public_key_b64=key2.verify_key_b64,
                message=message,
                signature_b64=signature_b64,
            )

    def test_verify_malformed_signature(self):
        """Test that malformed signature is rejected."""
        key = Ed25519Key.generate()

        with pytest.raises(SignatureVerificationError):
            Verifier.verify_signature(
                public_key_b64=key.verify_key_b64,
                message=b"test",
                signature_b64="not-valid-base64!!!",
            )


class TestAuthorityVerification:
    """Test authority signature verification."""

    def test_verify_signed_authority(self):
        """Test verifying a signed authority."""
        now = datetime.now(UTC)
        key = Ed25519Key.generate()

        # Create authority
        authority = Authority(
            actor="agent:test",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:test"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key=key.verify_key_b64,
        )

        # Sign it - convert to JSON-serializable dict first
        auth_dict = authority.model_dump()
        auth_dict["issued_at"] = auth_dict["issued_at"].isoformat()
        auth_dict["expires_at"] = auth_dict["expires_at"].isoformat()

        canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(auth_dict)
        signature_b64 = key.sign(canonical_bytes)

        # Add proof
        authority.proof = AuthorityProof(
            algorithm="Ed25519",
            key_id=key.key_id,
            signature=signature_b64,
        )

        # Verify
        result = AuthorityVerifier.verify_authority(authority)
        assert result is True

    def test_verify_unsigned_authority_fails(self):
        """Test that unsigned authority fails verification."""
        now = datetime.now(UTC)

        authority = Authority(
            actor="agent:test",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:test"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key="test_key",
            proof=None,  # No proof
        )

        with pytest.raises(SignatureVerificationError):
            AuthorityVerifier.verify_authority(authority)

    def test_verify_tampered_authority_fails(self):
        """Test that tampered authority fails verification."""
        now = datetime.now(UTC)
        key = Ed25519Key.generate()

        # Create and sign authority
        authority = Authority(
            actor="agent:test",
            sponsor="user:alice@example.com",
            actions=["purchase"],
            resources=["vendor/*"],
            purposes=["procurement"],
            authority_path=["user:alice@example.com", "agent:test"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            holder_public_key=key.verify_key_b64,
        )

        # Convert to JSON-serializable dict and sign
        auth_dict = authority.model_dump()
        auth_dict["issued_at"] = auth_dict["issued_at"].isoformat()
        auth_dict["expires_at"] = auth_dict["expires_at"].isoformat()

        canonical_bytes = CanonicalSerializer.serialize_authority_for_signing(auth_dict)
        signature_b64 = key.sign(canonical_bytes)

        authority.proof = AuthorityProof(
            algorithm="Ed25519",
            key_id=key.key_id,
            signature=signature_b64,
        )

        # Tamper with authority by changing an action
        authority.actions = ["purchase", "delete"]

        # Verification should fail
        with pytest.raises(SignatureVerificationError):
            AuthorityVerifier.verify_authority(authority)

    def test_verify_request_proof(self):
        """Test verifying a request proof."""
        key = Ed25519Key.generate()

        # Create request proof
        actor = "agent:test"
        authority_id = "ddf:authority:123"
        method = "POST"
        path = "/v1/authorize"
        body_hash = "abc123"
        timestamp = "2026-08-13T12:00:00Z"
        nonce = "nonce123"

        canonical_bytes = CanonicalSerializer.serialize_request_proof(
            actor=actor,
            authority_id=authority_id,
            method=method,
            path=path,
            body_hash=body_hash,
            timestamp=timestamp,
            nonce=nonce,
        )
        signature_b64 = key.sign(canonical_bytes)

        # Verify
        result = AuthorityVerifier.verify_request_proof(
            public_key_b64=key.verify_key_b64,
            actor=actor,
            authority_id=authority_id,
            method=method,
            path=path,
            body_hash=body_hash,
            timestamp=timestamp,
            nonce=nonce,
            signature_b64=signature_b64,
        )
        assert result is True

    def test_verify_request_proof_tampering(self):
        """Test that tampering with request proof is detected."""
        key = Ed25519Key.generate()

        actor = "agent:test"
        authority_id = "ddf:authority:123"
        method = "POST"
        path = "/v1/authorize"
        body_hash = "abc123"
        timestamp = "2026-08-13T12:00:00Z"
        nonce = "nonce123"

        canonical_bytes = CanonicalSerializer.serialize_request_proof(
            actor=actor,
            authority_id=authority_id,
            method=method,
            path=path,
            body_hash=body_hash,
            timestamp=timestamp,
            nonce=nonce,
        )
        signature_b64 = key.sign(canonical_bytes)

        # Try to verify with different body_hash
        with pytest.raises(SignatureVerificationError):
            AuthorityVerifier.verify_request_proof(
                public_key_b64=key.verify_key_b64,
                actor=actor,
                authority_id=authority_id,
                method=method,
                path=path,
                body_hash="TAMPERED",  # Different!
                timestamp=timestamp,
                nonce=nonce,
                signature_b64=signature_b64,
            )
