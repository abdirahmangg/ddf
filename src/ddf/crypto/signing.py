"""Ed25519 signing and verification for DDF.

All cryptographic signing uses Ed25519 via PyNaCl (libsodium).
This is a well-vetted, production-grade library.

Do not implement custom cryptography.
"""

import base64

import nacl.exceptions
import nacl.signing
import nacl.utils

from ddf.api.errors import SignatureVerificationError


class Ed25519Key:
    """Represents an Ed25519 signing key pair."""

    def __init__(self, signing_key: nacl.signing.SigningKey, key_id: str | None = None):
        """
        Initialize from a PyNaCl signing key.

        Args:
            signing_key: PyNaCl SigningKey
            key_id: Optional key ID (defaults to hash of public key)
        """
        self._signing_key = signing_key
        self.key_id = key_id or self._default_key_id()

    @property
    def signing_key_bytes(self) -> bytes:
        """Get the private key bytes (for local key storage)."""
        return bytes(self._signing_key)

    @property
    def verify_key_bytes(self) -> bytes:
        """Get the public key bytes (for sharing)."""
        return bytes(self._signing_key.verify_key)

    @property
    def verify_key_b64(self) -> str:
        """Get public key as base64 (for authority documents)."""
        return base64.b64encode(self.verify_key_bytes).decode("utf-8")

    def _default_key_id(self) -> str:
        """Generate default key ID from public key hash."""
        import hashlib

        pub_hash = hashlib.sha256(self.verify_key_bytes).hexdigest()[:12]
        return f"ddf:key:{pub_hash}"

    def sign(self, message: bytes) -> str:
        """
        Sign a message.

        Args:
            message: Message bytes to sign

        Returns:
            Base64-encoded signature
        """
        signature = self._signing_key.sign(message).signature
        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def generate(key_id: str | None = None) -> "Ed25519Key":
        """
        Generate a new Ed25519 key pair.

        Args:
            key_id: Optional key ID (defaults to hash of public key)

        Returns:
            New Ed25519Key
        """
        signing_key = nacl.signing.SigningKey.generate()
        return Ed25519Key(signing_key, key_id)

    @staticmethod
    def from_private_bytes(private_bytes: bytes, key_id: str | None = None) -> "Ed25519Key":
        """
        Load from private key bytes.

        Args:
            private_bytes: 32-byte private key
            key_id: Optional key ID

        Returns:
            Ed25519Key
        """
        try:
            signing_key = nacl.signing.SigningKey(private_bytes)
            return Ed25519Key(signing_key, key_id)
        except nacl.exceptions.ValueError as e:
            raise ValueError(f"Invalid private key: {e}") from e


class Verifier:
    """Verifies Ed25519 signatures."""

    @staticmethod
    def verify_signature(
        public_key_b64: str,
        message: bytes,
        signature_b64: str,
    ) -> bool:
        """
        Verify an Ed25519 signature.

        Args:
            public_key_b64: Base64-encoded public key
            message: Original message bytes
            signature_b64: Base64-encoded signature

        Returns:
            True if signature is valid

        Raises:
            SignatureVerificationError: If verification fails
        """
        try:
            # Decode base64
            public_key_bytes = base64.b64decode(public_key_b64)
            signature_bytes = base64.b64decode(signature_b64)

            # Create verify key
            verify_key = nacl.signing.VerifyKey(public_key_bytes)

            # Verify
            verify_key.verify(message, signature_bytes)
            return True

        except (ValueError, TypeError) as e:
            raise SignatureVerificationError(f"Invalid base64 encoding: {e}") from e
        except nacl.exceptions.BadSignatureError as e:
            raise SignatureVerificationError(f"Signature verification failed: {e}") from e
        except nacl.exceptions.ValueError as e:
            raise SignatureVerificationError(f"Invalid key format: {e}") from e
