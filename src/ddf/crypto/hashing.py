"""Hashing utilities for DDF.

All hashing uses SHA-256 for provenance and identification.
"""

import hashlib
from typing import Union


class Hasher:
    """SHA-256 hashing utilities."""

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        """
        Hash bytes with SHA-256.

        Args:
            data: Bytes to hash

        Returns:
            Hex-encoded hash digest
        """
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_string(data: str) -> str:
        """
        Hash string with SHA-256.

        Args:
            data: String to hash

        Returns:
            Hex-encoded hash digest
        """
        return Hasher.hash_bytes(data.encode("utf-8"))

    @staticmethod
    def hash_json(data: bytes) -> str:
        """
        Hash JSON bytes with SHA-256.

        Args:
            data: JSON bytes to hash

        Returns:
            Hex-encoded hash digest
        """
        return Hasher.hash_bytes(data)
