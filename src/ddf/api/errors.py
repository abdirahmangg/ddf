"""API error models and exception handlers."""

from typing import Any, Optional

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Detailed information about an error."""

    code: str = Field(
        description="Machine-readable error code"
    )
    message: str = Field(
        description="Human-readable error message"
    )
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Additional context-specific details",
    )


class ErrorResponse(BaseModel):
    """Standard API error response."""

    error: ErrorDetail


class HTTPException(Exception):
    """Base HTTP exception for DDF API errors."""

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        """Initialize HTTP exception.

        Args:
            status_code: HTTP status code
            error_code: Machine-readable error code
            message: Human-readable error message
            details: Additional context-specific details
        """
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def to_response(self) -> ErrorResponse:
        """Convert to ErrorResponse."""
        return ErrorResponse(
            error=ErrorDetail(
                code=self.error_code,
                message=self.message,
                details=self.details or None,
            )
        )


# Specific error types

class AuthorityNotFoundError(HTTPException):
    """Authority does not exist."""

    def __init__(self, authority_id: str):
        super().__init__(
            status_code=404,
            error_code="AUTHORITY_NOT_FOUND",
            message=f"Authority {authority_id} not found",
            details={"authority_id": authority_id},
        )


class AuthorityExpiredError(HTTPException):
    """Authority has expired."""

    def __init__(self, authority_id: str, expired_at: str):
        super().__init__(
            status_code=403,
            error_code="AUTHORITY_EXPIRED",
            message=f"Authority {authority_id} expired at {expired_at}",
            details={"authority_id": authority_id, "expired_at": expired_at},
        )


class AuthorityRevokedError(HTTPException):
    """Authority has been revoked."""

    def __init__(self, authority_id: str):
        super().__init__(
            status_code=403,
            error_code="AUTHORITY_REVOKED",
            message=f"Authority {authority_id} has been revoked",
            details={"authority_id": authority_id},
        )


class AttenuationViolationError(HTTPException):
    """Child authority violates attenuation constraints."""

    def __init__(self, violations: list[str], details: Optional[dict[str, Any]] = None):
        msg = f"Authority attenuation violation: {', '.join(violations)}"
        super().__init__(
            status_code=403,
            error_code="ATTENUATION_VIOLATION",
            message=msg,
            details=details or {"violations": violations},
        )


class ProofOfPossessionError(HTTPException):
    """Proof of possession validation failed."""

    def __init__(self, reason: str):
        super().__init__(
            status_code=403,
            error_code="PROOF_OF_POSSESSION_FAILED",
            message=f"Proof of possession failed: {reason}",
            details={"reason": reason},
        )


class InvalidAuthorityPathError(HTTPException):
    """Authority path is invalid or tampered."""

    def __init__(self, details: Optional[dict[str, Any]] = None):
        super().__init__(
            status_code=403,
            error_code="INVALID_AUTHORITY_PATH",
            message="Authority path validation failed",
            details=details or {},
        )


class SignatureVerificationError(HTTPException):
    """Cryptographic signature verification failed."""

    def __init__(self, reason: str):
        super().__init__(
            status_code=403,
            error_code="SIGNATURE_VERIFICATION_FAILED",
            message=f"Signature verification failed: {reason}",
            details={"reason": reason},
        )


class AuthorizationDeniedError(HTTPException):
    """Authorization request was denied."""

    def __init__(self, reason: str, details: Optional[dict[str, Any]] = None):
        super().__init__(
            status_code=403,
            error_code="AUTHORIZATION_DENIED",
            message=f"Authorization denied: {reason}",
            details=details or {"reason": reason},
        )


class InvalidIdentityError(HTTPException):
    """Identity is invalid or does not exist."""

    def __init__(self, identity_id: str):
        super().__init__(
            status_code=404,
            error_code="INVALID_IDENTITY",
            message=f"Identity {identity_id} not found or invalid",
            details={"identity_id": identity_id},
        )


class ValidationError(HTTPException):
    """Request validation failed."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        super().__init__(
            status_code=400,
            error_code="VALIDATION_ERROR",
            message=message,
            details=details or {},
        )


class DatabaseError(HTTPException):
    """Database operation failed."""

    def __init__(self, message: str):
        super().__init__(
            status_code=500,
            error_code="DATABASE_ERROR",
            message=message,
            details={},
        )


class InternalServerError(HTTPException):
    """Internal server error."""

    def __init__(self, message: str = "Internal server error"):
        super().__init__(
            status_code=500,
            error_code="INTERNAL_SERVER_ERROR",
            message=message,
            details={},
        )
