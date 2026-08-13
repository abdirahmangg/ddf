"""Authorization decision service for DDF."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.authority.models import Authority, AuthorizationRequest, AuthorizationDecision
from ddf.authority.attenuation import AttenuationEngine
from ddf.authority.constraints import ConstraintValidator
from ddf.db.models import Authority as AuthorityDB, AuthorizationLog
from ddf.api.errors import AuthorityNotFoundError, AuthorityExpiredError, AuthorizationDeniedError


class AuthorizationService:
    """Service for making authorization decisions."""

    @staticmethod
    async def authorize(
        session: AsyncSession,
        request: AuthorizationRequest,
    ) -> AuthorizationDecision:
        """
        Make an authorization decision.

        Checks if actor can perform action on resource for given purpose
        using specified authority.

        Args:
            session: Database session
            request: Authorization request

        Returns:
            Authorization decision (ALLOW or DENY)

        Raises:
            AuthorityNotFoundError: Authority doesn't exist
            AuthorityExpiredError: Authority is expired
        """
        now = datetime.now(timezone.utc)

        # Fetch authority from database
        stmt = select(AuthorityDB).where(
            AuthorityDB.authority_id == request.authority_id
        )
        result = await session.execute(stmt)
        auth_db = result.scalar_one_or_none()

        if not auth_db:
            decision = AuthorizationDecision(
                decision="DENY",
                actor=request.actor,
                action=request.action,
                resource=request.resource,
                purpose=request.purpose,
                sponsor="unknown",
                authority_path=[],
                reasons=["authority_not_found"],
                details={"authority_id": request.authority_id},
            )
            await AuthorizationService._log_decision(session, decision)
            raise AuthorityNotFoundError(f"Authority not found: {request.authority_id}")

        # Reconstruct Authority from DB record
        authority = Authority(
            version=auth_db.version,
            authority_id=auth_db.authority_id,
            actor=auth_db.actor,
            sponsor=auth_db.sponsor,
            actions=auth_db.actions,
            resources=auth_db.resources,
            purposes=auth_db.purposes,
            constraints=AuthorityValidator.reconstruct_constraints(auth_db.constraints_json),
            authority_path=auth_db.authority_path,
            issued_at=auth_db.issued_at,
            expires_at=auth_db.expires_at,
            parent_authority_id=auth_db.parent_authority_id,
            holder_public_key=auth_db.holder_public_key,
        )

        # Check expiration
        if authority.expires_at < now:
            decision = AuthorizationDecision(
                decision="DENY",
                actor=request.actor,
                action=request.action,
                resource=request.resource,
                purpose=request.purpose,
                sponsor=authority.sponsor,
                authority_path=authority.authority_path,
                reasons=["authority_expired"],
                details={"expires_at": authority.expires_at.isoformat()},
            )
            await AuthorizationService._log_decision(session, decision)
            raise AuthorityExpiredError(f"Authority expired: {authority.authority_id}")

        # Evaluate authorization
        reasons = []
        details = {}

        # Check actor
        if authority.actor != request.actor:
            reasons.append("actor_mismatch")
            details["authority_actor"] = authority.actor
            details["request_actor"] = request.actor

        # Check action
        if request.action not in authority.actions:
            reasons.append("action_not_permitted")
            details["authority_actions"] = authority.actions
            details["request_action"] = request.action

        # Check resource (hierarchical matching)
        resource_matches = any(
            AuthorizationService._resource_matches(request.resource, permitted)
            for permitted in authority.resources
        )
        if not resource_matches:
            reasons.append("resource_not_permitted")
            details["authority_resources"] = authority.resources
            details["request_resource"] = request.resource

        # Check purpose
        if request.purpose and request.purpose not in authority.purposes:
            reasons.append("purpose_not_permitted")
            details["authority_purposes"] = authority.purposes
            details["request_purpose"] = request.purpose

        # Check constraints
        if authority.constraints:
            constraint_validator = ConstraintValidator()
            if not constraint_validator.is_valid_now(authority.constraints, now):
                reasons.append("constraint_not_valid_now")
                details["constraint"] = authority.constraints.model_dump()

        # Make decision
        if reasons:
            decision = AuthorizationDecision(
                decision="DENY",
                actor=request.actor,
                action=request.action,
                resource=request.resource,
                purpose=request.purpose,
                sponsor=authority.sponsor,
                authority_path=authority.authority_path,
                reasons=reasons,
                details=details,
            )
        else:
            decision = AuthorizationDecision(
                decision="ALLOW",
                actor=request.actor,
                action=request.action,
                resource=request.resource,
                purpose=request.purpose,
                sponsor=authority.sponsor,
                authority_path=authority.authority_path,
                effective_constraints=authority.constraints,
                valid_until=authority.expires_at,
                reasons=["all_checks_passed"],
                details={},
            )

        # Log decision
        await AuthorizationService._log_decision(session, decision)
        return decision

    @staticmethod
    def _resource_matches(requested: str, permitted: str) -> bool:
        """Check if requested resource matches permitted pattern."""
        # Exact match
        if requested == permitted:
            return True

        # Wildcard match: vendor/* matches vendor/dell
        if permitted.endswith("/*"):
            prefix = permitted[:-2]
            return requested.startswith(prefix + "/")

        return False

    @staticmethod
    async def _log_decision(session: AsyncSession, decision: AuthorizationDecision):
        """Log authorization decision to database."""
        log = AuthorizationLog(
            decision_id=decision.decision_id,
            actor=decision.actor,
            action=decision.action,
            resource=decision.resource,
            purpose=decision.purpose,
            decision=decision.decision,
            authority_id=decision.authority_path[0] if decision.authority_path else None,
            reasons=decision.reasons,
            context_json=decision.details,
        )
        session.add(log)
        await session.commit()


class AuthorityValidator:
    """Helper for reconstructing Authority from database records."""

    @staticmethod
    def reconstruct_constraints(constraints_json: dict):
        """Reconstruct AuthorityConstraints from database JSON."""
        from ddf.authority.models import AuthorityConstraints
        
        if not constraints_json:
            return AuthorityConstraints()
        
        return AuthorityConstraints(**constraints_json)
