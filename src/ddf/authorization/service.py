"""Authorization decision service for DDF."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.errors import (
    AuthorityExpiredError,
    AuthorityNotFoundError,
)
from ddf.authority.constraints import ConstraintValidator
from ddf.authority.models import (
    Authority,
    AuthorityConstraints,
    AuthorizationDecision,
    AuthorizationRequest,
)
from ddf.db.models import (
    Authority as AuthorityDB,
    AuthorizationLog,
)


class AuthorizationService:
    """Service for making authorization decisions."""

    @staticmethod
    async def authorize(
        session: AsyncSession,
        request: AuthorizationRequest,
    ) -> AuthorizationDecision:
        """
        Make an authorization decision.

        Checks whether an actor can perform an action on a resource for the
        requested purpose using the specified authority.

        Args:
            session: Database session.
            request: Authorization request.

        Returns:
            AuthorizationDecision containing ALLOW or DENY and explanation.

        Raises:
            AuthorityNotFoundError: Authority does not exist.
            AuthorityExpiredError: Authority validity period has expired.
        """
        now = datetime.now(timezone.utc)

        stmt = select(AuthorityDB).where(
            AuthorityDB.authority_id == request.authority_id
        )
        result = await session.execute(stmt)
        auth_db = result.scalar_one_or_none()

        if auth_db is None:
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

            await AuthorizationService._log_decision(
                session=session,
                decision=decision,
                authority_id=request.authority_id,
            )

            raise AuthorityNotFoundError(request.authority_id)

        authority = Authority(
            version=auth_db.version,
            authority_id=auth_db.authority_id,
            actor=auth_db.actor,
            sponsor=auth_db.sponsor,
            actions=auth_db.actions,
            resources=auth_db.resources,
            purposes=auth_db.purposes,
            constraints=AuthorityValidator.reconstruct_constraints(
                auth_db.constraints_json
            ),
            authority_path=auth_db.authority_path,
            issued_at=auth_db.issued_at,
            expires_at=auth_db.expires_at,
            parent_authority_id=auth_db.parent_authority_id,
            holder_public_key=auth_db.holder_public_key,
        )

        if authority.expires_at < now:
            expired_at = authority.expires_at.isoformat()

            decision = AuthorizationDecision(
                decision="DENY",
                actor=request.actor,
                action=request.action,
                resource=request.resource,
                purpose=request.purpose,
                sponsor=authority.sponsor,
                authority_path=authority.authority_path,
                reasons=["authority_expired"],
                details={
                    "authority_id": authority.authority_id,
                    "expires_at": expired_at,
                },
            )

            await AuthorizationService._log_decision(
                session=session,
                decision=decision,
                authority_id=authority.authority_id,
            )

            raise AuthorityExpiredError(
                authority_id=authority.authority_id,
                expired_at=expired_at,
            )

        reasons: list[str] = []
        details: dict = {}

        # Actor
        if authority.actor != request.actor:
            reasons.append("actor_mismatch")
            details["authority_actor"] = authority.actor
            details["request_actor"] = request.actor

        # Action
        if request.action not in authority.actions:
            reasons.append("action_not_permitted")
            details["authority_actions"] = authority.actions
            details["request_action"] = request.action

        # Resource
        resource_matches = any(
            AuthorizationService._resource_matches(
                requested=request.resource,
                permitted=permitted,
            )
            for permitted in authority.resources
        )

        if not resource_matches:
            reasons.append("resource_not_permitted")
            details["authority_resources"] = authority.resources
            details["request_resource"] = request.resource

        # Purpose
        if request.purpose and request.purpose not in authority.purposes:
            reasons.append("purpose_not_permitted")
            details["authority_purposes"] = authority.purposes
            details["request_purpose"] = request.purpose

        # Constraints
        if authority.constraints:
            constraint_validator = ConstraintValidator()

            if not constraint_validator.is_valid_now(
                authority.constraints,
                now,
            ):
                reasons.append("constraint_not_valid_now")
                details["constraint"] = authority.constraints.model_dump()

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

        await AuthorizationService._log_decision(
            session=session,
            decision=decision,
            authority_id=authority.authority_id,
        )

        return decision

    @staticmethod
    def _resource_matches(
        requested: str,
        permitted: str,
    ) -> bool:
        """Check whether requested resource matches permitted resource scope."""
        if requested == permitted:
            return True

        if permitted.endswith("/*"):
            prefix = permitted[:-2]
            return requested.startswith(prefix + "/")

        return False

    @staticmethod
    async def _log_decision(
        session: AsyncSession,
        decision: AuthorizationDecision,
        authority_id: str | None = None,
    ) -> None:
        """Persist an authorization decision."""
        log = AuthorizationLog(
            decision_id=decision.decision_id,
            actor=decision.actor,
            action=decision.action,
            resource=decision.resource,
            purpose=decision.purpose,
            decision=decision.decision,
            authority_id=authority_id,
            reasons=decision.reasons,
            context_json=decision.details,
        )

        session.add(log)
        await session.commit()


class AuthorityValidator:
    """Helper for reconstructing Authority values from database records."""

    @staticmethod
    def reconstruct_constraints(
        constraints_json: dict | None,
    ) -> AuthorityConstraints:
        """Reconstruct AuthorityConstraints from stored JSON."""
        if not constraints_json:
            return AuthorityConstraints()

        return AuthorityConstraints(**constraints_json)
