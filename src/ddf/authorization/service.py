"""Full multi-hop authorization decision service for DDF."""

import base64
import json
from datetime import UTC, datetime
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from sqlalchemy.ext.asyncio import AsyncSession

from ddf.api.errors import (
    AuthorityExpiredError,
    AuthorityRevokedError,
    ProofOfPossessionError,
    SignatureVerificationError,
)
from ddf.authority.effective import (
    EffectiveAuthority,
    calculate_effective_authority,
    load_authority_chain,
)
from ddf.authority.models import (
    Authority,
    AuthorizationDecision,
    AuthorizationRequest,
)
from ddf.crypto.canonical import CanonicalSerializer
from ddf.db.models import AuthorizationLog
from ddf.policy.openfga import OpenFGAPolicy
from ddf.provenance.service import ProvenanceService
from ddf.revocation.service import RevocationService


class AuthorizationService:
    """Evaluate DDF authority across the full delegation chain."""

    @staticmethod
    async def authorize(
        session: AsyncSession,
        request: AuthorizationRequest,
    ) -> AuthorizationDecision:
        """Make a complete multi-hop authorization decision."""
        now = datetime.now(UTC)

        chain = await load_authority_chain(
            session,
            request.authority_id,
        )

        for authority in chain:
            if authority.expires_at < now:
                decision = AuthorizationService._decision(
                    request=request,
                    authority=authority,
                    decision="DENY",
                    reasons=["authority_expired"],
                    details={
                        "authority_id": authority.authority_id,
                        "expires_at": (authority.expires_at.isoformat()),
                    },
                )

                await AuthorizationService._record_decision(
                    session,
                    decision,
                    request.authority_id,
                )

                await session.commit()

                raise AuthorityExpiredError(
                    authority.authority_id,
                    authority.expires_at.isoformat(),
                )

            AuthorizationService.verify_authority_signature(authority)

        if await RevocationService.is_effectively_revoked(
            session,
            request.authority_id,
        ):
            leaf = chain[-1]

            decision = AuthorizationService._decision(
                request=request,
                authority=leaf,
                decision="DENY",
                reasons=["authority_revoked"],
                details={
                    "authority_id": request.authority_id,
                },
            )

            await AuthorizationService._record_decision(
                session,
                decision,
                request.authority_id,
            )

            await session.commit()

            raise AuthorityRevokedError(request.authority_id)

        effective = calculate_effective_authority(chain)
        leaf = chain[-1]

        AuthorizationService.verify_proof_of_possession(
            request=request,
            authority=leaf,
        )

        reasons: list[str] = []
        details: dict[str, Any] = {}

        if effective.actor != request.actor:
            reasons.append("actor_mismatch")
            details["authority_actor"] = effective.actor
            details["request_actor"] = request.actor

        if request.action not in effective.actions:
            reasons.append("action_not_permitted")
            details["authority_actions"] = effective.actions
            details["request_action"] = request.action

        resource_allowed = any(
            AuthorizationService._resource_matches(
                request.resource,
                permitted,
            )
            for permitted in effective.resources
        )

        if not resource_allowed:
            reasons.append("resource_not_permitted")
            details["authority_resources"] = effective.resources
            details["request_resource"] = request.resource

        if request.purpose not in effective.purposes:
            reasons.append("purpose_not_permitted")
            details["authority_purposes"] = effective.purposes
            details["request_purpose"] = request.purpose

        AuthorizationService._evaluate_constraints(
            request=request,
            effective=effective,
            reasons=reasons,
            details=details,
        )

        openfga = OpenFGAPolicy.from_env()

        if openfga.enabled:
            relation = request.context.get(
                "openfga_relation",
                "operator",
            )
            object_id = request.context.get(
                "openfga_object",
                f"resource:{request.resource}",
            )
            user = request.context.get(
                "openfga_user",
                request.actor,
            )

            relationship_allowed = await openfga.check(
                user=user,
                relation=relation,
                object=object_id,
            )

            if not relationship_allowed:
                reasons.append("openfga_denied")
                details["openfga"] = {
                    "user": user,
                    "relation": relation,
                    "object": object_id,
                }

        if reasons:
            decision = AuthorizationDecision(
                decision="DENY",
                actor=request.actor,
                action=request.action,
                resource=request.resource,
                purpose=request.purpose,
                sponsor=effective.sponsor,
                authority_path=effective.authority_path,
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
                sponsor=effective.sponsor,
                authority_path=effective.authority_path,
                effective_constraints=effective.constraints,
                valid_until=effective.valid_until,
                reasons=[
                    "authority_chain_valid",
                    "all_checks_passed",
                ],
                details={"authority_ids": (effective.authority_ids)},
            )

        await AuthorizationService._record_decision(
            session,
            decision,
            request.authority_id,
        )

        await session.commit()

        return decision

    @staticmethod
    def verify_authority_signature(
        authority: Authority,
    ) -> None:
        """
        Verify a signed authority.

        Unsigned authorities remain supported for the local v0.1
        compatibility path. When a proof is present, verification is strict.
        """
        if authority.proof is None:
            return

        if not authority.holder_public_key:
            raise SignatureVerificationError("signed authority has no verification key")

        payload = authority.model_dump()
        payload["proof"] = None

        canonical = CanonicalSerializer.serialize_authority_for_signing(payload)

        try:
            verify_key = VerifyKey(base64.b64decode(authority.holder_public_key))

            verify_key.verify(
                canonical,
                base64.b64decode(authority.proof.signature),
            )
        except Exception as exc:
            raise SignatureVerificationError("authority signature is invalid") from exc

    @staticmethod
    def request_proof_message(
        request: AuthorizationRequest,
    ) -> bytes:
        """Return deterministic bytes for request proof-of-possession."""
        context = dict(request.context)
        context.pop(
            "proof_of_possession",
            None,
        )

        payload = {
            "actor": request.actor,
            "action": request.action,
            "resource": request.resource,
            "purpose": request.purpose,
            "authority_id": request.authority_id,
            "context": context,
        }

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

    @staticmethod
    def verify_proof_of_possession(
        *,
        request: AuthorizationRequest,
        authority: Authority,
    ) -> None:
        """
        Require possession of the holder key when an authority is key-bound.
        """
        if not authority.holder_public_key:
            return

        proof = request.context.get("proof_of_possession")

        if not isinstance(proof, dict):
            raise ProofOfPossessionError("request proof is required")

        supplied_public_key = proof.get("public_key")
        signature = proof.get("signature")

        if supplied_public_key != authority.holder_public_key:
            raise ProofOfPossessionError("request was signed by a different key")

        if not signature:
            raise ProofOfPossessionError("request signature is missing")

        try:
            verify_key = VerifyKey(base64.b64decode(authority.holder_public_key))

            verify_key.verify(
                AuthorizationService.request_proof_message(request),
                base64.b64decode(signature),
            )
        except (
            BadSignatureError,
            ValueError,
            TypeError,
        ) as exc:
            raise ProofOfPossessionError("request signature is invalid") from exc

    @staticmethod
    def _evaluate_constraints(
        *,
        request: AuthorizationRequest,
        effective: EffectiveAuthority,
        reasons: list[str],
        details: dict[str, Any],
    ) -> None:
        constraints = effective.constraints
        context = request.context

        max_amount = getattr(
            constraints,
            "max_amount",
            None,
        )
        amount = context.get("amount")

        if max_amount is not None and amount is not None and amount > max_amount:
            reasons.append("AMOUNT_EXCEEDS_EFFECTIVE_AUTHORITY")
            details["max_amount"] = max_amount
            details["requested_amount"] = amount

        constraint_currency = getattr(
            constraints,
            "currency",
            None,
        )
        request_currency = context.get("currency")

        if constraint_currency and request_currency and request_currency != constraint_currency:
            reasons.append("currency_not_permitted")
            details["authority_currency"] = constraint_currency
            details["request_currency"] = request_currency

        geographies = getattr(
            constraints,
            "geographies",
            None,
        )
        geography = context.get("geography")

        if geographies and geography and geography not in geographies:
            reasons.append("geography_not_permitted")
            details["authority_geographies"] = geographies
            details["request_geography"] = geography

        audiences = getattr(
            constraints,
            "audiences",
            None,
        )
        audience = context.get("audience")

        if audiences and audience and audience not in audiences:
            reasons.append("audience_not_permitted")
            details["authority_audiences"] = audiences
            details["request_audience"] = audience

    @staticmethod
    def _decision(
        *,
        request: AuthorizationRequest,
        authority: Authority,
        decision: str,
        reasons: list[str],
        details: dict[str, Any],
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            decision=decision,
            actor=request.actor,
            action=request.action,
            resource=request.resource,
            purpose=request.purpose,
            sponsor=authority.sponsor,
            authority_path=authority.authority_path,
            reasons=reasons,
            details=details,
        )

    @staticmethod
    def _resource_matches(
        requested: str,
        permitted: str,
    ) -> bool:
        """Match a resource against an exact or hierarchical wildcard."""
        if requested == permitted:
            return True

        if permitted.endswith("/*"):
            prefix = permitted[:-2]
            return requested.startswith(prefix + "/")

        return False

    @staticmethod
    async def _record_decision(
        session: AsyncSession,
        decision: AuthorizationDecision,
        authority_id: str,
    ) -> None:
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

        await ProvenanceService.record_event(
            session,
            event_type=(
                "authorization_allowed" if decision.decision == "ALLOW" else "authorization_denied"
            ),
            authority_id=authority_id,
            actor=decision.actor,
            sponsor=decision.sponsor,
            action=decision.action,
            resource=decision.resource,
            details={
                "decision_id": decision.decision_id,
                "purpose": decision.purpose,
                "reasons": decision.reasons,
            },
        )

    @staticmethod
    async def _log_decision(
        session: AsyncSession,
        decision: AuthorizationDecision,
        authority_id: str | None = None,
    ) -> None:
        """Compatibility helper retained for existing callers/tests."""
        await AuthorizationService._record_decision(
            session,
            decision,
            authority_id or "",
        )
        await session.commit()
