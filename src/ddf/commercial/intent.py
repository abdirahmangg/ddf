"""Deterministic natural-language intent -> structured proposal compiler."""

from __future__ import annotations

import json
import re

from ddf.commercial.models import IntentProposal

_AMOUNT = re.compile(
    r"(?P<currency>GBP|USD|EUR|£|\$|€)?\s*"
    r"(?P<amount>\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

_RESOURCE = re.compile(r"(vendor/[A-Za-z0-9_.:/\-*]+)")

_PURPOSE = re.compile(
    r"\bfor\s+([A-Za-z][A-Za-z0-9_-]{1,64})",
    re.IGNORECASE,
)


def compile_intent(text: str) -> IntentProposal:
    stripped = text.strip()

    if stripped.startswith("{"):
        value = json.loads(stripped)
        return IntentProposal(
            **value,
            source="structured",
            confidence=1.0,
        )

    lower = stripped.lower()

    if any(word in lower for word in ("purchase", "buy", "order")):
        action = "purchase"
    elif "read" in lower or "view" in lower:
        action = "read"
    elif "update" in lower or "change" in lower:
        action = "update"
    else:
        raise ValueError("intent compiler could not determine an allowed action")

    resource_match = _RESOURCE.search(stripped)
    if not resource_match:
        raise ValueError("intent compiler requires an explicit resource such as vendor/dell/*")

    purpose_match = _PURPOSE.search(stripped)
    if not purpose_match:
        raise ValueError("intent compiler requires an explicit purpose using 'for <purpose>'")

    amount = None
    currency = None
    amount_match = _AMOUNT.search(stripped)

    if amount_match:
        amount = float(amount_match.group("amount"))
        raw_currency = amount_match.group("currency")

        currency = {
            "£": "GBP",
            "$": "USD",
            "€": "EUR",
        }.get(raw_currency, raw_currency.upper() if raw_currency else None)

    return IntentProposal(
        action=action,
        resource=resource_match.group(1),
        purpose=purpose_match.group(1).lower(),
        amount=amount,
        currency=currency,
        source="rule",
        confidence=1.0,
    )
