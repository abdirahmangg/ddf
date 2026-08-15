from __future__ import annotations

import argparse
import asyncio
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from ddf.commercial.production_readiness import (
    discover_identity_keys,
    revoke_identity_key,
    rotate_identity_key,
)


async def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--tenant",
        default="release-drill",
    )
    parser.add_argument(
        "--subject",
        default="release-drill-agent",
    )

    args = parser.parse_args()

    first = "drill-" + secrets.token_hex(8)
    second = "drill-" + secrets.token_hex(8)

    await rotate_identity_key(
        tenant_id=args.tenant,
        subject=args.subject,
        key_id=first,
        public_key=secrets.token_hex(32),
        revoke_previous=True,
    )

    revoked = await revoke_identity_key(
        tenant_id=args.tenant,
        subject=args.subject,
        key_id=first,
    )

    if not revoked:
        raise RuntimeError(
            "compromised key was not revoked"
        )

    await rotate_identity_key(
        tenant_id=args.tenant,
        subject=args.subject,
        key_id=second,
        public_key=secrets.token_hex(32),
        revoke_previous=True,
    )

    keys = await discover_identity_keys(
        tenant_id=args.tenant,
        subject=args.subject,
        requester_subject=args.subject,
        requester_roles=[],
    )

    result = {
        "completed_at": datetime.now(
            UTC
        ).isoformat(),
        "tenant": args.tenant,
        "subject": args.subject,
        "compromised_key": first,
        "replacement_key": second,
        "key_states": [
            {
                "key_id": row["key_id"],
                "status": row["status"],
            }
            for row in keys
        ],
    }

    Path(
        "release-evidence/key-compromise-drill.json"
    ).write_text(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
        + "\n"
    )

    print(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
