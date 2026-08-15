"""Commercial production-readiness controls for DDF.

These controls are deliberately fail-closed in production mode.

They do not turn a software release into a compliance certification.
External assurance remains a separate release gate.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import asyncpg  # type: ignore[import-untyped]
import httpx
import jwt
import redis.asyncio as redis
from nacl.signing import SigningKey, VerifyKey
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from sqlalchemy import select
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ddf.commercial.db import EvidenceRecord

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_REQUESTS = Counter(
    "ddf_http_requests_total",
    "DDF HTTP requests",
    ["method", "path", "status"],
)

_LATENCY = Histogram(
    "ddf_http_request_duration_seconds",
    "DDF HTTP request latency",
    ["method", "path"],
)

_pg_pool: Any = None
_redis_client: Any = None


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _environment() -> str:
    return os.getenv(
        "DDF_ENVIRONMENT",
        "development",
    ).strip().lower()


def _is_production() -> bool:
    return _environment() == "production"


def _database_url() -> str:
    url = (
        os.getenv("DDF_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or ""
    )

    return url.replace(
        "postgresql+asyncpg://",
        "postgresql://",
        1,
    )


def _header(
    scope: Scope,
    name: str,
) -> str | None:
    wanted = name.lower().encode()

    for key, value in scope.get("headers", []):
        if key.lower() == wanted:
            decoded = value.decode(
                "utf-8",
                errors="replace",
            )
            return str(decoded)

    return None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode()


def validate_production_environment() -> None:
    """Refuse obviously unsafe production configuration."""

    if not _is_production():
        return

    errors: list[str] = []

    if not _env_bool(
        "DDF_REQUIRE_TLS",
        default=True,
    ):
        errors.append(
            "DDF_REQUIRE_TLS must be enabled"
        )

    redis_url = os.getenv("DDF_REDIS_URL", "").strip()

    if not redis_url:
        errors.append(
            "DDF_REDIS_URL is required"
        )

    database_url = _database_url()

    if not database_url.startswith(
        ("postgresql://", "postgres://")
    ):
        errors.append(
            "production DATABASE_URL must use PostgreSQL"
        )

    bootstrap = os.getenv(
        "DDF_BOOTSTRAP_TOKEN",
        "",
    )

    if len(bootstrap) < 32:
        errors.append(
            "DDF_BOOTSTRAP_TOKEN must contain at least 32 characters"
        )

    max_body = int(
        os.getenv(
            "DDF_MAX_REQUEST_BYTES",
            str(1024 * 1024),
        )
    )

    if max_body <= 0 or max_body > 10 * 1024 * 1024:
        errors.append(
            "DDF_MAX_REQUEST_BYTES must be between 1 byte and 10 MiB"
        )

    if _env_bool(
        "DDF_ENABLE_CAPABILITY_BROKERS",
        False,
    ) and not os.getenv(
        "DDF_CAPABILITY_BROKER_POLICY",
        "",
    ):
        errors.append(
            "broker support requires DDF_CAPABILITY_BROKER_POLICY"
        )

    if errors:
        raise RuntimeError(
            "unsafe production configuration: "
            + "; ".join(errors)
        )


async def get_pg_pool() -> Any:
    global _pg_pool

    if _pg_pool is not None:
        return _pg_pool

    url = _database_url()

    if not url:
        raise RuntimeError(
            "database URL is not configured"
        )

    _pg_pool = await asyncpg.create_pool(
        dsn=url,
        min_size=int(
            os.getenv(
                "DDF_DB_POOL_MIN",
                "2",
            )
        ),
        max_size=int(
            os.getenv(
                "DDF_DB_POOL_MAX",
                "20",
            )
        ),
        command_timeout=float(
            os.getenv(
                "DDF_DB_COMMAND_TIMEOUT_SECONDS",
                "10",
            )
        ),
    )

    return _pg_pool


async def get_redis() -> Any:
    global _redis_client

    if _redis_client is not None:
        return _redis_client

    url = os.getenv(
        "DDF_REDIS_URL",
        "",
    ).strip()

    if not url:
        raise RuntimeError(
            "Redis is not configured"
        )

    _redis_client = redis.from_url(
        url,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )

    return _redis_client


async def _simple_response(
    send: Send,
    status: int,
    payload: dict[str, Any],
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = _canonical_json(payload)

    headers = [
        (
            b"content-type",
            b"application/json",
        ),
        (
            b"content-length",
            str(len(body)).encode(),
        ),
    ]

    if extra_headers:
        headers.extend(extra_headers)

    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        }
    )

    await send(
        {
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        }
    )


class BodyLimitMiddleware:
    """Enforce a hard body-size ceiling even without Content-Length."""

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int | None = None,
    ) -> None:
        self.app = app
        self.max_bytes = (
            max_bytes
            if max_bytes is not None
            else int(
                os.getenv(
                    "DDF_MAX_REQUEST_BYTES",
                    str(1024 * 1024),
                )
            )
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        length = _header(
            scope,
            "content-length",
        )

        if length is not None:
            try:
                if int(length) > self.max_bytes:
                    await _simple_response(
                        send,
                        413,
                        {
                            "detail": "request body too large",
                        },
                    )
                    return
            except ValueError:
                await _simple_response(
                    send,
                    400,
                    {
                        "detail": "invalid Content-Length",
                    },
                )
                return

        messages: list[Message] = []
        total = 0

        while True:
            message = await receive()

            if message["type"] != "http.request":
                messages.append(message)
                break

            body = message.get(
                "body",
                b"",
            )

            total += len(body)

            if total > self.max_bytes:
                await _simple_response(
                    send,
                    413,
                    {
                        "detail": "request body too large",
                    },
                )
                return

            messages.append(message)

            if not message.get(
                "more_body",
                False,
            ):
                break

        index = 0

        async def replay_receive() -> Message:
            nonlocal index

            if index < len(messages):
                message = messages[index]
                index += 1
                return message

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        await self.app(
            scope,
            replay_receive,
            send,
        )


class TLSRequiredMiddleware:
    def __init__(
        self,
        app: ASGIApp,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if (
            scope["type"] != "http"
            or not _is_production()
            or not _env_bool(
                "DDF_REQUIRE_TLS",
                True,
            )
        ):
            await self.app(
                scope,
                receive,
                send,
            )
            return

        scheme = str(
            scope.get(
                "scheme",
                "http",
            )
        ).lower()

        if _env_bool(
            "DDF_TRUST_PROXY_HEADERS",
            False,
        ):
            forwarded = _header(
                scope,
                "x-forwarded-proto",
            )

            if forwarded:
                scheme = (
                    forwarded.split(
                        ",",
                        1,
                    )[0]
                    .strip()
                    .lower()
                )

        if scheme != "https":
            await _simple_response(
                send,
                400,
                {
                    "detail": "HTTPS is required",
                },
            )
            return

        await self.app(
            scope,
            receive,
            send,
        )


class DistributedRateLimitMiddleware:
    """Redis-backed fixed-window limiter.

    Production fails closed if Redis is unavailable.
    """

    _SCRIPT = """
local value = redis.call('INCR', KEYS[1])
if value == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return value
"""

    def __init__(
        self,
        app: ASGIApp,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        limit = int(
            os.getenv(
                "DDF_RATE_LIMIT_PER_MINUTE",
                "120",
            )
        )

        if limit <= 0:
            await self.app(
                scope,
                receive,
                send,
            )
            return

        tenant = (
            _header(
                scope,
                "x-ddf-tenant",
            )
            or "anonymous"
        )

        principal = (
            _header(
                scope,
                "x-ddf-principal",
            )
            or "anonymous"
        )

        window = int(
            time.time()
            // 60
        )

        key = (
            "ddf:rate:"
            f"{tenant}:"
            f"{principal}:"
            f"{window}"
        )

        try:
            client = await get_redis()

            count = int(
                await client.eval(
                    self._SCRIPT,
                    1,
                    key,
                    70,
                )
            )
        except Exception:
            if _is_production():
                await _simple_response(
                    send,
                    503,
                    {
                        "detail": (
                            "rate-limit dependency unavailable"
                        ),
                    },
                )
                return

            await self.app(
                scope,
                receive,
                send,
            )
            return

        if count > limit:
            await _simple_response(
                send,
                429,
                {
                    "detail": "rate limit exceeded",
                },
                [
                    (
                        b"retry-after",
                        b"60",
                    )
                ],
            )
            return

        await self.app(
            scope,
            receive,
            send,
        )


class DurableIdempotencyMiddleware:
    """PostgreSQL-backed mutation idempotency."""

    def __init__(
        self,
        app: ASGIApp,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") not in _MUTATING_METHODS
            or not str(
                scope.get(
                    "path",
                    "",
                )
            ).startswith(
                "/v1/commercial"
            )
        ):
            await self.app(
                scope,
                receive,
                send,
            )
            return

        key = _header(
            scope,
            "x-ddf-idempotency-key",
        )

        if not key:
            if (
                _is_production()
                and _env_bool(
                    "DDF_REQUIRE_IDEMPOTENCY",
                    True,
                )
            ):
                await _simple_response(
                    send,
                    428,
                    {
                        "detail": (
                            "X-DDF-Idempotency-Key is required"
                        ),
                    },
                )
                return

            await self.app(
                scope,
                receive,
                send,
            )
            return

        if len(key) > 256:
            await _simple_response(
                send,
                400,
                {
                    "detail": "idempotency key too long",
                },
            )
            return

        tenant = _header(
            scope,
            "x-ddf-tenant",
        )

        if not tenant:
            await self.app(
                scope,
                receive,
                send,
            )
            return

        messages: list[Message] = []
        body_parts: list[bytes] = []

        while True:
            message = await receive()
            messages.append(message)

            if message["type"] == "http.request":
                body_parts.append(
                    message.get(
                        "body",
                        b"",
                    )
                )

                if not message.get(
                    "more_body",
                    False,
                ):
                    break
            else:
                break

        body = b"".join(
            body_parts
        )

        method = str(
            scope.get(
                "method",
                "",
            )
        )

        path = str(
            scope.get(
                "path",
                "",
            )
        )

        query = bytes(
            scope.get(
                "query_string",
                b"",
            )
        )

        digest = hashlib.sha256(
            method.encode()
            + b"\n"
            + path.encode()
            + b"\n"
            + query
            + b"\n"
            + body
        ).hexdigest()

        try:
            pool = await get_pg_pool()
        except Exception:
            if _is_production():
                await _simple_response(
                    send,
                    503,
                    {
                        "detail": (
                            "idempotency dependency unavailable"
                        ),
                    },
                )
                return

            pool = None

        if pool is None:
            await self.app(
                scope,
                receive,
                send,
            )
            return

        async with pool.acquire() as connection:
            inserted = await connection.fetchrow(
                """
                INSERT INTO ddf_idempotency_v2 (
                    tenant_id,
                    idempotency_key,
                    request_hash,
                    state,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, 'pending', now(), now())
                ON CONFLICT DO NOTHING
                RETURNING tenant_id
                """,
                tenant,
                key,
                digest,
            )

            if inserted is None:
                existing = await connection.fetchrow(
                    """
                    SELECT
                        request_hash,
                        state,
                        status_code,
                        response_body,
                        content_type
                    FROM ddf_idempotency_v2
                    WHERE tenant_id = $1
                      AND idempotency_key = $2
                    """,
                    tenant,
                    key,
                )

                if existing is None:
                    await _simple_response(
                        send,
                        409,
                        {
                            "detail": (
                                "idempotency state unavailable"
                            ),
                        },
                    )
                    return

                if existing["request_hash"] != digest:
                    await _simple_response(
                        send,
                        409,
                        {
                            "detail": (
                                "idempotency key reused "
                                "for a different request"
                            ),
                        },
                    )
                    return

                if existing["state"] == "completed":
                    cached = bytes(
                        existing["response_body"]
                        or b""
                    )

                    content_type = (
                        existing["content_type"]
                        or "application/json"
                    )

                    await send(
                        {
                            "type": "http.response.start",
                            "status": (
                                existing["status_code"]
                                or 200
                            ),
                            "headers": [
                                (
                                    b"content-type",
                                    content_type.encode(),
                                ),
                                (
                                    b"content-length",
                                    str(
                                        len(cached)
                                    ).encode(),
                                ),
                                (
                                    b"x-ddf-idempotent-replay",
                                    b"true",
                                ),
                            ],
                        }
                    )

                    await send(
                        {
                            "type": "http.response.body",
                            "body": cached,
                            "more_body": False,
                        }
                    )
                    return

                await _simple_response(
                    send,
                    409,
                    {
                        "detail": (
                            "idempotent request is already in progress"
                        ),
                    },
                )
                return

        index = 0

        async def replay_receive() -> Message:
            nonlocal index

            if index < len(messages):
                message = messages[index]
                index += 1
                return message

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        captured: list[Message] = []

        async def capture_send(
            message: Message,
        ) -> None:
            captured.append(
                message
            )

        try:
            await self.app(
                scope,
                replay_receive,
                capture_send,
            )
        except Exception:
            async with pool.acquire() as connection:
                await connection.execute(
                    """
                    UPDATE ddf_idempotency_v2
                    SET state = 'failed',
                        updated_at = now()
                    WHERE tenant_id = $1
                      AND idempotency_key = $2
                    """,
                    tenant,
                    key,
                )
            raise

        status = 500
        content_type = "application/json"
        response_parts: list[bytes] = []

        for message in captured:
            if message["type"] == "http.response.start":
                status = int(
                    message["status"]
                )

                for header_name, header_value in message.get(
                    "headers",
                    [],
                ):
                    if (
                        header_name.lower()
                        == b"content-type"
                    ):
                        content_type = header_value.decode(
                            errors="replace"
                        )

            elif message["type"] == "http.response.body":
                response_parts.append(
                    message.get(
                        "body",
                        b"",
                    )
                )

        response_body = b"".join(
            response_parts
        )

        max_cached = int(
            os.getenv(
                "DDF_IDEMPOTENCY_MAX_RESPONSE_BYTES",
                str(4 * 1024 * 1024),
            )
        )

        if len(response_body) > max_cached:
            async with pool.acquire() as connection:
                await connection.execute(
                    """
                    UPDATE ddf_idempotency_v2
                    SET state = 'non_replayable',
                        status_code = $3,
                        updated_at = now()
                    WHERE tenant_id = $1
                      AND idempotency_key = $2
                    """,
                    tenant,
                    key,
                    status,
                )
        else:
            async with pool.acquire() as connection:
                await connection.execute(
                    """
                    UPDATE ddf_idempotency_v2
                    SET state = 'completed',
                        status_code = $3,
                        response_body = $4,
                        content_type = $5,
                        updated_at = now()
                    WHERE tenant_id = $1
                      AND idempotency_key = $2
                    """,
                    tenant,
                    key,
                    status,
                    response_body,
                    content_type,
                )

        for message in captured:
            await send(
                message
            )


class MetricsMiddleware:
    def __init__(
        self,
        app: ASGIApp,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        method = str(
            scope.get(
                "method",
                "UNKNOWN",
            )
        )

        path = str(
            scope.get(
                "path",
                "",
            )
        )

        status = 500
        started = time.perf_counter()

        async def metric_send(
            message: Message,
        ) -> None:
            nonlocal status

            if message["type"] == "http.response.start":
                status = int(
                    message["status"]
                )

            await send(
                message
            )

        try:
            await self.app(
                scope,
                receive,
                metric_send,
            )
        finally:
            elapsed = (
                time.perf_counter()
                - started
            )

            _REQUESTS.labels(
                method=method,
                path=path,
                status=str(status),
            ).inc()

            _LATENCY.labels(
                method=method,
                path=path,
            ).observe(
                elapsed
            )


class JsonFormatter(logging.Formatter):
    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        payload = {
            "timestamp": datetime.now(
                UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exception"] = (
                self.formatException(
                    record.exc_info
                )
            )

        return json.dumps(
            payload,
            separators=(",", ":"),
        )


def configure_json_logging() -> None:
    if not _env_bool(
        "DDF_JSON_LOGGING",
        _is_production(),
    ):
        return

    root = logging.getLogger()

    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonFormatter()
    )

    root.handlers.clear()
    root.addHandler(
        handler
    )

    root.setLevel(
        os.getenv(
            "DDF_LOG_LEVEL",
            "INFO",
        ).upper()
    )


# ============================================================
# CAPABILITY BROKER POLICY
# ============================================================


def capability_caller_allowed(
    principal: Any,
    actor: str,
) -> bool:
    subject = str(
        getattr(
            principal,
            "subject",
            "",
        )
    )

    if subject == actor:
        return True

    if not _env_bool(
        "DDF_ENABLE_CAPABILITY_BROKERS",
        False,
    ):
        return False

    roles = set(
        getattr(
            principal,
            "roles",
            [],
        )
        or []
    )

    if "capability_broker" not in roles:
        return False

    raw = os.getenv(
        "DDF_CAPABILITY_BROKER_POLICY",
        "{}",
    )

    try:
        policy = json.loads(
            raw
        )
    except json.JSONDecodeError:
        return False

    allowed = policy.get(
        subject,
        [],
    )

    if not isinstance(
        allowed,
        list,
    ):
        return False

    for pattern in allowed:
        if (
            isinstance(
                pattern,
                str,
            )
            and fnmatch.fnmatchcase(
                actor,
                pattern,
            )
        ):
            return True

    return False


# ============================================================
# IDENTITY LIFECYCLE
# ============================================================


async def rotate_identity_key(
    *,
    tenant_id: str,
    subject: str,
    key_id: str,
    public_key: str,
    expires_at: datetime | None = None,
    revoke_previous: bool = True,
) -> None:
    pool = await get_pg_pool()

    async with pool.acquire() as connection, connection.transaction():
        if revoke_previous:
            await connection.execute(
                """
                    UPDATE ddf_identity_keys
                    SET status = 'revoked',
                        revoked_at = now()
                    WHERE tenant_id = $1
                      AND subject = $2
                      AND status = 'active'
                    """,
                tenant_id,
                subject,
            )

        await connection.execute(
            """
                INSERT INTO ddf_identity_keys (
                    tenant_id,
                    subject,
                    key_id,
                    public_key,
                    status,
                    not_before,
                    expires_at,
                    created_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    'active',
                    now(),
                    $5,
                    now()
                )
                ON CONFLICT (
                    tenant_id,
                    subject,
                    key_id
                )
                DO UPDATE SET
                    public_key = EXCLUDED.public_key,
                    status = 'active',
                    not_before = now(),
                    expires_at = EXCLUDED.expires_at,
                    revoked_at = NULL
                """,
            tenant_id,
            subject,
            key_id,
            public_key,
            expires_at,
        )


async def revoke_identity_key(
    *,
    tenant_id: str,
    subject: str,
    key_id: str,
) -> bool:
    pool = await get_pg_pool()

    async with pool.acquire() as connection:
        result = await connection.execute(
            """
            UPDATE ddf_identity_keys
            SET status = 'revoked',
                revoked_at = now()
            WHERE tenant_id = $1
              AND subject = $2
              AND key_id = $3
              AND status <> 'revoked'
            """,
            tenant_id,
            subject,
            key_id,
        )

    return not result.endswith(
        " 0"
    )


async def discover_identity_keys(
    *,
    tenant_id: str,
    subject: str,
    requester_subject: str,
    requester_roles: list[str] | tuple[str, ...],
) -> list[dict[str, Any]]:
    roles = set(
        requester_roles
    )

    if (
        requester_subject != subject
        and "tenant_admin" not in roles
        and "identity_discovery" not in roles
    ):
        raise PermissionError(
            "identity discovery is not authorized"
        )

    pool = await get_pg_pool()

    async with pool.acquire() as connection:
        rows = await connection.fetch(
            """
            SELECT
                subject,
                key_id,
                public_key,
                status,
                not_before,
                expires_at,
                revoked_at
            FROM ddf_identity_keys
            WHERE tenant_id = $1
              AND subject = $2
            ORDER BY created_at DESC
            """,
            tenant_id,
            subject,
        )

    return [
        dict(row)
        for row in rows
    ]


async def resolve_did_web(
    did: str,
) -> dict[str, Any]:
    prefix = "did:web:"

    if not did.startswith(
        prefix
    ):
        raise ValueError(
            "only did:web is supported"
        )

    value = did[
        len(prefix) :
    ]

    parts = [
        unquote(part)
        for part in value.split(":")
        if part
    ]

    if not parts:
        raise ValueError(
            "invalid did:web identifier"
        )

    host = parts[0]

    if any(
        value in host.lower()
        for value in (
            "/",
            "\\",
            "@",
        )
    ):
        raise ValueError(
            "invalid did:web host"
        )

    if len(parts) == 1:
        url = (
            f"https://{host}"
            "/.well-known/did.json"
        )
    else:
        path = "/".join(
            parts[1:]
        )
        url = (
            f"https://{host}/"
            f"{path}/did.json"
        )

    async with httpx.AsyncClient(
        timeout=5,
        follow_redirects=False,
    ) as client:
        response = await client.get(
            url
        )
        response.raise_for_status()

        raw_document = response.json()

    if not isinstance(
        raw_document,
        dict,
    ):
        raise ValueError(
            "DID document must be a JSON object"
        )

    document: dict[str, Any] = dict(
        raw_document
    )

    if document.get(
        "id"
    ) != did:
        raise ValueError(
            "DID document id mismatch"
        )

    return document


async def verify_oidc_token(
    token: str,
) -> dict[str, Any]:
    issuer = os.getenv(
        "DDF_OIDC_ISSUER",
        "",
    ).strip()

    audience = os.getenv(
        "DDF_OIDC_AUDIENCE",
        "",
    ).strip()

    jwks_url = os.getenv(
        "DDF_OIDC_JWKS_URL",
        "",
    ).strip()

    if not all(
        (
            issuer,
            audience,
            jwks_url,
        )
    ):
        raise RuntimeError(
            "OIDC verifier is not configured"
        )

    algorithms = [
        value.strip()
        for value in os.getenv(
            "DDF_OIDC_ALGORITHMS",
            "RS256",
        ).split(",")
        if value.strip()
    ]

    header = jwt.get_unverified_header(
        token
    )

    algorithm = header.get(
        "alg"
    )

    kid = header.get(
        "kid"
    )

    if algorithm not in algorithms:
        raise ValueError(
            "OIDC token algorithm is not allowed"
        )

    if not kid:
        raise ValueError(
            "OIDC token is missing kid"
        )

    async with httpx.AsyncClient(
        timeout=5,
        follow_redirects=False,
    ) as client:
        response = await client.get(
            jwks_url
        )
        response.raise_for_status()
        jwks = response.json()

    matching = [
        key
        for key in jwks.get(
            "keys",
            [],
        )
        if key.get(
            "kid"
        )
        == kid
    ]

    if len(matching) != 1:
        raise ValueError(
            "OIDC signing key is not uniquely pinned"
        )

    key = jwt.PyJWK.from_dict(
        matching[0]
    ).key

    claims = jwt.decode(
        token,
        key=key,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
        options={
            "require": [
                "exp",
                "iat",
                "sub",
            ]
        },
    )

    return dict(
        claims
    )


def map_spiffe_id(
    spiffe_id: str,
) -> str:
    if not spiffe_id.startswith(
        "spiffe://"
    ):
        raise ValueError(
            "invalid SPIFFE identifier"
        )

    raw = os.getenv(
        "DDF_SPIFFE_IDENTITY_MAP",
        "{}",
    )

    mapping = json.loads(
        raw
    )

    subject = mapping.get(
        spiffe_id
    )

    if not isinstance(
        subject,
        str,
    ):
        raise PermissionError(
            "SPIFFE identity is not mapped"
        )

    return subject


# ============================================================
# OPENFGA ADMIN + FAIL-CLOSED READINESS
# ============================================================


class OpenFGAAdminClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        store_id: str | None = None,
        authorization_model_id: str | None = None,
        token: str | None = None,
    ) -> None:
        configured_base_url = (
            base_url
            or os.getenv(
                "DDF_OPENFGA_URL",
                "",
            )
            or ""
        )

        self.base_url = configured_base_url.rstrip(
            "/"
        )

        self.store_id = (
            store_id
            or os.getenv(
                "DDF_OPENFGA_STORE_ID",
                "",
            )
        )

        self.authorization_model_id = (
            authorization_model_id
            or os.getenv(
                "DDF_OPENFGA_MODEL_ID",
                "",
            )
        )

        self.token = (
            token
            or os.getenv(
                "DDF_OPENFGA_TOKEN",
                "",
            )
        )

    def _headers(
        self,
    ) -> dict[str, str]:
        headers = {
            "content-type": "application/json",
        }

        if self.token:
            headers["authorization"] = (
                f"Bearer {self.token}"
            )

        return headers

    def _require_configuration(
        self,
    ) -> None:
        if (
            not self.base_url
            or not self.store_id
        ):
            raise RuntimeError(
                "OpenFGA is not configured"
            )

    async def ready(
        self,
    ) -> bool:
        self._require_configuration()

        async with httpx.AsyncClient(
            timeout=3,
        ) as client:
            response = await client.get(
                f"{self.base_url}/healthz",
                headers=self._headers(),
            )

        return response.status_code == 200

    async def check(
        self,
        *,
        user: str,
        relation: str,
        object_: str,
    ) -> bool:
        self._require_configuration()

        body: dict[str, Any] = {
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": object_,
            }
        }

        if self.authorization_model_id:
            body[
                "authorization_model_id"
            ] = self.authorization_model_id

        async with httpx.AsyncClient(
            timeout=5,
        ) as client:
            response = await client.post(
                (
                    f"{self.base_url}/stores/"
                    f"{self.store_id}/check"
                ),
                headers=self._headers(),
                json=body,
            )

        if response.status_code != 200:
            return False

        return bool(
            response.json().get(
                "allowed",
                False,
            )
        )

    async def write_tuple(
        self,
        *,
        user: str,
        relation: str,
        object_: str,
        authority_granted: bool,
    ) -> None:
        if not authority_granted:
            raise PermissionError(
                "DDF authority is required "
                "for ReBAC administration"
            )

        self._require_configuration()

        body: dict[str, Any] = {
            "writes": {
                "tuple_keys": [
                    {
                        "user": user,
                        "relation": relation,
                        "object": object_,
                    }
                ]
            }
        }

        if self.authorization_model_id:
            body[
                "authorization_model_id"
            ] = self.authorization_model_id

        async with httpx.AsyncClient(
            timeout=5,
        ) as client:
            response = await client.post(
                (
                    f"{self.base_url}/stores/"
                    f"{self.store_id}/write"
                ),
                headers=self._headers(),
                json=body,
            )

        response.raise_for_status()

    async def delete_tuple(
        self,
        *,
        user: str,
        relation: str,
        object_: str,
        authority_granted: bool,
    ) -> None:
        if not authority_granted:
            raise PermissionError(
                "DDF authority is required "
                "for ReBAC administration"
            )

        self._require_configuration()

        body: dict[str, Any] = {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": user,
                        "relation": relation,
                        "object": object_,
                    }
                ]
            }
        }

        if self.authorization_model_id:
            body[
                "authorization_model_id"
            ] = self.authorization_model_id

        async with httpx.AsyncClient(
            timeout=5,
        ) as client:
            response = await client.post(
                (
                    f"{self.base_url}/stores/"
                    f"{self.store_id}/write"
                ),
                headers=self._headers(),
                json=body,
            )

        response.raise_for_status()


# ============================================================
# REMOTE / LLM INTENT ADAPTER
# ============================================================


class RemoteIntentAdapter:
    def __init__(
        self,
        *,
        url: str | None = None,
        token: str | None = None,
    ) -> None:
        self.url = (
            url
            or os.getenv(
                "DDF_REMOTE_INTENT_URL",
                "",
            )
        )

        self.token = (
            token
            or os.getenv(
                "DDF_REMOTE_INTENT_TOKEN",
                "",
            )
        )

    async def parse(
        self,
        text: str,
    ) -> dict[str, Any]:
        if not self.url:
            raise RuntimeError(
                "remote intent parser is not configured"
            )

        headers = {
            "content-type": "application/json",
        }

        if self.token:
            headers["authorization"] = (
                f"Bearer {self.token}"
            )

        async with httpx.AsyncClient(
            timeout=float(
                os.getenv(
                    "DDF_REMOTE_INTENT_TIMEOUT_SECONDS",
                    "5",
                )
            ),
            follow_redirects=False,
        ) as client:
            response = await client.post(
                self.url,
                headers=headers,
                json={
                    "text": text,
                },
            )

        response.raise_for_status()

        proposal = response.json()

        if not isinstance(
            proposal,
            dict,
        ):
            raise ValueError(
                "remote parser returned invalid output"
            )

        return proposal


def authorize_remote_intent(
    proposal: dict[str, Any],
    *,
    allowed_actions: list[str],
    allowed_resources: list[str],
    allowed_purposes: list[str],
) -> dict[str, Any]:
    """Deterministically reject parser output outside authority scope."""

    action = proposal.get(
        "action"
    )

    resource = proposal.get(
        "resource"
    )

    purpose = proposal.get(
        "purpose"
    )

    if action not in allowed_actions:
        raise PermissionError(
            "remote intent action exceeds authority"
        )

    if purpose not in allowed_purposes:
        raise PermissionError(
            "remote intent purpose exceeds authority"
        )

    if not isinstance(
        resource,
        str,
    ):
        raise PermissionError(
            "remote intent resource is invalid"
        )

    if not any(
        fnmatch.fnmatchcase(
            resource,
            allowed,
        )
        for allowed in allowed_resources
    ):
        raise PermissionError(
            "remote intent resource exceeds authority"
        )

    return dict(
        proposal
    )


# ============================================================
# EVIDENCE BUNDLES + OFFLINE VERIFIER
# ============================================================


def _normalize_evidence_row(
    row: dict[str, Any],
) -> dict[str, Any]:
    normalized = dict(
        row
    )

    if (
        "previous_hash"
        not in normalized
        and "prev_hash" in normalized
    ):
        normalized[
            "previous_hash"
        ] = normalized[
            "prev_hash"
        ]

    if (
        "event_hash"
        not in normalized
        and "hash" in normalized
    ):
        normalized[
            "event_hash"
        ] = normalized[
            "hash"
        ]

    return normalized


def build_evidence_bundle(
    *,
    tenant_id: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized = [
        _normalize_evidence_row(
            record
        )
        for record in records
    ]

    records_hash = hashlib.sha256(
        _canonical_json(
            normalized
        )
    ).hexdigest()

    manifest = {
        "schema_version": "1",
        "tenant_id": tenant_id,
        "exported_at": datetime.now(
            UTC
        ).isoformat(),
        "record_count": len(
            normalized
        ),
        "records_sha256": records_hash,
        "legacy_compatibility": [
            "0.1",
            "1",
        ],
    }

    bundle: dict[str, Any] = {
        "manifest": manifest,
        "records": normalized,
    }

    seed_b64 = os.getenv(
        "DDF_EVIDENCE_BUNDLE_SIGNING_KEY_B64",
        "",
    ).strip()

    if seed_b64:
        seed = base64.b64decode(
            seed_b64
        )

        if len(seed) not in {
            32,
            64,
        }:
            raise ValueError(
                "evidence signing key must decode "
                "to 32 or 64 bytes"
            )

        signing_key = SigningKey(
            seed[:32]
        )

        signature = signing_key.sign(
            _canonical_json(
                manifest
            )
        ).signature

        bundle["signature"] = {
            "algorithm": "Ed25519",
            "public_key": base64.b64encode(
                bytes(
                    signing_key.verify_key
                )
            ).decode(),
            "signature": base64.b64encode(
                signature
            ).decode(),
        }

    return bundle


def verify_evidence_bundle(
    bundle: dict[str, Any],
) -> bool:
    manifest = bundle.get(
        "manifest"
    )

    records = bundle.get(
        "records"
    )

    if not isinstance(
        manifest,
        dict,
    ) or not isinstance(
        records,
        list,
    ):
        return False

    expected = hashlib.sha256(
        _canonical_json(
            records
        )
    ).hexdigest()

    if expected != manifest.get(
        "records_sha256"
    ):
        return False

    if manifest.get(
        "record_count"
    ) != len(
        records
    ):
        return False

    signature = bundle.get(
        "signature"
    )

    if signature is None:
        return True

    try:
        verify_key = VerifyKey(
            base64.b64decode(
                signature[
                    "public_key"
                ]
            )
        )

        verify_key.verify(
            _canonical_json(
                manifest
            ),
            base64.b64decode(
                signature[
                    "signature"
                ]
            ),
        )
    except Exception:
        return False

    return True


async def export_evidence_bundle(
    session: Any,
    *,
    tenant_id: str,
) -> dict[str, Any]:
    statement = select(
        EvidenceRecord
    ).where(
        EvidenceRecord.tenant_id
        == tenant_id
    )

    result = await session.execute(
        statement
    )

    objects = result.scalars().all()

    records: list[
        dict[str, Any]
    ] = []

    for item in objects:
        record = {
            column.name: getattr(
                item,
                column.name,
            )
            for column in item.__table__.columns
        }

        records.append(
            record
        )

    return build_evidence_bundle(
        tenant_id=tenant_id,
        records=records,
    )


# ============================================================
# HEALTH / READINESS / METRICS
# ============================================================


async def _probe_openfga_readiness() -> bool | None:
    """Probe configured OpenFGA HTTP health for dependency readiness."""
    base_url = (
        os.getenv("DDF_OPENFGA_URL")
        or os.getenv("DDF_OPENFGA_API_URL")
        or os.getenv("OPENFGA_API_URL")
    )

    if not base_url:
        return None

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(
                f"{base_url.rstrip('/')}/healthz"
            )
        return response.is_success
    except (httpx.HTTPError, OSError):
        return False


async def dependency_readiness() -> dict[str, Any]:
    result: dict[str, Any] = {
        "database": False,
        "redis": False,
        "openfga": None,
    }

    try:
        pool = await get_pg_pool()

        async with pool.acquire() as connection:
            value = await connection.fetchval(
                "SELECT 1"
            )

        result["database"] = (
            value == 1
        )
    except Exception:
        result["database"] = False

    try:
        client = await get_redis()

        result["redis"] = bool(
            await client.ping()
        )
    except Exception:
        result["redis"] = False

    result["openfga"] = await _probe_openfga_readiness()

    return result


def install_production_readiness(
    app: Any,
) -> None:
    """Install production controls on the FastAPI application."""

    configure_json_logging()

    app.add_middleware(
        MetricsMiddleware
    )

    app.add_middleware(
        DurableIdempotencyMiddleware
    )

    app.add_middleware(
        DistributedRateLimitMiddleware
    )

    app.add_middleware(
        TLSRequiredMiddleware
    )

    app.add_middleware(
        BodyLimitMiddleware
    )

    @app.on_event(
        "startup"
    )
    async def _production_startup_guard() -> None:
        validate_production_environment()

        if _is_production():
            await get_pg_pool()
            client = await get_redis()
            await client.ping()

    async def livez() -> dict[str, str]:
        return {
            "status": "alive",
        }

    async def production_ready() -> Response:
        dependencies = await dependency_readiness()

        required = [
            dependencies[
                "database"
            ],
            dependencies[
                "redis"
            ],
        ]

        if (
            dependencies[
                "openfga"
            ]
            is not None
        ):
            required.append(
                bool(
                    dependencies[
                        "openfga"
                    ]
                )
            )

        status = (
            200
            if all(
                required
            )
            else 503
        )

        return JSONResponse(
            dependencies,
            status_code=status,
        )

    async def metrics() -> Response:
        return Response(
            generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    app.add_api_route(
        "/livez",
        livez,
        methods=[
            "GET",
        ],
        tags=[
            "operations",
        ],
    )

    app.add_api_route(
        "/ready/dependencies",
        production_ready,
        methods=[
            "GET",
        ],
        tags=[
            "operations",
        ],
    )

    app.add_api_route(
        "/metrics",
        metrics,
        methods=[
            "GET",
        ],
        include_in_schema=False,
    )
