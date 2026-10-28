"""OpenFGA relationship authorization integration."""

import os
from urllib.parse import urlsplit

import httpx


class OpenFGAConfigurationError(RuntimeError):
    """OpenFGA has been enabled without required configuration."""


class OpenFGAPolicy:
    """
    Thin OpenFGA HTTP client.

    DDF remains the source of delegated authority. OpenFGA answers the
    separate relationship-entitlement question. Authorization is allowed
    only when both layers allow.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        api_url: str = "http://localhost:8080",
        store_id: str | None = None,
        authorization_model_id: str | None = None,
        api_token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.enabled = enabled
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id
        self.authorization_model_id = authorization_model_id
        self.api_token = api_token
        self.transport = transport

    @classmethod
    def from_env(cls) -> "OpenFGAPolicy":
        """Create configuration from environment variables."""
        enabled = os.getenv(
            "DDF_OPENFGA_ENABLED",
            "false",
        ).lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        return cls(
            enabled=enabled,
            api_url=os.getenv(
                "DDF_OPENFGA_API_URL",
                "http://localhost:8080",
            ),
            store_id=os.getenv("DDF_OPENFGA_STORE_ID"),
            authorization_model_id=os.getenv("DDF_OPENFGA_AUTHORIZATION_MODEL_ID"),
            api_token=os.getenv("DDF_OPENFGA_API_TOKEN"),
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "content-type": "application/json",
        }

        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        return headers

    def _require_configuration(self) -> None:
        if not self.enabled:
            return

        if not self.store_id:
            raise OpenFGAConfigurationError(
                "DDF_OPENFGA_STORE_ID is required when OpenFGA is enabled"
            )

    async def check(
        self,
        *,
        user: str,
        relation: str,
        object: str,
    ) -> bool:
        """Perform an OpenFGA Check request."""
        if not self.enabled:
            return True

        self._require_configuration()

        payload: dict = {
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": object,
            }
        }

        if self.authorization_model_id:
            payload["authorization_model_id"] = self.authorization_model_id

        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=5.0,
        ) as client:
            response = await client.post(
                (f"{self.api_url}/stores/{self.store_id}/check"),
                headers=self._headers(),
                json=payload,
            )

            response.raise_for_status()
            body = response.json()

        return bool(body.get("allowed", False))

    @staticmethod
    def principal_object(pei: str) -> str:
        """Map a principal entity identifier to an OpenFGA user object."""
        if not urlsplit(pei).scheme:
            raise ValueError("principal PEI must be a URI")
        return f"principal:{pei}"

    @staticmethod
    def resource_object(namespace: str, resource: str) -> str:
        """Map a universal namespace/resource pair to an OpenFGA object."""
        if not namespace or not resource:
            raise ValueError("resource namespace and identifier cannot be empty")
        return f"resource:{namespace}:{resource}"

    @classmethod
    def resource_candidates(cls, namespace: str, resource: str) -> list[str]:
        """Return exact and ancestor wildcard objects for namespace-scoped checks."""
        candidates = [cls.resource_object(namespace, resource)]
        if resource.endswith("/*"):
            resource = resource[:-2]

        prefix = resource.rstrip("/")
        while "/" in prefix:
            prefix = prefix.rsplit("/", 1)[0]
            candidates.append(cls.resource_object(namespace, f"{prefix}/*"))
        if resource.startswith("urn:") and resource.count(":") >= 2:
            urn_namespace = ":".join(resource.split(":")[:2])
            candidates.append(cls.resource_object(namespace, f"{urn_namespace}:*"))
        candidates.append(cls.resource_object(namespace, "*"))
        return list(dict.fromkeys(candidates))

    async def check_capability(
        self,
        *,
        principal: str,
        target_namespace: str,
        target_resource: str,
        relation: str = "subject",
    ) -> bool:
        """Check exact resource and broader resource/namespace relationships."""
        user = self.principal_object(principal)
        for object_id in self.resource_candidates(target_namespace, target_resource):
            if await self.check(user=user, relation=relation, object=object_id):
                return True
        return False

    async def write_capability_tuple(
        self,
        *,
        principal: str,
        target_namespace: str,
        target_resource: str,
        relation: str = "subject",
    ) -> None:
        """Write a PEI-to-universal-resource relationship tuple."""
        await self.write_tuple(
            user=self.principal_object(principal),
            relation=relation,
            object=self.resource_object(target_namespace, target_resource),
        )

    async def write_tuple(
        self,
        *,
        user: str,
        relation: str,
        object: str,
    ) -> None:
        """Write one relationship tuple."""
        if not self.enabled:
            raise OpenFGAConfigurationError("OpenFGA must be enabled to write tuples")

        self._require_configuration()

        payload: dict = {
            "writes": {
                "tuple_keys": [
                    {
                        "user": user,
                        "relation": relation,
                        "object": object,
                    }
                ]
            }
        }

        if self.authorization_model_id:
            payload["authorization_model_id"] = self.authorization_model_id

        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=5.0,
        ) as client:
            response = await client.post(
                (f"{self.api_url}/stores/{self.store_id}/write"),
                headers=self._headers(),
                json=payload,
            )

            response.raise_for_status()

    async def delete_capability_tuple(
        self,
        *,
        principal: str,
        target_namespace: str,
        target_resource: str,
        relation: str = "subject",
    ) -> None:
        """Delete the exact relationship tuple associated with a capability."""
        await self.delete_tuples(
            [
                {
                    "user": self.principal_object(principal),
                    "relation": relation,
                    "object": self.resource_object(target_namespace, target_resource),
                }
            ]
        )

    async def delete_tuples(self, tuple_keys: list[dict[str, str]]) -> None:
        """Delete exact OpenFGA relationship tuples."""
        if not self.enabled:
            raise OpenFGAConfigurationError("OpenFGA must be enabled to delete tuples")
        self._require_configuration()
        payload: dict = {"deletes": {"tuple_keys": tuple_keys}}
        if self.authorization_model_id:
            payload["authorization_model_id"] = self.authorization_model_id
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=5.0,
        ) as client:
            response = await client.post(
                f"{self.api_url}/stores/{self.store_id}/write",
                headers=self._headers(),
                json=payload,
            )
            response.raise_for_status()
