"""Create a local OpenFGA store and DDF authorization model."""

import asyncio
import json
import os
from pathlib import Path

import httpx


async def main() -> None:
    api_url = os.getenv(
        "DDF_OPENFGA_API_URL",
        "http://localhost:8080",
    ).rstrip("/")

    model = json.loads(Path("openfga/model.json").read_text())

    async with httpx.AsyncClient(timeout=10.0) as client:
        store_response = await client.post(
            f"{api_url}/stores",
            json={"name": "DDF Local"},
        )
        store_response.raise_for_status()

        store_id = store_response.json()["id"]

        model_response = await client.post(
            (f"{api_url}/stores/{store_id}/authorization-models"),
            json=model,
        )
        model_response.raise_for_status()

        model_id = model_response.json()["authorization_model_id"]

    print()
    print("OpenFGA bootstrap complete.")
    print()
    print("Export these values:")
    print("export DDF_OPENFGA_ENABLED=true")
    print(f"export DDF_OPENFGA_API_URL={api_url}")
    print(f"export DDF_OPENFGA_STORE_ID={store_id}")
    print(f"export DDF_OPENFGA_AUTHORIZATION_MODEL_ID={model_id}")


if __name__ == "__main__":
    asyncio.run(main())
