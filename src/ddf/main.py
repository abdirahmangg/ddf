"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ddf import __version__
from ddf.api.errors import HTTPException
from ddf.api.routes.authorization_endpoints import (
    router as authorization_router,
)
from ddf.api.routes.delegation_endpoints import (
    router as delegation_router,
)
from ddf.api.routes.provenance_endpoints import (
    router as provenance_router,
)
from ddf.api.routes.revocation_endpoints import (
    router as revocation_router,
)
from ddf.commercial.api import install_commercial
from ddf.settings import get_settings


@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncIterator[None]:
    """Application lifespan context manager."""
    settings = get_settings()

    print(f"DDF v{__version__} starting...")
    print(f"API: {settings.api_host}:{settings.api_port}")
    print(f"Database: {settings.database_url}")
    print(f"OpenFGA: {settings.openfga_url}")

    yield

    print("DDF shutting down...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="DDF - Dynamic Delegation Fabric",
        description=("Open-source authorization infrastructure for delegated AI-agent authority"),
        version=__version__,
        lifespan=lifespan,
    )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        """Handle DDF HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content=(exc.to_response().model_dump()),
        )

    @app.get("/health")
    async def health() -> dict:
        """Return service health."""
        return {
            "status": "ok",
            "version": __version__,
            "debug": settings.debug,
        }

    app.include_router(delegation_router)
    app.include_router(authorization_router)
    app.include_router(revocation_router)
    app.include_router(provenance_router)

    return app


app = create_app()
install_commercial(app)
