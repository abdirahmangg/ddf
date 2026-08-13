"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ddf import __version__
from ddf.api.errors import HTTPException
from ddf.settings import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
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
        description="Open-source authorization infrastructure for delegated AI-agent authority",
        version=__version__,
        lifespan=lifespan,
    )

    # Exception handler for DDF-specific exceptions
    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException  # noqa: ARG001
    ):
        """Handle DDF HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_response().model_dump(),
        )

    # Health check endpoint
    @app.get("/health")
    async def health() -> dict:
        """Health check endpoint."""
        return {
            "status": "ok",
            "version": __version__,
            "debug": settings.debug,
        }

    return app
