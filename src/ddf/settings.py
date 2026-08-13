"""DDF application settings and configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False

    database_url: str = "postgresql://ddf:ddf_password@localhost:5432/ddf_db"
    sqlalchemy_echo: bool = False

    # OpenFGA HTTP API. Port 8081 is the gRPC endpoint.
    openfga_host: str = "localhost"
    openfga_port: int = 8080
    openfga_store_id: str = ""

    crypto_algorithm: str = "Ed25519"

    log_level: str = "INFO"

    request_signature_validity_seconds: int = 300

    development_mode: bool = False

    @property
    def openfga_url(self) -> str:
        """Return the configured OpenFGA HTTP API URL."""
        return f"http://{self.openfga_host}:{self.openfga_port}"

    @property
    def project_root(self) -> Path:
        """Return the DDF project root."""
        return Path(__file__).parent.parent.parent


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
