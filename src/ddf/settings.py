"""DDF application settings and configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False

    # Database
    database_url: str = "postgresql://ddf:ddf_password@localhost:5432/ddf_db"
    sqlalchemy_echo: bool = False

    # OpenFGA
    openfga_host: str = "localhost"
    openfga_port: int = 8081
    openfga_store_id: str = ""

    # Cryptography
    crypto_algorithm: str = "Ed25519"

    # Logging
    log_level: str = "INFO"

    # Security
    request_signature_validity_seconds: int = 300

    # Development flag (NEVER use in production)
    development_mode: bool = False

    # Computed properties
    @property
    def openfga_url(self) -> str:
        """OpenFGA API URL."""
        return f"http://{self.openfga_host}:{self.openfga_port}"

    @property
    def project_root(self) -> Path:
        """Root directory of the DDF project."""
        return Path(__file__).parent.parent.parent

    class Config:
        """Pydantic config."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get application settings (cached singleton)."""
    return Settings()
