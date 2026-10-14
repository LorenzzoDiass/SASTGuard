"""Central application configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed settings. Values come from env vars or an .env file."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # Application
    app_name: str = "SASTGuard"
    app_env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite:///./sastguard.db"

    # Redis / Celery
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Ollama
    ollama_enabled: bool = True
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_timeout: int = 60

        # AI provider
    ai_provider: str = "ollama"

    # Groq API
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    groq_timeout: int = 60

    # Uploads
    upload_max_bytes: int = 20 * 1024 * 1024
    upload_dir: str = "./data/uploads"
    # Source files the platform can scan, plus .zip for whole projects.
    # Python is analysed natively; JS/TS/Java are analysed by the Tree-sitter
    # scanners (which are active only when their runtime is installed).
    allowed_extensions: str = ".py,.js,.jsx,.mjs,.cjs,.ts,.tsx,.java,.zip"

    # Security gate default policy
    gate_fail_critical: int = 1
    gate_fail_high: int = 3
    gate_warn_medium: int = 5

    # --- Authentication / sessions ---
    # When False, the API is open (useful for the CLI/CI and local demos without
    # a secret). When True, all non-public routes require a valid JWT.
    auth_enabled: bool = True
    # HS256 signing secret. MUST be overridden in production via the environment.
    # The default is clearly a dev placeholder and triggers a startup warning.
    secret_key: str = "dev-insecure-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480  # 8h working session
    # Optional bootstrap admin created at startup when it does not exist.
    # Leave the password empty to have one generated and logged once (dev only).
    admin_username: str = "admin"
    admin_password: str = ""
    # Comma-separated list of allowed CORS origins for the dashboard.
    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_extensions_list(self) -> List[str]:
        return [e.strip().lower() for e in self.allowed_extensions.split(",") if e.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()


settings = get_settings()
