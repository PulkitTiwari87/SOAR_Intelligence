"""Central configuration. Every setting comes from the environment (or .env).

There are no credential defaults: an unset key means the matching integration
is reported as "not configured" rather than silently using a made-up value.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # --- Runtime ---
    env: str = Field("development", alias="SOAR_ENV")  # development | testing | production
    database_url: str = f"sqlite:///{ROOT / 'data' / 'soar.db'}"
    data_dir: Path = Field(ROOT / "data", alias="SOAR_DATA_DIR")
    model_dir: Path = Field(ROOT / "models", alias="SOAR_MODEL_DIR")
    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    # --- Auth ---
    jwt_secret: str = ""
    jwt_expire_minutes: int = 480
    cookie_secure: bool = False  # set true when served over HTTPS
    ingest_api_key: str = ""  # shared secret for machine ingestion (X-API-Key)
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    admin_username: str = Field("", alias="SOAR_ADMIN_USERNAME")
    admin_password: str = Field("", alias="SOAR_ADMIN_PASSWORD")

    # --- Pipeline tuning ---
    correlation_window_minutes: int = 30
    correlation_threshold: float = 3.0
    intel_cache_hours: int = 24

    # --- Response policy ---
    # Highest action risk that may run without a human: none | low | medium
    auto_execute_max_risk: str = "low"
    auto_playbooks_enabled: bool = True
    protected_ips: str = ""  # comma separated extra IPs/CIDRs that may never be blocked
    notify_webhook_url: str = ""

    # --- LLM (decision support only) ---
    llm_provider: str = "none"  # none | gemini | openai | anthropic | ollama | openai_compatible
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 45.0
    llm_auto_analyze: bool = False
    gemini_api_key: str = ""
    openai_api_key: str = ""
    anthropic_api_key: str = ""

    # --- Integrations (all optional) ---
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_pass: str = ""
    wazuh_indexer_url: str = ""
    wazuh_indexer_user: str = ""
    wazuh_indexer_pass: str = ""
    wazuh_verify_tls: bool = True
    wazuh_isolate_command: str = ""  # custom active-response command name, if you built one
    wazuh_disable_account_command: str = ""
    thehive_url: str = ""
    thehive_api_key: str = ""
    cortex_url: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_tls: bool = True

    @model_validator(mode="after")
    def _finalize(self) -> "Settings":
        if not self.jwt_secret:
            if self.env == "production":
                raise ValueError("JWT_SECRET must be set when SOAR_ENV=production")
            # Ephemeral secret: sessions do not survive a restart in dev/test.
            self.jwt_secret = secrets.token_urlsafe(48)
        if self.env == "production" and len(self.jwt_secret) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters in production")
        if self.auto_execute_max_risk not in ("none", "low", "medium"):
            raise ValueError("AUTO_EXECUTE_MAX_RISK must be none, low or medium")
        return self

    # --- Derived helpers ---
    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def llm_key(self) -> str:
        """Key for the selected provider: LLM_API_KEY wins, else the provider-specific key."""
        if self.llm_api_key:
            return self.llm_api_key
        return {"gemini": self.gemini_api_key, "openai": self.openai_api_key,
                "anthropic": self.anthropic_api_key}.get(self.llm_provider, "")


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings() -> None:
    """Drop the cached settings (tests change the environment)."""
    get_settings.cache_clear()
