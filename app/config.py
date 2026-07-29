from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value else default


@dataclass(slots=True)
class Settings:
    app_name: str = "A11 Agentic SOC"
    environment: str = "development"
    database_url: str = "sqlite:///./data/soc.db"
    api_key: str = "change-me-ingest-key"
    admin_token: str = "change-me-admin-token"
    cors_origins: str = "http://localhost:8000"
    ollama_enabled: bool = False
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "qwen2.5:7b"
    ollama_timeout_seconds: int = 45
    response_mode: str = "dry_run"
    response_webhook_url: str = ""
    notification_webhook_url: str = ""
    opnsense_url: str = ""
    opnsense_key: str = ""
    opnsense_secret: str = ""
    opnsense_alias: str = "SOC_BLOCKLIST"
    opnsense_verify_tls: bool = True
    correlation_window_seconds: int = 300
    syslog_enabled: bool = True
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    data_dir: Path = Path("data")
    knowledge_dir: Path = Path("knowledge")

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()
        return cls(
            app_name=os.getenv("APP_NAME", defaults.app_name),
            environment=os.getenv("ENVIRONMENT", defaults.environment),
            database_url=os.getenv("DATABASE_URL", defaults.database_url),
            api_key=os.getenv("SOC_API_KEY", defaults.api_key),
            admin_token=os.getenv("SOC_ADMIN_TOKEN", defaults.admin_token),
            cors_origins=os.getenv("CORS_ORIGINS", defaults.cors_origins),
            ollama_enabled=_bool("OLLAMA_ENABLED", defaults.ollama_enabled),
            ollama_url=os.getenv("OLLAMA_URL", defaults.ollama_url),
            ollama_model=os.getenv("OLLAMA_MODEL", defaults.ollama_model),
            ollama_timeout_seconds=_int(
                "OLLAMA_TIMEOUT_SECONDS", defaults.ollama_timeout_seconds
            ),
            response_mode=os.getenv("RESPONSE_MODE", defaults.response_mode),
            response_webhook_url=os.getenv(
                "RESPONSE_WEBHOOK_URL", defaults.response_webhook_url
            ),
            notification_webhook_url=os.getenv(
                "NOTIFICATION_WEBHOOK_URL", defaults.notification_webhook_url
            ),
            opnsense_url=os.getenv("OPNSENSE_URL", defaults.opnsense_url),
            opnsense_key=os.getenv("OPNSENSE_KEY", defaults.opnsense_key),
            opnsense_secret=os.getenv("OPNSENSE_SECRET", defaults.opnsense_secret),
            opnsense_alias=os.getenv("OPNSENSE_ALIAS", defaults.opnsense_alias),
            opnsense_verify_tls=_bool(
                "OPNSENSE_VERIFY_TLS", defaults.opnsense_verify_tls
            ),
            correlation_window_seconds=_int(
                "CORRELATION_WINDOW_SECONDS", defaults.correlation_window_seconds
            ),
            syslog_enabled=_bool("SYSLOG_ENABLED", defaults.syslog_enabled),
            syslog_host=os.getenv("SYSLOG_HOST", defaults.syslog_host),
            syslog_port=_int("SYSLOG_PORT", defaults.syslog_port),
            data_dir=Path(os.getenv("DATA_DIR", str(defaults.data_dir))),
            knowledge_dir=Path(
                os.getenv("KNOWLEDGE_DIR", str(defaults.knowledge_dir))
            ),
        )

    @property
    def allowed_origins(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]

    def validate_safety(self) -> list[str]:
        warnings: list[str] = []
        if self.api_key.startswith("change-me"):
            warnings.append("SOC_API_KEY is using the development default.")
        if self.admin_token.startswith("change-me"):
            warnings.append("SOC_ADMIN_TOKEN is using the development default.")
        if self.response_mode not in {"dry_run", "webhook", "opnsense"}:
            warnings.append(
                f"Unknown RESPONSE_MODE={self.response_mode!r}; dry-run will be used."
            )
        if self.response_mode == "opnsense" and not all(
            [self.opnsense_url, self.opnsense_key, self.opnsense_secret]
        ):
            warnings.append(
                "OPNsense response mode selected but credentials are incomplete."
            )
        return warnings
