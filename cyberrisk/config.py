"""Environment configuration, validated at startup (fail fast)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Mapping


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_path: str
    secret_key: str
    secret_is_ephemeral: bool
    token_ttl_minutes: int
    host: str
    port: int
    max_body_bytes: int
    rate_limit_per_minute: int
    login_limit_per_minute: int
    job_max_attempts: int
    job_backoff_base_seconds: float
    job_backoff_cap_seconds: float

    @property
    def is_dev(self) -> bool:
        return self.app_env in ("development", "test")


def _int(env: Mapping[str, str], key: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer") from exc
    if not lo <= val <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return val


def parse_database_url(url: str) -> str:
    if url == "sqlite:///:memory:" or url == ":memory:":
        return ":memory:"
    if not url.startswith("sqlite:///"):
        raise ConfigError("Only sqlite:/// URLs are supported by this build (see docs for PostgreSQL notes)")
    return url[len("sqlite:///"):]


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    app_env = env.get("APP_ENV", "development")
    if app_env not in ("development", "test", "production"):
        raise ConfigError("APP_ENV must be development, test or production")
    key = env.get("SECRET_KEY", "")
    ephemeral = False
    if not key:
        if app_env == "production":
            raise ConfigError("SECRET_KEY is required in production")
        key, ephemeral = secrets.token_urlsafe(48), True
    elif len(key) < 32:
        raise ConfigError("SECRET_KEY must be at least 32 characters")
    if app_env == "production" and key.startswith("<"):
        raise ConfigError("SECRET_KEY still contains the placeholder value")
    return Settings(
        app_env=app_env,
        database_path=parse_database_url(env.get("DATABASE_URL", "sqlite:///./cyber_risk.db")),
        secret_key=key,
        secret_is_ephemeral=ephemeral,
        token_ttl_minutes=_int(env, "ACCESS_TOKEN_EXPIRE_MINUTES", 30, 1, 1440),
        host=env.get("HOST", "127.0.0.1"),
        port=_int(env, "PORT", 8000, 1, 65535),
        max_body_bytes=_int(env, "MAX_BODY_BYTES", 1_000_000, 1024, 20_000_000),
        rate_limit_per_minute=_int(env, "RATE_LIMIT_PER_MINUTE", 240, 1, 100000),
        login_limit_per_minute=_int(env, "LOGIN_LIMIT_PER_MINUTE", 8, 1, 1000),
        job_max_attempts=_int(env, "JOB_MAX_ATTEMPTS", 3, 1, 20),
        job_backoff_base_seconds=float(_int(env, "JOB_BACKOFF_BASE_SECONDS", 2, 0, 3600)),
        job_backoff_cap_seconds=float(_int(env, "JOB_BACKOFF_CAP_SECONDS", 60, 0, 86400)),
    )
