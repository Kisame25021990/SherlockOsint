from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent

load_dotenv(dotenv_path=PROJECT_ROOT / ".env")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    def __init__(self) -> None:
        self.db_path = Path(os.getenv("OSINT_DB_PATH", str(BACKEND_DIR / "osint.db")))
        self.static_dir = Path(os.getenv("OSINT_STATIC_DIR", str(PROJECT_ROOT / "frontend")))
        self.sherlock_timeout = _int_env("SHERLOCK_TIMEOUT", 20)
        self.request_timeout = _int_env("REQUEST_TIMEOUT", 10)
        self.max_concurrent_scans = max(1, _int_env("MAX_CONCURRENT_SCANS", 3))
        self.proxy = os.getenv("OSINT_PROXY") or None
        self.sherlock_use_remote_sites = _bool_env("SHERLOCK_USE_REMOTE_SITES")
        self.api_keys = {
            name: os.getenv(env_name, "")
            for name, env_name in {
                "hibp": "HIBP_API_KEY",
                "virustotal": "VIRUSTOTAL_API_KEY",
                "shodan": "SHODAN_API_KEY",
            }.items()
        }
        self.cors_origins = [
            origin.strip()
            for origin in os.getenv("OSINT_CORS_ORIGINS", "http://127.0.0.1:8000").split(",")
            if origin.strip()
        ]
        self.auth_user = os.getenv("OSINT_AUTH_USER", "")
        self.auth_password = os.getenv("OSINT_AUTH_PASSWORD", "")

    @property
    def auth_enabled(self) -> bool:
        return bool(self.auth_user and self.auth_password)


settings = Settings()
