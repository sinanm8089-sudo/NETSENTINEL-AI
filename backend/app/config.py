"""Configuration management for NETSENTINEL AI."""
import os
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "NETSENTINEL AI"
    VERSION: str = "1.0.0"
    CREATOR: str = "Sinan Mohammed"
    API_V1_STR: str = "/api/v1"

    # Database: Defaults to local SQLite for zero-config operation; supports PostgreSQL via DATABASE_URL
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./netsentinel.db")

    # Security & JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "netsentinel-enterprise-secret-key-change-in-prod-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 hours

    # Default Authorized CIDRs (strictly enforced by CIDR validator)
    DEFAULT_AUTHORIZED_CIDRS: List[str] = [
        "192.168.56.0/24",
        "10.20.30.0/24",
        "127.0.0.1/32",
    ]

    # Scanner safety & rate limit settings
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
    SCAN_HOST_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_HOST_TIMEOUT_SECONDS", "120"))
    SCAN_MAX_RATE_PPS: int = int(os.getenv("SCAN_MAX_RATE_PPS", "500"))
    PREFER_REAL_NMAP: bool = os.getenv("PREFER_REAL_NMAP", "false").lower() == "true"

    # Hybrid AI settings (Statistical engine always works offline even if all AI is disabled/unavailable)
    AI_PROVIDER_PREFERENCE: str = os.getenv("AI_PROVIDER_PREFERENCE", "AUTO")  # AUTO | LOCAL_OLLAMA | CLOUD_GEMINI | CLOUD_OPENAI | STATISTICAL_OFFLINE
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Dashboard & Notification settings
    DASHBOARD_REFRESH_SECONDS: int = int(os.getenv("DASHBOARD_REFRESH_SECONDS", "8"))
    ALERT_WEBHOOK_URL: str = os.getenv("ALERT_WEBHOOK_URL", "")

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

