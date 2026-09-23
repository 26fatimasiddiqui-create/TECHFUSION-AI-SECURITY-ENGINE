from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Supabase credentials
    SUPABASE_URL: Optional[str] = None
    SUPABASE_KEY: Optional[str] = None

    # Cognee context credentials
    COGNEE_API_KEY: Optional[str] = None
    COGNEE_API_URL: Optional[str] = None

    # n8n webhook integration
    N8N_WEBHOOK_URL: Optional[str] = None

    # Security correlation & risk thresholds
    CORRELATION_WINDOW_MINUTES: int = 30
    ALERT_RISK_THRESHOLD: int = 70

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
