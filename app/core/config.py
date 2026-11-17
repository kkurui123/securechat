from functools import lru_cache

from pydantic import SecretStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: SecretStr

    jwt_secret: SecretStr = Field(
        min_length=32,
    )

    admin_email: str = "kkurui951@gmail.com"

    admin_password: SecretStr | None = None

    cors_origins: list[str] = []

    enable_docs: bool = False

    # Gmail SMTP settings used to send password-reset codes.
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: SecretStr | None = None
    smtp_from_email: str = ""

    # Password-reset code lifetime in minutes.
    password_reset_code_ttl_minutes: int = 10

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def settings():
    return Settings()
