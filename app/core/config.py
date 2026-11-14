from functools import lru_cache
from pydantic import SecretStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: SecretStr
    jwt_secret: SecretStr = Field(min_length=32)
    admin_email: str = "kkurui951@gmail.com"
    admin_password: SecretStr | None = None
    cors_origins: list[str] = []
    enable_docs: bool = False
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def settings():
    return Settings()
