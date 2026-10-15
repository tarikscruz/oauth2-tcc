from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    app_secret: str
    token_pepper: str
    fernet_key: str
    issuer: str = "http://localhost:8000"
    access_token_minutes: int = 15
    auth_code_seconds: int = 120
    refresh_token_days: int = 7
    cookie_secure: bool = False
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
