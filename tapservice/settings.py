from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TAPSERVICE_", case_sensitive=False)

    environment: str = "development"
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_username: str | None = None
    mqtt_password: str | None = None

    cors_origins: List[str] = ["http://localhost:3000"]
    websocket_idle_timeout_seconds: int = 60  # timeout for waiting states
    heartbeat_interval_seconds: int = 25  # keep below typical proxy idle cutoff

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

@lru_cache
def get_settings() -> Settings:
    return Settings()
