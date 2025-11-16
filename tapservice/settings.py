from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TAPSERVICE_", case_sensitive=False)

    environment: str = "development"
    mqtt_host: str = "localhost"  # Internal service-to-broker connection
    mqtt_external_host: str | None = None  # External device-to-broker connection (defaults to mqtt_host)
    mqtt_port: int = 1883
    mqtt_tls_port: int = 8883
    mqtt_use_tls: bool = False  # Enable TLS for internal service connection
    mqtt_username: str | None = None
    mqtt_password: str | None = None
    mqtt_client_cert: str | None = None  # Client certificate for mTLS (service-to-broker)
    mqtt_client_key: str | None = None   # Client private key for mTLS

    @property
    def device_mqtt_host(self) -> str:
        """MQTT host that devices should connect to (external accessible address)."""
        return self.mqtt_external_host or self.mqtt_host

    @property
    def device_mqtt_port(self) -> int:
        """MQTT port for devices (always use TLS port for mTLS connections)."""
        return self.mqtt_tls_port

    # Certificate paths for mTLS and device provisioning
    ca_cert_path: str = "/etc/libretap/ca/ca.crt"
    ca_key_path: str = "/etc/libretap/ca/ca.key"
    crl_path: str | None = "/etc/libretap/ca/crl.pem"
    
    # Device certificate validity
    device_cert_validity_days: int = 365

    cors_origins: List[str] = ["http://localhost:3000"]
    websocket_idle_timeout_seconds: int = 60  # timeout for waiting states
    heartbeat_interval_seconds: int = 25  # keep below typical proxy idle cutoff

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

@lru_cache
def get_settings() -> Settings:
    return Settings()
