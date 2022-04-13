"""Settings."""
import os
from pydantic import BaseSettings, Field


class DeviceSettings(BaseSettings):
    """Settings for device."""

    host: str = Field(default=...)
    client_id: str = Field(default=...)
    client_secret: str = Field(default=...)
    scope: str = Field(default=...)

    # pylint: disable=too-few-public-methods
    class Config:
        """Additional configuration."""

        env_prefix = os.environ.get("OIDCISH_ENV_PREFIX", "oicdish_")
        env_file = ".env"
        extra = "ignore"
