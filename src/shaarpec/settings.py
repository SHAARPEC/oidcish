"""Settings."""

from pydantic import BaseSettings, Field


class IdpSettings(BaseSettings):
    """Settings for API client."""

    host: str = Field(default=...)
    client_id: str = Field(default=...)
    client_secret: str = Field(default=...)
    scope: str = Field(default=...)

    # pylint: disable=too-few-public-methods
    class Config:
        """Additional configuration."""

        env_prefix = "shaarpec_idp_"
        env_file = ".env"
        extra = "ignore"
