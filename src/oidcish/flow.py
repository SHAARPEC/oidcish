"""Definition of authentication flows."""
import os
from abc import ABC, abstractmethod
from typing import List, Optional, final

import httpx
import jose
import jose.jwt
from pydantic import BaseSettings, Field, parse_obj_as
from strenum import StrEnum

from oidcish import models


class Status(StrEnum):
    """Base enum for general authentication flow."""

    UNINITIALIZED = "UNINITIALIZED: Authentication not started."


class Settings(BaseSettings):
    """Settings for general authentication flow."""

    host: str = Field(default=...)
    timeout: float = Field(default=3.0)

    # pylint: disable=too-few-public-methods
    class Config:
        """Additional configuration."""

        env_prefix = os.environ.get("OIDCISH_ENV_PREFIX", "oidcish_")
        env_file = ".env"
        extra = "ignore"


class AuthenticationFlow(ABC):
    """Abstract class for authentication flows."""

    def __init__(self, settings: Settings) -> None:
        # Set attributes
        self._client = httpx.Client(base_url=settings.host, timeout=settings.timeout)
        self._idp = self.get_info()
        self._jwks = self.get_jwks()
        self._status = Status.UNINITIALIZED
        self._settings = settings
        self._credentials: Optional[models.Credentials] = None

    @final
    def get_info(self) -> models.Idp:
        """Get discovery document from identity provider."""
        response = self._client.get(".well-known/openid-configuration")
        response.raise_for_status()

        return models.Idp.parse_obj(response.json())

    @final
    def get_jwks(self) -> List[models.Jwks]:
        """Get public JWK set from identity provider."""
        response = self._client.get(self.idp.jwks_uri)
        response.raise_for_status()

        return parse_obj_as(List[models.Jwks], response.json().get("keys"))

    @final
    @property
    def status(self) -> Status:
        """Access authentication status."""
        return self._status

    @final
    @property
    def settings(self) -> Settings:
        """Access settings."""
        return self._settings

    @final
    @property
    def credentials(self) -> Optional[models.Credentials]:
        """Access credentials."""
        return self._credentials

    @final
    @property
    def idp(self) -> models.Idp:
        """Access provider info."""
        return self._idp

    @final
    @property
    def jwks(self) -> List[models.Jwks]:
        """Access public JWK set."""
        return self._jwks

    @final
    @property
    def jwks_key(self) -> Optional[models.Jwks]:
        """Access public JWK key corresponding to credentials."""
        if self.credentials is None:
            return None

        unverified_header = jose.jwt.get_unverified_header(
            self.credentials.access_token
        )
        return {key.kid: key for key in self.jwks}.get(unverified_header["kid"])

    @final
    @property
    def id_claims(self) -> Optional[models.Claims]:
        """Id claims corresponding to credentials."""
        if self.credentials is None:
            return None

        return models.Claims.from_token(self.credentials.id_token)

    @final
    @property
    def access_claims(self) -> Optional[models.Claims]:
        """Access claims corresponding to credentials."""
        if self.credentials is None:
            return None

        return models.Claims.from_token(self.credentials.access_token)

    @abstractmethod
    def init(self) -> None:
        """Initiate sign-in."""
        raise NotImplementedError

    @abstractmethod
    def refresh(self) -> None:
        """Refresh credentials."""
        raise NotImplementedError
