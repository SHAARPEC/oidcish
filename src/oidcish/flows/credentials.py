"""Client credentials flow."""
import json
import os
import time
from strenum import StrEnum

import background
import httpx
import pendulum
from pydantic import Field, ValidationError

from oidcish import models
from oidcish.flows.base import AuthenticationFlow, Settings


class CredentialsSettings(Settings):
    """Settings for client credentials flow."""

    client_id: str = Field(default=...)
    client_secret: str = Field(default=...)
    audience: str = Field(default=...)

    class Config:
        """Additional configuration."""

        env_prefix = os.environ.get("OIDCISH_ENV_PREFIX", "oidcish_")
        env_file = ".env"
        extra = "ignore"


class CredentialsStatus(StrEnum):
    """Status for client credentials flow."""

    UNINITIALIZED = "UNINITIALIZED: Authentication not started."
    ERROR = "ERROR: Authentication failed."
    SUCCESS = "SUCCESS: Authentication was successful."


class CredentialsFlow(AuthenticationFlow):
    """Authenticate with IDP host using client credentials flow.

    The client on the IDP host must support client credentials flow. Authentication
    arguments can be provided as keywords, environment variables, or in a file whose
    path is given with the special `_env_file` argument. The variables in this file are
    prefixed with the value given by the OIDCISH_ENV_PREFIX environment variable
    (default: OIDCISH_).
    \f
    Parameters
    ----------
      **kwargs : Authentication details and other arguments.

        Valid authentication arguments are:
          host: str, The IDP host name (OIDCISH_HOST).
          client_id: str, The client ID (OIDCISH_CLIENT_ID).
          client_secret: str, The client secret (OIDCISH_CLIENT_SECRET).
          audience: str = The access claim was designated for this audience
            (OIDCISH_AUDIENCE).

        Valid other arguments are:
          poll_rate: float, How often to check for token expiration.
            (default: 1.0)
            None

    Examples
    --------
    >>> from oidcish.credentials import CredentialsFlow
    >>> auth = CredentialsFlow(
            host="https://idp.example.com",
            client_id=...,
            client_secret=...,
            audience=...,
        )
    # Or, read auth variables from my_env_file in working dir
    >>> auth = CredentialsFlow(_env_file="./my_env_file")
    >>> auth.credentials.access_token
    eyJhbGciOiJSU...

    """

    settings: CredentialsSettings

    def __init__(self, **kwargs) -> None:
        poll_rate = kwargs.pop("poll_rate", 1.0)

        super().__init__(CredentialsSettings(**kwargs))

        # Initiate sign-in procedure
        self.init(poll_rate=poll_rate)

    @background.task
    def __auto_refresh(self, poll_rate: float = 1.0) -> None:
        while self.status not in {CredentialsStatus.ERROR}:
            if self.access_claims is None:
                print(
                    "Failed to refresh credentials because there were no access claims."
                )
                break
            if pendulum.now(tz="UTC").int_timestamp > self.access_claims.exp:
                self.refresh()
            time.sleep(poll_rate)

    def init(self, poll_rate: float = 1.0) -> None:
        """Initiate sign-in."""
        data = self.settings.dict()
        data.pop("host")

        response = httpx.post(
            self.idp.token_endpoint,
            data=dict(
                data,
                grant_type="client_credentials",
            ),
        )

        try:
            response.raise_for_status()
            self._credentials = models.Credentials.parse_obj(response.json())
        except httpx.HTTPStatusError as exc:
            self._status = CredentialsStatus.ERROR
            raise httpx.HTTPStatusError(
                request=exc.request,
                response=exc.response,
                message=f"Unexpected response {response.text}.",
            )
        except json.JSONDecodeError as exc:
            self._status = CredentialsStatus.ERROR
            raise json.JSONDecodeError(
                msg=(
                    "Failed to validate client credentials data "
                    f"from {self.idp.token_endpoint}."
                ),
                doc=response.text,
                pos=exc.pos,
            ) from exc
        except ValidationError as exc:
            self._status = CredentialsStatus.ERROR
            raise ValueError(
                f"Failed to validate client credentials data {response.json()} "
                f"from {self.idp.token_endpoint}."
            ) from exc
        else:
            assert response.status_code == 200
            self._status = CredentialsStatus.SUCCESS
            print(self.status)

        if poll_rate > 0:
            # Start monitoring auto refresh in background task
            self.__auto_refresh(poll_rate)

    def refresh(self) -> None:
        """Refresh credentials."""
        if self.credentials is None:
            self._status = CredentialsStatus.UNINITIALIZED
            return

        data = dict(
            self.settings.dict(),
            grant_type="client_credentials",
        )
        data.pop("host")

        response = self._client.post(self.idp.token_endpoint, data=data)

        try:
            response.raise_for_status()
            credentials = models.Credentials.parse_obj(response.json())
        except httpx.HTTPStatusError as exc:
            self._status = CredentialsStatus.ERROR
            raise httpx.HTTPStatusError(
                request=exc.request,
                response=exc.response,
                message=f"Unexpected response {response.text}.",
            )
        except json.JSONDecodeError as exc:
            self._status = CredentialsStatus.ERROR
            raise ValueError(
                f"Failed to decode response {response.text} as json "
                f"from {self.idp.token_endpoint}"
            ) from exc
        except ValidationError as exc:
            self._status = CredentialsStatus.ERROR
            raise ValueError(
                f"Failed to validate refresh data {response.json()} "
                f"from {self.idp.token_endpoint}."
            ) from exc
        else:
            self._credentials = credentials
            self._status = CredentialsStatus.SUCCESS
