"""Device flow."""
import json
import time
from strenum import StrEnum

import background
import httpx
import pendulum
from pydantic import BaseModel, Field, ValidationError

from oidcish import models
from oidcish.flow import AuthenticationFlow, Settings


class DeviceSettings(Settings):
    """Settings for device authentication flow."""

    client_id: str = Field(default=...)
    client_secret: str = Field(default=...)
    scope: str = Field(default=...)
    audience: str = Field(default=...)


class DeviceStatus(StrEnum):
    """Status for device authentication flow."""

    UNINITIALIZED = "UNINITIALIZED: Authentication not started."
    PENDING = "PENDING: Authentication is pending."
    NO_CONFIRMATION = "NO_CONFIRMATION: Authentication expired without confirmation."
    EXPIRED = "EXPIRED: Authentication claims have expired."
    ERROR = "ERROR: Authentication failed."
    SUCCESS = "SUCCESS: Authentication was successful."


class DeviceVerification(BaseModel):
    """Device verification from IDP server."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class DeviceFlow(AuthenticationFlow):
    """Authenticate with IDP server using device flow.

    The client on the IDP server must support device flow. Authentication arguments can be
    provided as keywords or omitted and read from a .env file in the working directory.
    The environment variables are prefixed with OIDCISH, so OIDCISH_CLIENT_ID etc.
    \f
    Parameters
    ----------
      host : str
        The IDP host name.
      **kwargs : Authentication details and other arguments.

        Valid authentication arguments are:
          client_id: str, The client ID.
          client_secret: str, The client secret.
          scope: str, A space separated, case-sensitive list of scopes.
                      (Default = openid profile offline_access)
          audience: str = The access claim was designated for this audience.

        Valid other arguments are:
          poll_rate: float, How often to check for sign in completion in seconds (Default = 1.0).

    Examples
    --------
    >>> from oidcish.device import DeviceFlow
    >>> auth = DeviceFlow(
            host="https://idp.example.com",
            client_id=...,
            client_secret=...,
            scope=...,
            audience=...,
        )
    # Or, read auth variables from .env in working dir
    >>> auth = DeviceFlow(host="https://idp.example.com")
    >>> auth.credentials.access_token
    eyJhbGciOiJSU...

    """

    settings: DeviceSettings

    def __init__(self, host: str, **kwargs) -> None:
        poll_rate = kwargs.pop("poll_rate", 1.0)

        super().__init__(DeviceSettings(host=host, **kwargs))

        # Initiate sign-in procedure
        self.init(poll_rate=poll_rate)

    @background.task
    def __signin_once_confirmed(self, verification: DeviceVerification) -> None:
        """Background tasks that signs in once the user confirms the device."""
        data = self.settings.dict()
        data.pop("host")

        start = time.time()
        while (elapsed := time.time() - start) <= verification.expires_in and (
            self.status is not DeviceStatus.ERROR
        ):
            response = httpx.post(
                self.idp.token_endpoint,
                data=dict(
                    data,
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    device_code=verification.device_code,
                ),
            )

            try:
                response.raise_for_status()
                self._credentials = models.Credentials.parse_obj(response.json())
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 400:
                    error_msg = exc.response.json().get("error")
                    if error_msg == "authorization_pending":
                        time.sleep(verification.interval)
                    else:
                        self._status = DeviceStatus.ERROR
                        raise httpx.HTTPStatusError(
                            request=exc.request,
                            response=exc.response,
                            message=f"Unexpected error message {error_msg}.",
                        ) from exc
                else:
                    self._status = DeviceStatus.ERROR
                    raise httpx.HTTPStatusError(
                        request=exc.request,
                        response=exc.response,
                        message=f"Unexpected response {response.text}.",
                    )
            except json.JSONDecodeError as exc:
                self._status = DeviceStatus.ERROR
                raise json.JSONDecodeError(
                    msg=(
                        "Failed to validate device code data "
                        f"from {self.idp.device_authorization_endpoint}."
                    ),
                    doc=response.text,
                    pos=exc.pos,
                ) from exc
            except ValidationError as exc:
                self._status = DeviceStatus.ERROR
                raise ValueError(
                    f"Failed to validate device code data {response.json()} "
                    f"from {self.idp.device_authorization_endpoint}."
                ) from exc
            else:
                self._status = DeviceStatus.SUCCESS
                print(f"{self.status} Took {elapsed} seconds.")
                break

        if self.status is DeviceStatus.PENDING:
            self._status = DeviceStatus.NO_CONFIRMATION
            print(f"Warning: {self.status}")

    @background.task
    def __auto_refresh(self, poll_rate: float = 1.0) -> None:
        while self.status not in {DeviceStatus.NO_CONFIRMATION, DeviceStatus.ERROR}:
            if (self.access_claims is not None) and (
                pendulum.now(tz="UTC").int_timestamp > self.access_claims.exp
            ):
                self.refresh()
            time.sleep(poll_rate)

    def init(self, poll_rate: float = 1.0) -> None:
        """Initiate sign-in."""
        data = self.settings.dict()
        data.pop("host")

        response = self._client.post(self.idp.device_authorization_endpoint, data=data)

        try:
            response.raise_for_status()
            verification = DeviceVerification.parse_obj(response.json())
        except httpx.HTTPStatusError as exc:
            self._status = DeviceStatus.ERROR
            raise httpx.HTTPStatusError(
                request=exc.request,
                response=exc.response,
                message=f"Unexpected response {response.text}.",
            )
        except json.JSONDecodeError as exc:
            self._status = DeviceStatus.ERROR
            raise ValueError(
                f"Failed to decode response {response.text} as json "
                f"from {self._idp.device_authorization_endpoint}"
            ) from exc
        except ValidationError as exc:
            self._status = DeviceStatus.ERROR
            raise RuntimeError(
                f"Failed to validate device code data {response.json()} "
                f"from {self.idp.device_authorization_endpoint}."
            ) from exc
        else:
            assert response.status_code == 200
            self._status = DeviceStatus.PENDING
            print(
                f"Visit {verification.verification_uri_complete} to complete sign-in."
            )

            # Run sign in procedure as background task
            self.__signin_once_confirmed(verification)

            if poll_rate > 0:
                # Start monitoring auto refresh in background task
                self.__auto_refresh(poll_rate)

    def refresh(self) -> None:
        """Refresh credentials."""
        if self.credentials is None:
            self._status = DeviceStatus.UNINITIALIZED
            return

        data = dict(
            self.settings.dict(),
            grant_type="refresh_token",
            refresh_token=self.credentials.refresh_token,
        )
        data.pop("host")

        response = self._client.post(self.idp.token_endpoint, data=data)

        try:
            response.raise_for_status()
            credentials = models.Credentials.parse_obj(response.json())
        except httpx.HTTPStatusError as exc:
            self._status = DeviceStatus.ERROR
            raise httpx.HTTPStatusError(
                request=exc.request,
                response=exc.response,
                message=f"Unexpected response {response.text}.",
            )
        except json.JSONDecodeError as exc:
            self._status = DeviceStatus.ERROR
            raise ValueError(
                f"Failed to decode response {response.text} as json "
                f"from {self.idp.token_endpoint}"
            ) from exc
        except ValidationError as exc:
            self._status = DeviceStatus.ERROR
            raise ValueError(
                f"Failed to validate refresh data {response.json()} "
                f"from {self.idp.token_endpoint}."
            ) from exc
        else:
            self._credentials = credentials
            self._status = DeviceStatus.SUCCESS
