"""Client module."""
import json
import time
from typing import Optional

import background
import httpx
from pydantic import ValidationError

from oidcish.settings import DeviceSettings
from oidcish.constants import DeviceStatus
from oidcish import models


class DeviceFlow:
    """Class authenticates with IDP server using device flow."""

    def __init__(self, host: str, **kwargs) -> None:
        self._client = httpx.Client(base_url=host, timeout=kwargs.pop("timeout", 3.0))
        self._idp = self.discover()
        self._status = DeviceStatus.UNINITIALIZED
        self._settings = DeviceSettings(host=host, **kwargs)
        self._credentials: Optional[models.Credentials] = None

        # Initiate sign-in procedure
        self.init()

    def discover(self) -> models.Idp:
        """Read discovery document from IDP server."""
        response = self._client.get(".well-known/openid-configuration")
        response.raise_for_status()

        return models.Idp.parse_obj(response.json())

    def init(self) -> None:
        """Pre-sign in procedure."""
        data = self._settings.dict()
        data.pop("host")

        response = self._client.post(self._idp.device_authorization_endpoint, data=data)
        response.raise_for_status()

        assert response.status_code == 200

        try:
            verification = models.DeviceVerification.parse_obj(response.json())
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
                f"from {self._idp.device_authorization_endpoint}."
            ) from exc
        else:
            self._status = DeviceStatus.PENDING
            print(
                f"Visit {verification.verification_uri_complete} to complete sign-in."
            )

            # Run sign in procedure as background task
            self.__signin_once_confirmed(verification)

    @background.task
    def __signin_once_confirmed(self, verification: models.DeviceVerification) -> None:
        """Background tasks that signs in once the user confirms the device."""
        data = self._settings.dict()
        data.pop("host")

        start = time.time()
        while (elapsed := time.time() - start) <= verification.expires_in:
            response = httpx.post(
                self._idp.token_endpoint,
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
                raise ValueError(
                    f"Failed to decode response {response.text} as json "
                    f"from {self._idp.device_authorization_endpoint}"
                ) from exc
            except ValidationError as exc:
                self._status = DeviceStatus.ERROR
                raise RuntimeError(
                    f"Failed to validate device code data {response.json()} "
                    f"from {self._idp.device_authorization_endpoint}."
                ) from exc
            else:
                self._status = DeviceStatus.SUCCESS
                print(f"{self.status} Took {elapsed} seconds.")
                break

        if self.status is DeviceStatus.PENDING:
            self._status = DeviceStatus.NO_CONFIRMATION
            print(f"Warning: {self.status}")

    @property
    def status(self) -> DeviceStatus:
        """Return the authentication status."""
        return self._status

    @property
    def credentials(self) -> Optional[models.Credentials]:
        """Access IDP credentials."""
        return self._credentials
