"""Client module."""
from typing import Optional
import time
import json

import background
import httpx
from pydantic import ValidationError

from shaarpec.settings import IdpSettings
from shaarpec import models


class IdpAuthenticator:
    """Class authenticates with the IDP server."""

    def __init__(self, host: str, **kwargs) -> None:
        self._client = httpx.Client(base_url=host, timeout=kwargs.pop("timeout", 3.0))
        self._idp = self.discover()
        self._signed_in = False
        self._settings = IdpSettings(host=host, **kwargs)
        self._credentials: Optional[models.IdpCredentials] = None

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
            verification = models.IdpDeviceVerification.parse_obj(response.json())
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Failed to decode response {response.text} as json "
                f"from {self._idp.device_authorization_endpoint}"
            ) from exc
        except ValidationError as exc:
            raise RuntimeError(
                f"Failed to validate device code data {response.json()} "
                f"from {self._idp.device_authorization_endpoint}."
            ) from exc
        else:
            print(
                f"Visit {verification.verification_uri_complete} to complete sign-in."
            )

            # Run sign in procedure as background task
            self.__signin_once_confirmed(verification)

    @background.task
    def __signin_once_confirmed(
        self, verification: models.IdpDeviceVerification
    ) -> None:
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
                self._credentials = models.IdpCredentials.parse_obj(response.json())
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 400:
                    error_msg = exc.response.json().get("error")
                    if error_msg == "authorization_pending":
                        time.sleep(verification.interval)
                    else:
                        raise httpx.HTTPStatusError(
                            request=exc.request,
                            response=exc.response,
                            message=f"Unexpected error message {error_msg}.",
                        ) from exc
                else:
                    raise httpx.HTTPStatusError(
                        request=exc.request,
                        response=exc.response,
                        message=f"Unexpected response {response.text}.",
                    )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Failed to decode response {response.text} as json "
                    f"from {self._idp.device_authorization_endpoint}"
                ) from exc
            except ValidationError as exc:
                raise RuntimeError(
                    f"Failed to validate device code data {response.json()} "
                    f"from {self._idp.device_authorization_endpoint}."
                ) from exc
            else:
                print(f"Signed in after {elapsed} seconds.")
                self._signed_in = True
                break

        if not self.signed_in:
            print("Warning: Sign-in time expired without confirmation.")

    @property
    def signed_in(self) -> bool:
        """Whether client is signed in to host."""
        return self._signed_in

    @property
    def credentials(self) -> Optional[models.IdpCredentials]:
        """Access IDP credentials."""
        return self._credentials
