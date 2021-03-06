"""Code flow."""
import json
from collections import namedtuple
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit

import background
import httpx
import pkce
from bs4 import BeautifulSoup, element
from pydantic import BaseModel, Field, ValidationError
from strenum import StrEnum

from oidcish import conn, models
from oidcish.flow import AuthenticationFlow, Settings

PkcePair = namedtuple("PkcePair", ["code_verifier", "code_challenge"])


class CodeSettings(Settings):
    """Settings for code flow."""

    client_id: str = Field(default=...)
    client_secret: str = Field(default=...)
    redirect_uri: str = Field(default=...)
    username: str = Field(default=...)
    password: str = Field(default=...)
    audience: str = Field(default=...)
    scope: str = Field(default=...)


class CodeStatus(StrEnum):
    """Status for device authentication flow."""

    UNINITIALIZED = "UNINITIALIZED: Authentication not started."
    PENDING = "PENDING: Authentication is pending."
    ERROR = "ERROR: Authentication failed."
    SUCCESS = "SUCCESS: Authentication was successful."


class PreLoginParameters(BaseModel):
    """Pre-login parameters from IDP server."""

    login_url: str
    return_url: str
    request_verification_token: str
    cookie: str


class LoginParameters(BaseModel):
    """Login parameters from IDP server."""

    code: str


class CodeFlow(AuthenticationFlow):
    """Authenticate with IDP server using code flow.

    The client on the IDP server must support code flow. Authentication arguments can be
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
          redirect_uri: str, Must exactly match one of the allowed redirect URIs for the client.
                             (Default = http://localhost)
          username: str = The user name.
          password: str = The user password.
          scope: str, A space separated, case-sensitive list of scopes.
                      (Default = openid profile offline_access)
          audience: str = The access claim was designated for this audience.

        Valid other arguments are:
          verbose: boolean, Print more information during the login procedure. (Default = False)

    Examples
    --------
    >>> from oidcish.code import CodeFlow
    >>> auth = DeviceFlow(
            host="https://idp.example.com",
            client_id=...,
            client_secret=...,
            redirect_uri=...,
            username=...,
            password=...,
            scope=...,
            audience=...,
        )
    # Or, read auth variables from .env in working dir
    >>> auth = CodeFlow(host="https://idp.example.com")
    >>> auth.credentials.access_token
    eyJhbGciOiJSU...
    """

    settings: CodeSettings

    def __init__(self, host: str, **kwargs) -> None:
        verbose = kwargs.pop("verbose", False)

        super().__init__(CodeSettings(host=host, **kwargs))

        self.pkce_pair = PkcePair(*pkce.generate_pkce_pair())
        self.verbose = verbose

        # Initiate sign-in procedure
        self.init()

    def __pre_login(self) -> PreLoginParameters:
        """Pre-login by sending authorization request to server.

        Returns pre-login parameters.
        """
        response = self._client.get(
            self.idp.authorization_endpoint,
            params={
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "audience": self.settings.audience,
                "scope": self.settings.scope,
                "redirect_uri": self.settings.redirect_uri,
                "response_type": "code",
                "code_challenge_method": "S256"
                if "S256" in self.idp.code_challenge_methods_supported
                else "plain",
                "code_challenge": self.pkce_pair.code_challenge,
            },
        )

        # Follow redirects
        while response.next_request is not None:
            response = self._client.send(response.next_request)

        if self.verbose:
            print(
                f"Pre-login: {response.request.method}: {response.request.url} "
                f"with headers {response.request.headers}."
            )

        login_screen = BeautifulSoup(response.text, features="html.parser")

        assert login_screen is not None, "Server did not send a login screen."

        if isinstance(
            errors := login_screen.find("div", {"class": "error-page"}), element.Tag
        ):
            reason = errors.find("div", {"class": "alert-danger"})

            reason_text = (
                " ".join(reason.get_text().split()) if reason else "Unknown login error"
            )

            raise RuntimeError(reason_text)

        return_url = login_screen.find("input", {"name": "ReturnUrl"}).get("value")
        request_verification_token = login_screen.find(
            "input", {"name": "__RequestVerificationToken"}
        ).get("value")

        cookie = ";".join(
            [
                f"{name}={value}"
                for (name, value) in response.cookies.items()
                if "antiforgery" in name.lower()
            ]
        )

        return PreLoginParameters(
            login_url=urljoin(self.idp.issuer, response.request.url.path),
            return_url=return_url,
            request_verification_token=request_verification_token,
            cookie=cookie,
        )

    def __login(self) -> LoginParameters:
        """Login by sending username and password to server.

        Return login parameters.
        """
        pre_login_parameters = self.__pre_login()

        response = self._client.post(
            pre_login_parameters.login_url,
            headers={"cookie": pre_login_parameters.cookie},
            params={"ReturnUrl": pre_login_parameters.return_url},
            data={
                "ReturnUrl": pre_login_parameters.return_url,
                "Username": self.settings.username,
                "Password": self.settings.password,
                "button": "login",
                "__RequestVerificationToken": pre_login_parameters.request_verification_token,
                "RememberLogin": "false",
            },
        )

        # Follow redirects
        while response.next_request is not None:
            response = self._client.send(response.next_request)

        if self.verbose:
            print(
                f"Authentication: {response.request.method}: {response.request.url} "
                f"with headers {response.request.headers}."
            )

        # Get authorization code from request path
        try:
            code = parse_qs(urlsplit(str(response.url)).query).get("code", [""])[0]
        except ValueError as exc:
            port = urlparse(self.settings.redirect_uri).port or 80
            raise ValueError(
                (
                    "Failed to get authorization code. "
                    f"Make sure no other process is running on port {port}. "
                    "In WSL you might need to run `wsl --shutdown`"
                    "in Windows Powershell to terminate lingering processes."
                )
            ) from exc
        else:
            return LoginParameters(code=code)

    @background.task
    def __start_confirmation_server(self, port: int) -> None:
        # Create server that listens for redirection request.
        with conn.ReuseAddrTCPServer(("", port), conn.SigninRequestHandler) as server:
            while self.status is CodeStatus.PENDING:
                server.handle_request()

    def init(self) -> None:
        """Initiate sign-in."""
        self._status = CodeStatus.PENDING

        port = urlparse(self.settings.redirect_uri).port or 80
        if conn.port_is_free(port):
            # Start redirection server in the background.
            self.__start_confirmation_server(port)

        # Start login process to get authentication code.
        login_parameters = self.__login()

        response = self._client.post(
            self.idp.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "redirect_uri": self.settings.redirect_uri,
                "code": login_parameters.code,
                "code_verifier": self.pkce_pair.code_verifier,
            },
        )

        if self.verbose:
            print(
                f"Token request: {response.request.method}: {response.request.url} "
                f"with headers {response.request.headers}."
            )

        # Parse credentials
        try:
            response.raise_for_status()
            credentials = models.Credentials.parse_obj(response.json())
        except httpx.HTTPStatusError as exc:
            self._status = CodeStatus.ERROR
            raise httpx.HTTPStatusError(
                request=exc.request,
                response=exc.response,
                message=f"Unexpected response {response.text}.",
            )
        except json.JSONDecodeError as exc:
            self._status = CodeStatus.ERROR
            raise ValueError(
                f"Failed to decode response {response.text} as json "
                f"from {self.idp.token_endpoint}"
            ) from exc
        except ValidationError as exc:
            self._status = CodeStatus.ERROR
            raise ValueError(
                f"Failed to validate response data {response.json()} "
                f"from {self.idp.token_endpoint}."
            ) from exc
        else:
            self._credentials = credentials
            self._status = CodeStatus.SUCCESS

    def refresh(self) -> None:
        """Refresh credentials."""
        if self.credentials is None:
            self._status = CodeStatus.UNINITIALIZED
            return
        return

    #     data = dict(
    #         self.settings.dict(),
    #         grant_type="refresh_token",
    #         refresh_token=self.credentials.refresh_token,
    #     )
    #     data.pop("host")

    #     response = self._client.post(self.idp.token_endpoint, data=data)

    #     try:
    #         response.raise_for_status()
    #         credentials = models.Credentials.parse_obj(response.json())
    #     except httpx.HTTPStatusError as exc:
    #         self._status = DeviceStatus.ERROR
    #         raise httpx.HTTPStatusError(
    #             request=exc.request,
    #             response=exc.response,
    #             message=f"Unexpected response {response.text}.",
    #         )
    #     except json.JSONDecodeError as exc:
    #         self._status = DeviceStatus.ERROR
    #         raise ValueError(
    #             f"Failed to decode response {response.text} as json "
    #             f"from {self.idp.token_endpoint}"
    #         ) from exc
    #     except ValidationError as exc:
    #         self._status = DeviceStatus.ERROR
    #         raise ValueError(
    #             f"Failed to validate refresh data {response.json()} "
    #             f"from {self.idp.token_endpoint}."
    #         ) from exc
    #     else:
    #         self._credentials = credentials
    #         self._status = DeviceStatus.SUCCESS
