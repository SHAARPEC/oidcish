"""Code flow."""
from collections import namedtuple
from multiprocessing import Process
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit

import pkce
from bs4 import BeautifulSoup, element
from pydantic import BaseModel, Field, ValidationError

from oidcish import models
from oidcish.flow import Flow, Settings
from oidcish import server

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


class PreLoginParameters(BaseModel):
    """Pre-login parameters from IDP server."""

    login_url: str
    return_url: str
    request_verification_token: str
    cookie: str


class LoginParameters(BaseModel):
    """Login parameters from IDP server."""

    code: str


class Code(Flow):
    """Class authenticates with IDP server using code flow.

    Class for authenticating with the IDP server.
    \f
    Parameters
    ----------
    host : str
           Address to OIDC server, e.g. https://idp.someprovider.com
    **kwargs: dict, optional
           Dict with settings for the IDP server.

    Examples
    --------
    >>> from oidcish import Code
    >>> auth = Code(host="https://idp.example.com")
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
        params = self.settings.dict()
        params = {
            setting: params[setting]
            for setting in (
                "client_id",
                "client_secret",
                "audience",
                "scope",
                "redirect_uri",
            )
            if setting in params
        }

        response = self._client.get(
            self.idp.authorization_endpoint,
            params=dict(
                params,
                response_type="code",
                code_challenge_method="S256",
                code_challenge=self.pkce_pair.code_challenge,
            ),
        )

        if self.verbose:
            print(
                f"Pre-login: {response.request.method}: {response.request.url} "
                f"with headers {response.request.headers} "
                f'and content is "{response.request.content}"'
            )

        login_uri = response.request.url

        login_screen = BeautifulSoup(response.text, features="html.parser")

        if login_screen is None:
            raise RuntimeError("Server did not send a login screen..")

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
            login_url=urljoin(self.idp.issuer, login_uri.path),
            return_url=return_url,
            request_verification_token=request_verification_token,
            cookie=cookie,
        )

    def __login(self) -> LoginParameters:
        """Login by sending username and password to server.

        Return login parameters.
        """
        pre_login_parameters = self.__pre_login()

        rvt = pre_login_parameters.request_verification_token

        response = self._client.post(
            pre_login_parameters.login_url,
            headers={"cookie": pre_login_parameters.cookie},
            params={"ReturnUrl": pre_login_parameters.return_url},
            data={
                "ReturnUrl": pre_login_parameters.return_url,
                "Username": self.settings.username,
                "Password": self.settings.password,
                "button": "login",
                "__RequestVerificationToken": rvt,
                "RememberLogin": "false",
            },
        )

        if self.verbose:
            print(
                f"Authentication: {response.request.method}: {response.request.url} "
                f"with headers {response.request.headers} "
                f'and content is "{response.request.content}"'
            )

        # Get authorization code from request path
        if not (
            code := parse_qs(urlsplit(str(response.request.url)).query).get(
                "code", [""]
            )[0]
        ):
            port = urlparse(self.settings.redirect_uri).port or 80
            raise ValueError(
                (
                    "Failed to get authorization code. "
                    f"Make sure no other process is running on port {port}. "
                    "In WSL you might need to run `wsl --shutdown`"
                    "in Windows Powershell to terminate lingering processes."
                )
            )

        return LoginParameters(code=code)

    def init(self) -> None:
        """Initiate sign-in."""
        port = urlparse(self.settings.redirect_uri).port or 80

        idle_server: Optional[server.ReuseAddrTCPServer] = None
        idle_server_process: Optional[Process] = None
        if no_server := not server.port_is_used(port):
            # Setup server that listens for redirection request.
            idle_server = server.ReuseAddrTCPServer(
                ("", port), server.SigninRequestHandler
            )
            # Handle request in separate thread
            idle_server_process = Process(
                target=idle_server.handle_request, daemon=True
            )
            idle_server_process.start()

        # Start login process
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
                f"with headers {response.request.headers} "
                f'and content is "{response.request.content}"'
            )

        # Parse credentials
        try:
            credentials = models.Credentials.parse_obj(response.json())
        except ValidationError as exc:
            raise ValueError(f"{response}: {response.json()}") from exc
        else:
            self._credentials = credentials

        if no_server and idle_server is not None and idle_server_process is not None:
            # Shutdown server listening for redirection request.
            idle_server.server_close()
            idle_server_process.terminate()
            idle_server_process.join()

    # def refresh(self) -> Credentials:
    #     """Return refreshed credentials."""

    #     response = requests.post(
    #         self._oidc.token_endpoint,
    #         data={
    #             "grant_type": "refresh_token",
    #             "client_id": self._idp.client_id,
    #             "client_secret": self._idp.client_secret,
    #             "refresh_token": self._credentials.refresh_token,
    #         },
    #     )

    #     # Parse credentials
    #     try:
    #         credentials = Credentials.parse_obj(response.json())
    #     except ValidationError as exc:
    #         raise ValueError(f"{response}: {response.json()}") from exc

    #     return credentials
