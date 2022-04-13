"""Device code flow tests."""
import time
import secrets
from typing import List, Dict, Union, Any
from uuid import uuid4

import httpx
import respx
import pendulum
import pytest
import pytest_check as check

from pydantic import BaseModel

from oidcish import DeviceFlow
from oidcish.crypt import Codec
from oidcish.constants import DeviceStatus


class IdpData(BaseModel):
    """Test suite for connection errors."""

    host: str = "https://idp.example.com"
    doc: Dict[str, Union[str, bool, List[str]]] = {
        "issuer": "https://idp.example.com",
        "jwks_uri": "https://idp.example.com/.well-known/openid-configuration/jwks",
        "authorization_endpoint": "https://idp.example.com/connect/authorize",
        "token_endpoint": "https://idp.example.com/connect/token",
        "userinfo_endpoint": "https://idp.example.com/connect/userinfo",
        "end_session_endpoint": "https://idp.example.com/connect/endsession",
        "check_session_iframe": "https://idp.example.com/connect/checksession",
        "revocation_endpoint": "https://idp.example.com/connect/revocation",
        "introspection_endpoint": "https://idp.example.com/connect/introspect",
        "device_authorization_endpoint": "https://idp.example.com/connect/deviceauthorization",
        "frontchannel_logout_supported": True,
        "frontchannel_logout_session_supported": True,
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "scopes_supported": [
            "roles",
            "openid",
            "offline_access",
        ],
        "claims_supported": ["role", "sub"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "implicit",
            "password",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "id_token token",
            "code id_token",
            "code token",
            "code id_token token",
        ],
        "response_modes_supported": ["form_post", "query", "fragment"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "request_parameter_supported": True,
    }

    device_authorization: Dict[str, Any] = {
        "device_code": "4A53BBC987BB24AF360F9EE38DCAD1CC346F77702D3BFC5D69518DF407366221",
        "user_code": "974954262",
        "verification_uri": "https://idp.example.com/device",
        "verification_uri_complete": "https://idp.example.com/device?userCode=974954262",
        "expires_in": 3,
        "interval": 1,
    }

    env: Dict[str, str] = {
        "OICDISH_CLIENT_ID": "test_client_id",
        "OICDISH_CLIENT_SECRET": "test_client_secret",
        "OICDISH_SCOPE": "test_scope1 test_scope2",
    }


class TestErrorsWithConnection:
    """Test suite for connection errors."""

    data = IdpData()

    @pytest.mark.respx(base_url=data.host)
    def test_unknown_host_raises_timeout_error(
        self, respx_mock: respx.MockRouter
    ) -> None:
        """Test that unknown host raises a connect error."""
        respx_mock.get(
            ".well-known/openid-configuration"
        ).side_effect = httpx.ConnectTimeout

        with pytest.raises(httpx.ConnectTimeout):
            auth = IdpAuthenticator(self.data.host, timeout=3)
            check.equal(auth.status, AuthenticationStatus.ERROR)

    @pytest.mark.respx(base_url=data.host)
    def test_discovery_document_not_found_raises_status_error(
        self, respx_mock: respx.MockRouter
    ) -> None:
        """Test that 404 for discovery document raises a status error."""
        respx_mock.get(
            ".well-known/openid-configuration"
        ).return_value = httpx.Response(404, text="")

        with pytest.raises(httpx.HTTPStatusError):
            auth = IdpAuthenticator(self.data.host)
            check.equal(auth.status, AuthenticationStatus.ERROR)

    @pytest.mark.respx(base_url=data.host)
    def test_device_authorization_endpoint_not_found_raises_status_error(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> None:
        """Test that 404 for device authorization endpoint raises status error."""
        for (var, value) in self.data.env.items():
            monkeypatch.setenv(var, value)

        respx_mock.get(
            ".well-known/openid-configuration"
        ).return_value = httpx.Response(200, json=self.data.doc)
        respx_mock.post("connect/deviceauthorization").return_value = httpx.Response(
            404, text=""
        )

        with pytest.raises(httpx.HTTPStatusError):
            auth = IdpAuthenticator(self.data.host)
            check.equal(auth.status, AuthenticationStatus.ERROR)

    @pytest.mark.respx(base_url=data.host)
    def test_device_authorization_endpoint_ok_but_no_json_raises_value_error(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> None:
        """Test that 200 for device authorization endpoint raises value error if not json."""
        for (var, value) in self.data.env.items():
            monkeypatch.setenv(var, value)

        respx_mock.get(
            ".well-known/openid-configuration"
        ).return_value = httpx.Response(200, json=self.data.doc)
        respx_mock.post("connect/deviceauthorization").return_value = httpx.Response(
            200, text=""
        )

        with pytest.raises(ValueError):
            auth = IdpAuthenticator(self.data.host)
            check.equal(auth.status, AuthenticationStatus.ERROR)


# class TestErrorsWithSignin:
#     """Test suite for sign-in errors."""

#     data = IdpData()
#     codec = ClaimsCodec.from_size(kid="12345", use="sig")

#     def test_device_authorization_times_out_without_confirmation(
#         self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
#     ) -> None:
#         for (var, value) in self.data.env.items():
#             monkeypatch.setenv(var, value)

#         respx_mock.get(
#             ".well-known/openid-configuration"
#         ).return_value = httpx.Response(200, json=self.data.doc)
#         respx_mock.post("connect/deviceauthorization").return_value = httpx.Response(
#             200, json=self.data.device_authorization
#         )
#         respx_mock.post("connect/token").return_value = httpx.Response(
#             200, json={"error": "authorization_pending"}
#         )

#         # with pytest.raises(jose.exceptions.ExpiredSignatureError):
#         auth = IdpAuthenticator(self.data.host)

#         time.sleep(self.data.device_authorization["expires_in"] + 2)

#         check.equal(auth.status, AuthenticationStatus.SUCCESS)


class TestSuccessWithSignin:
    """Test suite for successful sign-ins."""

    data = IdpData()

    def test_succesful_signin(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> None:
        """Test that device can sign in."""
        for (var, value) in self.data.env.items():
            monkeypatch.setenv(var, value)

        respx_mock.get(
            ".well-known/openid-configuration"
        ).return_value = httpx.Response(200, json=self.data.doc)
        respx_mock.post("connect/deviceauthorization").return_value = httpx.Response(
            200, json=self.data.device_authorization
        )

        access_claims = {
            "nbf": pendulum.now().int_timestamp,
            "exp": pendulum.now().add(seconds=self.data.token_info["expires_in"]),
            "iss": self.data.host,
            "aud": self.data.host,
            "client_id": self.data.env["CLIENT_ID"],
            "sub": "foo",
            "auth_time": pendulum.now().subtract(seconds=10).int_timestamp,
            "role": "databases.neo4j",
            "jti": uuid4(),
            "sid": uuid4(),
            "iat": pendulum.now().int_timestamp,
            "scope": self.data.env["SCOPE"],
            "amr": ["pwd"],
        }

        respx_mock.post("connect/token").return_value = httpx.Response(
            200, json=self.data.token_info
        )

        auth = IdpAuthenticator(self.data.host)

        time.sleep(self.data.device_authorization["expires_in"])

        check.equal(auth.status, AuthenticationStatus.SUCCESS)
