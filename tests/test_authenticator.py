"""Authenticator tests."""
from typing import List, Dict, Union

import pytest
import pytest_check as check
import httpx
import respx

from pydantic import BaseModel

from shaarpec import IdpAuthenticator


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
            "shaarpec_api.full_access_scope",
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
    env: Dict[str, str] = {
        "SHAARPEC_IDP_CLIENT_ID": "test_client_id",
        "SHAARPEC_IDP_CLIENT_SECRET": "test_client_secret",
        "SHAARPEC_IDP_SCOPE": "test_scope1 test_scope2",
    }


class TestConnectionErrors:
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
            check.equal(auth.signed_in, False)

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
            check.equal(auth.signed_in, False)

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
            check.equal(auth.signed_in, False)

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
            check.equal(auth.signed_in, False)

    def test_device_authorization_times_out(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> None:
        check.equal(1 + 1, 2)
