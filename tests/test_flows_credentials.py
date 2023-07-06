"""Client credentials flow tests."""
import time
from typing import Iterator

import httpx
import pytest
import pytest_check as check
import respx

from oidcish.flows.credentials import CredentialsFlow, CredentialsStatus

from . import common


class TestGeneralCredentialsFlow:
    """Test suite for client credentials flow."""

    codec = common.mock_codec()
    data = common.MockFlowData()

    @pytest.fixture()
    def mock_env_basic(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> respx.MockRouter:
        """Mock identity provider."""
        for var, value in self.data.env:
            monkeypatch.setenv(var, value)

        return respx_mock

    @pytest.fixture(name="auth_credentials")
    def mock_client_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> Iterator[CredentialsFlow]:
        """Mock identity provider."""
        for var, value in {
            "OIDCISH_HOST": "http://oidc_server_mock",
            "OIDCISH_CLIENT_ID": "mock-client-credentials",
            "OIDCISH_CLIENT_SECRET": "mock-client-credentials-secret",
            "OIDCISH_AUDIENCE": "mock-client-credentials-audience",
        }.items():
            monkeypatch.setenv(var, value)

        auth = CredentialsFlow()

        if auth is None:
            pytest.fail("CredentialsFlow failed to initialize")
        if auth.credentials is None or auth.access_claims is None:
            pytest.fail("CredentialsFlow failed to fetch credentials")

        yield auth

        auth._status = CredentialsStatus.ERROR

    @pytest.fixture()
    def mock_idp(self, respx_mock: respx.MockRouter) -> None:
        """Mock identity provider."""
        respx_mock.get(
            f"{self.data.idp.issuer}/.well-known/openid-configuration"
        ).respond(status_code=200, json=self.data.idp.dict())

        respx_mock.get(self.data.idp.jwks_uri).respond(
            status_code=200, json={"keys": [self.codec.key.public_dict]}
        )

    @pytest.mark.unit
    @pytest.mark.usefixtures("mock_env_basic", "mock_idp")
    def test_invalid_client_error_is_caught(self, respx_mock: respx.MockRouter) -> None:
        """Test that invalid client id gives invalid_client error."""
        respx_mock.post("connect/token").return_value = httpx.Response(
            400, json={"error": "invalid_client"}
        )

        with pytest.raises(httpx.HTTPStatusError) as exc:
            auth = CredentialsFlow(host=self.data.idp.issuer)
            check.equal(auth.status, CredentialsStatus.ERROR)
            check.equal(exc.response.status_code, 400)  # type: ignore
            check.is_in("error", exc.response.json())  # type: ignore
            check.equal(exc.response.json().get("error"), "invalid_client")  # type: ignore  # noqa: E501

    @pytest.mark.integration
    def test_client_credentials_are_refreshed(
        self, auth_credentials: CredentialsFlow
    ) -> None:
        assert auth_credentials.credentials is not None
        assert auth_credentials.access_claims is not None

        expires_in = auth_credentials.credentials.expires_in
        original = auth_credentials.access_claims.exp
        refreshed = auth_credentials.access_claims.exp

        start = time.time()
        while (refreshed == original) or ((time.time() - start) > (2 * expires_in)):
            refreshed = auth_credentials.access_claims.exp
            time.sleep(0.1)

        check.greater(refreshed, original)
