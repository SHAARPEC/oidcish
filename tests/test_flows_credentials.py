"""Client credentials flow tests."""
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

    @pytest.fixture(autouse=True)
    def mock_env(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> respx.MockRouter:
        """Mock identity provider."""
        for (var, value) in self.data.env:
            monkeypatch.setenv(var, value)

        return respx_mock

    @pytest.fixture()
    def mock_idp(self, respx_mock: respx.MockRouter) -> respx.MockRouter:
        """Mock identity provider."""
        respx_mock.get(
            f"{self.data.idp.issuer}/.well-known/openid-configuration"
        ).respond(status_code=200, json=self.data.idp.dict())

        respx_mock.get(self.data.idp.jwks_uri).respond(
            status_code=200, json={"keys": [self.codec.key.public_dict]}
        )

    @pytest.mark.usefixtures("mock_idp")
    def test_invalid_client_error_is_caught(self, respx_mock: respx.MockRouter) -> None:
        """Test that invalid client id gives invalid_client error."""
        respx_mock.post("connect/token").return_value = httpx.Response(
            400, json={"error": "invalid_client"}
        )

        with pytest.raises(httpx.HTTPStatusError) as exc:
            auth = CredentialsFlow(host=self.data.idp.issuer)
            check.equal(auth.status, CredentialsStatus.ERROR)
            check.equal(exc.response.status_code, 400)
            check.is_in("error", exc.response.json())
            check.equal(exc.response.json().get("error"), "invalid_client")
