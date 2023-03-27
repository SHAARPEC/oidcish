"""Test some tests."""
import pytest
import pytest_check as check
import respx

from oidcish.flows.base import AuthenticationFlow, Settings

from . import common


class MockFlow(AuthenticationFlow):
    """Mock class for testing abstract Flow class."""

    def __init__(self, host: str, **kwargs) -> None:
        super().__init__(Settings(host=host, **kwargs))

    def init(self) -> None:
        """Implementation of init method."""
        return None

    def refresh(self) -> None:
        """Implementation of refresh method."""
        return None


class TestGeneralFlow:
    """Tests for general authentication flow."""

    data = common.MockFlowData()
    codec = common.mock_codec(kid="12345")

    @pytest.fixture
    def mock_idp(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> respx.MockRouter:
        """Mock identity provider."""
        for (var, value) in self.data.env:
            monkeypatch.setenv(var, value)

        respx_mock.get(
            f"{self.data.idp.issuer}/.well-known/openid-configuration"
        ).respond(status_code=200, json=self.data.idp.dict())
        respx_mock.get(self.data.idp.jwks_uri).respond(
            status_code=200, json={"keys": [self.codec.key.public_dict]}
        )

        return respx_mock

    @pytest.mark.usefixtures("mock_idp")
    def test_get_info_is_successful(self) -> None:
        """Test that provider info is parsed."""
        flow = MockFlow(host=self.data.idp.issuer)

        check.equal(flow.idp, self.data.idp)
