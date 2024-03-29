"""Device code flow tests."""
import time

import httpx
import pytest
import pytest_check as check
import respx

from oidcish.flows.device import DeviceFlow, DeviceStatus, DeviceVerification

from . import common


def mock_device() -> DeviceVerification:
    """Mock data for device verification."""
    code = "4A53BBC987BB24AF360F9EE38DCAD1CC346F77702D3BFC5D69518DF407366221"
    return DeviceVerification.model_validate(
        {
            "device_code": code,
            "user_code": "974954262",
            "verification_uri": "https://idp.example.com/device",
            "verification_uri_complete": "https://idp.example.com/device?userCode=974954262",
            "expires_in": 3,
            "interval": 1,
        }
    )


class TestConnectionErrors:
    """Test suite for connection errors."""

    codec = common.mock_codec()
    data = common.MockFlowData()
    device = mock_device()

    @pytest.fixture(autouse=True)
    def mock_env(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> respx.MockRouter:
        """Mock identity provider."""
        for var, value in self.data.env:
            monkeypatch.setenv(var, value)

        return respx_mock

    @pytest.mark.unit
    @pytest.mark.respx(base_url=data.idp.issuer)
    def test_error_on_timeout(self, respx_mock: respx.MockRouter) -> None:
        """Test that unknown host raises a connect error."""

        respx_mock.get(
            ".well-known/openid-configuration"
        ).side_effect = httpx.ConnectTimeout

        with pytest.raises(httpx.ConnectTimeout):
            auth = DeviceFlow(host=self.data.idp.issuer, timeout=3)
            check.equal(auth.status, DeviceStatus.ERROR)

    @pytest.mark.unit
    @pytest.mark.respx(base_url=data.idp.issuer)
    def test_status_error_when_no_provider_info(
        self, respx_mock: respx.MockRouter
    ) -> None:
        """Test that 404 for discovery document raises a status error."""
        respx_mock.get(".well-known/openid-configuration").respond(status_code=404)

        with pytest.raises(httpx.HTTPStatusError):
            auth = DeviceFlow(host=self.data.idp.issuer)
            check.equal(auth.status, DeviceStatus.ERROR)

    @pytest.mark.unit
    def test_status_error_when_no_device_authorization_endpoint(
        self, respx_mock: respx.MockRouter
    ) -> None:
        """Test that 404 response from authorization endpoint raises status error."""
        respx_mock.get(
            f"{self.data.idp.issuer}/.well-known/openid-configuration"
        ).respond(status_code=200, json=self.data.idp.model_dump())
        respx_mock.get(self.data.idp.jwks_uri).respond(
            status_code=200, json={"keys": [self.codec.key.public_dict]}
        )
        respx_mock.post(self.data.idp.device_authorization_endpoint).respond(
            status_code=404
        )

        with pytest.raises(httpx.HTTPStatusError):
            auth = DeviceFlow(host=self.data.idp.issuer)
            check.equal(auth.status, DeviceStatus.ERROR)


class TestDeviceParsingErrors:
    """Test suite for device flow parsing errors."""

    codec = common.mock_codec()
    data = common.MockFlowData()
    device = mock_device()

    @pytest.fixture(autouse=True)
    def mock_env(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> respx.MockRouter:
        """Mock environment."""
        for var, value in self.data.env:
            monkeypatch.setenv(var, value)

        return respx_mock

    @pytest.fixture()
    def mock_idp(self, respx_mock: respx.MockRouter) -> respx.MockRouter:
        """Mock identity provider."""
        respx_mock.get(
            f"{self.data.idp.issuer}/.well-known/openid-configuration"
        ).respond(status_code=200, json=self.data.idp.model_dump())
        respx_mock.get(self.data.idp.jwks_uri).respond(
            status_code=200, json={"keys": [self.codec.key.public_dict]}
        )
        respx_mock.post(self.data.idp.device_authorization_endpoint).respond(
            status_code=200, json=self.device.model_dump()
        )

        return respx_mock

    @pytest.mark.unit
    def test_validation_error_when_no_json_from_device_authorization_endpoint(
        self, respx_mock: respx.MockRouter
    ) -> None:
        """Test that 200 for authorization endpoint raises value error if not json."""
        respx_mock.get(
            f"{self.data.idp.issuer}/.well-known/openid-configuration"
        ).respond(status_code=200, json=self.data.idp.model_dump())
        respx_mock.get(self.data.idp.jwks_uri).respond(
            status_code=200, json={"keys": [self.codec.key.public_dict]}
        )
        respx_mock.post(self.data.idp.device_authorization_endpoint).respond(
            status_code=200, text=""
        )

        with pytest.raises(ValueError):
            auth = DeviceFlow(host=self.data.idp.issuer)
            check.equal(auth.status, DeviceStatus.ERROR)

    @pytest.mark.unit
    @pytest.mark.usefixtures("mock_idp")
    def test_device_authorization_times_out_without_confirmation(
        self, respx_mock: respx.MockRouter
    ) -> None:
        """Test that the authorization fails when there is no confirmation."""
        respx_mock.post("connect/token").return_value = httpx.Response(
            400, json={"error": "authorization_pending"}
        )

        auth = DeviceFlow(host=self.data.idp.issuer)
        # Wait 10% extra so that confirmation expires
        time.sleep(self.device.expires_in * 1.1)
        check.equal(auth.status, DeviceStatus.NO_CONFIRMATION)
