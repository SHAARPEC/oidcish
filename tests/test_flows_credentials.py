"""Device code flow tests."""
# import secrets
import time

# from typing import List, Dict, Union, Any
# from uuid import uuid4

import httpx

# import pendulum
import pytest
import pytest_check as check
import respx

from oidcish.flows.device import DeviceFlow, DeviceStatus, DeviceVerification

from . import common


class TestFoo:
    """Test suite for foo."""

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

    @pytest.mark.respx(base_url=data.idp.issuer)
    def test_foo(self) -> None:
        """Test foo."""

        assert True
