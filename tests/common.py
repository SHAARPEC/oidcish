"""Test data."""
from uuid import uuid4

import pendulum
from pydantic import BaseModel

from oidcish import models
from oidcish.crypt import Codec


class FlowTestEnv(BaseModel):
    """Test setting environment variables."""

    OIDCISH_CLIENT_ID: str
    OIDCISH_CLIENT_SECRET: str
    OIDCISH_SCOPE: str
    OIDCISH_AUDIENCE: str


class MockFlowData(BaseModel):
    """Mock data for the flow tests."""

    env: FlowTestEnv = FlowTestEnv.parse_obj(
        {
            "OIDCISH_CLIENT_ID": "test_client_id",
            "OIDCISH_CLIENT_SECRET": "test_client_secret",
            "OIDCISH_SCOPE": "test_scope1 test_scope2",
            "OIDCISH_AUDIENCE": "aud",
        }
    )

    idp: models.Idp = models.Idp.parse_obj(
        {
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
    )

    claims: models.Claims = models.Claims.parse_obj(
        {
            "nbf": pendulum.now().int_timestamp,
            "exp": pendulum.now().add(seconds=60).int_timestamp,
            "iss": idp.issuer,
            "aud": idp.issuer,
            "idp": "local",
            "client_id": env.OIDCISH_CLIENT_ID,
            "sub": "foo",
            "auth_time": pendulum.now().subtract(seconds=10).int_timestamp,
            "role": "databases.default",
            "jti": str(uuid4()),
            "sid": str(uuid4()),
            "iat": pendulum.now().int_timestamp,
            "scope": env.OIDCISH_SCOPE,
            "amr": ["pwd"],
        }
    )


def mock_codec(kid: str = "12345") -> Codec:
    """Mock a codec."""
    return Codec.from_size(kid=kid, use="sig")
