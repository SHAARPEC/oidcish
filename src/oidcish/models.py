"""Models."""
from typing import List, Optional

from pydantic import BaseModel, Field


class Idp(BaseModel):
    """IDP discovery document."""

    authorization_endpoint: str
    backchannel_logout_session_supported: bool
    backchannel_logout_supported: bool
    check_session_iframe: str
    claims_supported: List[str]
    code_challenge_methods_supported: List[str]
    device_authorization_endpoint: str
    end_session_endpoint: str
    frontchannel_logout_session_supported: bool
    frontchannel_logout_supported: bool
    grant_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    introspection_endpoint: str
    issuer: str
    jwks_uri: str
    request_parameter_supported: bool
    response_modes_supported: List[str]
    response_types_supported: List[str]
    revocation_endpoint: str
    scopes_supported: List[str]
    subject_types_supported: List[str]
    token_endpoint: str
    token_endpoint_auth_methods_supported: List[str]
    userinfo_endpoint: str


class Credentials(BaseModel):
    """Credentials from IDP server."""

    id_token: str
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str
    scope: str


class DeviceVerification(BaseModel):
    """Device verification from IDP server."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class Claims(BaseModel):
    """Set of reserved claims for a token."""

    nbf: int
    exp: int
    iss: str
    aud: str
    client_id: str
    sub: str
    auth_time: int
    idp: str
    jti: str
    iat: int
    role: Optional[List[str]] = Field(None)
    scope: List[str]
    amr: List[str]
