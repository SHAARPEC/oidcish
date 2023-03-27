"""Models."""
from __future__ import annotations
from typing import List, Optional, Union

import jose
import jose.jwt
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

    id_token: Optional[str]
    access_token: str
    refresh_token: Optional[str]
    expires_in: int
    token_type: str
    scope: str


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
    role: Union[str, List[str], None] = Field(...)
    scope: Union[str, List[str]] = Field(...)
    amr: List[str]

    @staticmethod
    def from_token(token: str) -> Claims:
        """Convert token to claims object."""
        return Claims.parse_obj(jose.jwt.get_unverified_claims(token))


class Jwks(BaseModel):
    """JWKS key."""

    kty: str
    use: str
    kid: str
    x5t: Optional[str]
    e: str
    n: str
    x5c: Optional[List[str]]
    alg: str
