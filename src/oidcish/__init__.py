"""oidcish is a library that obtains claims from an identity provider via OIDC.

Device and code flows are supported.
"""
from oidcish.flows.device import DeviceFlow as DeviceFlow
from oidcish.flows.code import CodeFlow as CodeFlow
from oidcish.flows.credentials import CredentialsFlow as CredentialsFlow
