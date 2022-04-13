"""Constants."""
from strenum import StrEnum


class DeviceStatus(StrEnum):
    """Status for authentication with device code flow."""

    UNINITIALIZED = "Authentication not started."
    PENDING = "Authentication is pending."
    NO_CONFIRMATION = "Authentication expired without confirmation."
    EXPIRED = "Authentication claims have expired."
    ERROR = "Authentication failed."
    SUCCESS = "Authentication was successful."
