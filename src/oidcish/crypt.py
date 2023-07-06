"""Cryptography module."""
from __future__ import annotations
from typing import Dict, Mapping, Any, MutableMapping

import jose
import jose.jwt
import jose.constants
from jose.jwk import RSAKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class RsaKeysFactory:
    """Create and handle RSA key pair."""

    def __init__(
        self,
        public_exponent: int = 65537,
        key_size: int = 2048,
        algorithm: str = jose.constants.Algorithms.RS256,
        **kwargs,
    ) -> None:
        self._algorithm = algorithm
        self._private_key = rsa.generate_private_key(
            public_exponent=public_exponent, key_size=key_size
        )
        self._public_key = self._private_key.public_key()
        self.headers = kwargs

    @property
    def algorithm(self) -> str:
        """The algorithm used by RSA keys factory."""
        return self._algorithm

    @property
    def private_pem(self) -> str:
        """The private RSA key in PEM format."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    @property
    def public_pem(self) -> str:
        """The public RSA key in PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    @property
    def private(self) -> RSAKey | None:  # type: ignore
        """The private RSA key."""
        if RSAKey:
            return RSAKey(algorithm=self.algorithm, key=self.private_pem)
        return None

    @property
    def public(self) -> RSAKey | None:  # type: ignore
        """The public RSA key."""
        if RSAKey:
            return RSAKey(algorithm=self.algorithm, key=self.public_pem)
        return None

    @property
    def private_dict(self) -> Dict[str, Any] | None:
        """The private RSA key as a dictionary."""
        if self.private:
            return {**self.private.to_dict(), **self.headers}
        return None

    @property
    def public_dict(self) -> Dict[str, Any] | None:
        """The public RSA key as a dictionary."""
        if self.public:
            return {**self.public.to_dict(), **self.headers}
        return None


class Codec:
    """Class that uses a RsaKeysFactory to encode and decode claims."""

    def __init__(self, key: RsaKeysFactory) -> None:
        self._key = key

    @classmethod
    def from_size(
        cls,
        key_size: int = 2048,
        algorithm: str = jose.constants.Algorithms.RS256,
        **kwargs,
    ) -> Codec:
        """Create a Codec that uses the given key size and algorithm."""
        key_factory = RsaKeysFactory(key_size=key_size, algorithm=algorithm, **kwargs)
        return cls(key=key_factory)

    def encode(self, claims: MutableMapping[Any, Any]) -> str | None:
        """Encode claims.

        kwargs are used as extra headers.
        """
        if self._key.private_dict:
            return jose.jwt.encode(
                claims,
                key=self._key.private_dict,
                algorithm=self._key.algorithm,
                headers=self._key.headers,
            )
        return None

    def decode(self, token: str) -> Mapping[Any, Any] | None:
        """Decode the claims in the token."""
        if self._key.public_dict:
            return jose.jwt.decode(token, key=self._key.public_dict)
        return None

    @staticmethod
    def get_unverified_claims(token: str) -> Mapping[Any, Any]:
        """Get unverified claims in the token."""
        return jose.jwt.get_unverified_claims(token)

    @property
    def key(self):
        """Access RSA key."""
        return self._key
