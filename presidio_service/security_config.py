"""Fail-closed security configuration for the Presidio web service."""

from dataclasses import dataclass
import os
import re
from typing import Mapping
from werkzeug.security import check_password_hash


@dataclass(frozen=True)
class SecurityConfig:
    session_secret: str
    username: str
    password_hash: str


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set before the service starts.")
    return value


def _validate_password_hash(password_hash: str) -> None:
    error = (
        "PRESIDIO_PASSWORD_HASH must be a valid Werkzeug scrypt hash "
        "(n>=32768, r>=8, p>=1) or PBKDF2-SHA256/SHA512 hash "
        "(iterations>=600000)."
    )
    try:
        method, salt, digest = password_hash.split("$", 2)
        parts = method.split(":")
        if len(salt) < 16 or not salt.isalnum():
            raise ValueError

        if parts[0] == "scrypt" and len(parts) == 4:
            n, r, p = (int(value) for value in parts[1:])
            if n < 32768 or r < 8 or p < 1:
                raise ValueError
            expected_digest_length = 128
        elif parts[0] == "pbkdf2" and len(parts) == 3:
            algorithm, iterations = parts[1], int(parts[2])
            if algorithm not in {"sha256", "sha512"} or iterations < 600000:
                raise ValueError
            expected_digest_length = 64 if algorithm == "sha256" else 128
        else:
            raise ValueError

        if len(digest) != expected_digest_length or not re.fullmatch(
            r"[0-9a-f]+", digest
        ):
            raise ValueError

        # Exercise Werkzeug's parser once at startup so malformed hashes cannot
        # turn every login attempt into a server error.
        check_password_hash(password_hash, "__configuration_probe__")
    except (TypeError, ValueError):
        raise RuntimeError(error) from None


def load_security_config(env: Mapping[str, str] | None = None) -> SecurityConfig:
    """Load authentication settings without providing insecure defaults."""
    source = os.environ if env is None else env
    session_secret = _required(source, "PRESIDIO_SESSION_SECRET")
    username = _required(source, "PRESIDIO_USERNAME")
    password_hash = _required(source, "PRESIDIO_PASSWORD_HASH")

    if len(session_secret) < 32:
        raise RuntimeError("PRESIDIO_SESSION_SECRET must be at least 32 characters.")
    if len(username) > 128:
        raise RuntimeError("PRESIDIO_USERNAME must be at most 128 characters.")
    _validate_password_hash(password_hash)

    return SecurityConfig(
        session_secret=session_secret,
        username=username,
        password_hash=password_hash,
    )
