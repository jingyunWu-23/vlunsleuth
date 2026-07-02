from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Tuple


PASSWORD_ITERATIONS = 260_000
SESSION_DAYS = 7


def hash_password(password: str, salt: str | None = None, iterations: int = PASSWORD_ITERATIONS) -> Tuple[str, str, int]:
    salt_value = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_value.encode("utf-8"), iterations)
    return digest.hex(), salt_value, iterations


def verify_password(password: str, password_hash: str, salt: str, iterations: int) -> bool:
    candidate, _, _ = hash_password(password, salt=salt, iterations=iterations)
    return hmac.compare_digest(candidate, password_hash)


def new_access_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_expires_at() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
