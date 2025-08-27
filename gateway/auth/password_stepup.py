"""
Password-based step-up (demo-only, in-memory).

This module provides a minimal password step-up flow:
- set_password(sub, password): Register or update a user's password (salted PBKDF2-SHA256).
- new_challenge(sub): Start a time-bound challenge for the user; returns a nonce and prompt.
- verify_assertion(nonce, password): Verify the password for the pending challenge.

Notes:
- All data is stored in process memory for demo purposes only.
- In production, store password hashes in a proper database and use a mature library
  (e.g., argon2, scrypt, or bcrypt via passlib/argon2-cffi) and enforce robust policies.
"""
from __future__ import annotations

import os
import time
import hmac
import base64
import hashlib
import json
from typing import Dict, Any

# Optional pepper (if set, appended to password before hashing). Do not hardcode in source.
_PEPPER = os.getenv("PASSWORD_PEPPER", "")

# In-memory credential store: sub -> {"salt": b64url, "hash": b64url, "algo": str, "iter": int}
_creds: Dict[str, Dict[str, Any]] = {}

# Pending challenges: nonce -> {"sub": str, "exp": int, "attempts": int}
_pending: Dict[str, Dict[str, Any]] = {}

# Configuration
_ITERATIONS = 200_000
_TTL_SECONDS = 180  # 3 minutes
_MAX_ATTEMPTS = 5
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "password_store.json")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(data: str) -> bytes:
    # add padding back if removed
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _hash_password(password: str, salt: bytes, iterations: int = _ITERATIONS) -> bytes:
    # PBKDF2-HMAC-SHA256
    pwd = (password + _PEPPER).encode()
    return hashlib.pbkdf2_hmac("sha256", pwd, salt, iterations)


def _save_creds():
    with open(CONFIG_PATH, "w") as f:
        json.dump(_creds, f, indent=2, sort_keys=True)


def _load_creds():
    global _creds
    try:
        with open(CONFIG_PATH, "r") as f:
            _creds = json.load(f)
    except Exception:
        _creds = {}


_load_creds()


def set_password(sub: str, password: str) -> None:
    """Create or update a user's password.
    Stores salted PBKDF2-SHA256 hash with iterations in memory.
    """
    if not sub:
        raise ValueError("sub is required")
    if not isinstance(password, str) or len(password) < 8:
        # Demo policy: at least 8 chars. Adjust as needed.
        raise ValueError("password must be a string of at least 8 characters")
    salt = os.urandom(16)
    digest = _hash_password(password, salt, _ITERATIONS)
    _creds[sub] = {
        "salt": _b64url(salt),
        "hash": _b64url(digest),
        "algo": "pbkdf2_sha256",
        "iter": _ITERATIONS,
    }
    _save_creds()


def has_password(sub: str) -> bool:
    return sub in _creds


def check_password(sub: str, password: str) -> bool:
    entry = _creds.get(sub)
    if not entry:
        return False
    salt = _b64url_decode(entry["salt"])
    iters = int(entry.get("iter", _ITERATIONS))
    expected = _b64url_decode(entry["hash"])
    actual = _hash_password(password, salt, iters)
    return hmac.compare_digest(expected, actual)


def new_challenge(sub: str) -> Dict[str, Any]:
    """Start a new step-up challenge for a user.
    Returns a dict with a `nonce` and `prompt`.
    """
    if not has_password(sub):
        # For demo flows, caller can decide to prompt user to set a password first.
        raise ValueError("no_password_registered")
    nonce = _b64url(os.urandom(24))
    _pending[nonce] = {
        "sub": sub,
        "exp": int(time.time()) + _TTL_SECONDS,
        "attempts": 0,
    }
    return {
        "nonce": nonce,
        "prompt": f"Enter password for {sub}",
        "expires_in": _TTL_SECONDS,
    }


def verify_assertion(nonce: str, password: str) -> bool:
    entry = _pending.get(nonce)
    if not entry:
        return False
    now = int(time.time())
    if now > entry["exp"]:
        _pending.pop(nonce, None)
        return False
    if entry["attempts"] >= _MAX_ATTEMPTS:
        _pending.pop(nonce, None)
        return False

    ok = check_password(entry["sub"], password)
    entry["attempts"] += 1
    if ok:
        _pending.pop(nonce, None)
        return True
    # Optionally lock out after too many attempts
    if entry["attempts"] >= _MAX_ATTEMPTS:
        _pending.pop(nonce, None)
    return False


def clear_user(sub: str) -> None:
    """Remove a user's stored password (demo helper)."""
    _creds.pop(sub, None)


__all__ = [
    "set_password",
    "has_password",
    "check_password",
    "new_challenge",
    "verify_assertion",
    "clear_user",
]
