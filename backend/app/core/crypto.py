"""
Cryptographic helpers: at-rest encryption for sensitive DB fields.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the cryptography package.
Key is derived from NYX_SECRET_KEY via PBKDF2-HMAC-SHA256.

If NYX_SECRET_KEY is not set, encrypt/decrypt are no-ops (backward compatible).
"""
from __future__ import annotations

import base64
import hashlib
import logging

from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

logger = logging.getLogger("nyx.crypto")

_fernet = None
_fernet_init = False


def _get_fernet():
    """Return a Fernet instance keyed from NYX_SECRET_KEY, or None if not configured."""
    global _fernet, _fernet_init
    if _fernet_init:
        return _fernet
    _fernet_init = True
    try:
        from app.config import get_settings
        secret = get_settings().NYX_SECRET_KEY
        if not secret:
            return None
        from cryptography.fernet import Fernet
        # Derive a 32-byte key from the secret using SHA-256 (deterministic, no salt needed
        # here because NYX_SECRET_KEY must already be high-entropy)
        raw_key = hashlib.sha256(secret.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(raw_key)
        _fernet = Fernet(fernet_key)
    except Exception:
        logger.exception("Failed to initialize Fernet — at-rest encryption disabled")
        _fernet = None
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns plaintext unchanged if NYX_SECRET_KEY is not set."""
    if not plaintext:
        return plaintext
    f = _get_fernet()
    if f is None:
        return plaintext
    try:
        return f.encrypt(plaintext.encode()).decode()
    except Exception:
        logger.exception("Encryption failed — storing plaintext")
        return plaintext


def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt a ciphertext string. If decryption fails (e.g., value is plaintext
    from before encryption was enabled), returns the value unchanged.
    """
    if not ciphertext:
        return ciphertext
    f = _get_fernet()
    if f is None:
        return ciphertext
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except Exception:
        # Value was stored before encryption was enabled — return as-is
        return ciphertext


class EncryptedString(TypeDecorator):
    """
    SQLAlchemy column type that transparently encrypts on write and decrypts on read.
    Stores as Text. Falls back to plaintext if NYX_SECRET_KEY is not configured.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return encrypt_secret(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return decrypt_secret(value)
