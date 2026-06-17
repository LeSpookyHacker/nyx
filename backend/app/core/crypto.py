"""
Cryptographic helpers: at-rest encryption for sensitive DB fields.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the cryptography package.
Key is derived from NYX_SECRET_KEY via HKDF-SHA256 (SEC-006).

Versioned token format
----------------------
v2:<base64url-fernet-token>   — HKDF-derived key (current, written by encrypt_secret)
<bare-fernet-token>           — legacy SHA-256-derived key (read-only, backward compat)
<plaintext>                   — values stored before encryption was enabled (read-only)

The "v2:" prefix is unambiguous: Fernet tokens always start with "gAAAAA…"
(the 0x80 version byte base64url-encoded), which cannot collide with "v2:".

If NYX_SECRET_KEY is not set, encrypt/decrypt are no-ops (backward compatible).
"""
from __future__ import annotations

import base64
import hashlib
import logging

from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

logger = logging.getLogger("nyx.crypto")

# Versioned prefix written by the current encryption path.
_V2_PREFIX = "v2:"

# Domain-separating constants for HKDF — changing these invalidates all v2 tokens.
_HKDF_SALT = b"nyx-at-rest-kdf-v1"
_HKDF_INFO = b"nyx-fernet-key"

_fernet_v2 = None   # HKDF-derived key  (for new writes and v2 reads)
_fernet_v1 = None   # SHA-256-derived key (legacy reads only)
_fernet_init = False


def _derive_key_v2(secret: str) -> bytes:
    """
    Derive a 32-byte Fernet key from NYX_SECRET_KEY using HKDF-SHA256 (SEC-006).

    HKDF (RFC 5869) is the NIST-recommended KDF for extracting/expanding
    key material from already-high-entropy inputs.  It provides domain
    separation via the salt and info parameters, preventing key reuse across
    different applications or contexts.  SHA-256 direct hashing (the old v1
    approach) provided no such separation and no future-proofing.

    Because NYX_SECRET_KEY must already be high-entropy (enforced at startup),
    the HKDF extract step provides domain separation rather than password
    stretching; iteration count is not applicable here.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    return hkdf.derive(secret.encode())


def _derive_key_v1(secret: str) -> bytes:
    """Legacy SHA-256 key derivation — used only for decrypting old tokens."""
    return hashlib.sha256(secret.encode()).digest()


def _init_fernets(secret: str) -> None:
    """Initialize both Fernet instances from the given secret."""
    global _fernet_v2, _fernet_v1
    from cryptography.fernet import Fernet
    _fernet_v2 = Fernet(base64.urlsafe_b64encode(_derive_key_v2(secret)))
    _fernet_v1 = Fernet(base64.urlsafe_b64encode(_derive_key_v1(secret)))


def _get_fernets():
    """Return (fernet_v2, fernet_v1) or (None, None) if not configured."""
    global _fernet_v2, _fernet_v1, _fernet_init
    if _fernet_init:
        return _fernet_v2, _fernet_v1
    _fernet_init = True
    try:
        from app.config import get_settings
        secret = get_settings().NYX_SECRET_KEY
        if not secret:
            return None, None
        _init_fernets(secret)
    except Exception:
        logger.exception("Failed to initialize Fernet — at-rest encryption disabled")
        _fernet_v2, _fernet_v1 = None, None
    return _fernet_v2, _fernet_v1


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt a plaintext string using the v2 (HKDF) key.
    Returns plaintext unchanged if NYX_SECRET_KEY is not set.
    Tokens are prefixed with 'v2:' to distinguish them from legacy tokens.
    """
    if not plaintext:
        return plaintext
    fernet_v2, _ = _get_fernets()
    if fernet_v2 is None:
        return plaintext
    try:
        return _V2_PREFIX + fernet_v2.encrypt(plaintext.encode()).decode()
    except Exception:
        logger.exception("Encryption failed — storing plaintext")
        return plaintext


def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt a ciphertext string.

    Dispatch:
    - "v2:<token>" → decrypt with HKDF-derived key
    - "<bare-fernet-token>" → decrypt with legacy SHA-256 key (backward compat)
    - Anything else → return as-is (plaintext from before encryption was enabled)
    """
    if not ciphertext:
        return ciphertext
    fernet_v2, fernet_v1 = _get_fernets()
    if fernet_v2 is None:
        return ciphertext

    if ciphertext.startswith(_V2_PREFIX):
        # Current format — use HKDF key
        try:
            return fernet_v2.decrypt(ciphertext[len(_V2_PREFIX):].encode()).decode()
        except Exception:
            logger.warning("v2 token decryption failed — returning ciphertext as-is")
            return ciphertext

    # Legacy format — try the v1 (SHA-256) key for backward compatibility
    if fernet_v1 is not None:
        try:
            return fernet_v1.decrypt(ciphertext.encode()).decode()
        except Exception:
            pass  # not a v1 Fernet token — treat as plaintext

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
