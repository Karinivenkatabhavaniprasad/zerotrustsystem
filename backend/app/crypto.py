"""Cryptographic primitives for Zero Trust identity, MFA, tokens, and hash-chained auditing.

Uses Python standard library (`hashlib`, `hmac`, `secrets`, `base64`, `struct`) to avoid
fragile third-party dependency assumptions while preserving strong cryptographic guarantees:
- PBKDF2-HMAC-SHA256 password hashing with per-user 16-byte random salt
- RFC 6238 TOTP (HMAC-SHA1) verification and generation
- HMAC-SHA256 signed compact JWT-compatible tokens with jti, exp, iat, and scope claims
- SHA-256 tamper-evident hash chain calculation
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hash_password(password: str, salt: str | None = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 200_000)
    return f"pbkdf2_sha256$200000${salt_bytes.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2-HMAC-SHA256 hash."""
    try:
        scheme, iter_str, salt_hex, hash_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations
        )
        return hmac.compare_digest(derived.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def generate_totp_secret() -> str:
    """Generate a Base32-encoded 160-bit TOTP secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def compute_totp(secret: str, for_time: int | None = None, step: int = 30, digits: int = 6) -> str:
    """Compute an RFC 6238 TOTP code for the given Base32 secret and timestamp."""
    counter = int((for_time if for_time is not None else time.time()) // step)
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def verify_totp(
    secret: str,
    code: str,
    *,
    for_time: int | None = None,
    step: int = 30,
    digits: int = 6,
    window: int = 1,
) -> bool:
    """Verify a TOTP code within +/- `window` time steps using constant-time comparison."""
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != digits:
        return False
    now = int(for_time if for_time is not None else time.time())
    for delta in range(-window, window + 1):
        candidate = compute_totp(secret, for_time=now + delta * step, step=step, digits=digits)
        if hmac.compare_digest(cleaned, candidate):
            return True
    return False


def sign_token(payload: dict[str, Any], secret: str, ttl_seconds: int) -> str:
    """Create a short-lived HMAC-SHA256 signed JWT token."""
    now = int(time.time())
    claims = {
        **payload,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": payload.get("jti") or secrets.token_hex(16),
    }
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def verify_token(token: str, secret: str) -> dict[str, Any] | None:
    """Verify signature and expiration of an HMAC-SHA256 JWT token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != "HS256":
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        if int(claims.get("exp", 0)) <= int(time.time()):
            return None
        return claims
    except Exception:
        return None


def compute_audit_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """Compute SHA-256 link hash for tamper-evident audit logging."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    material = f"{prev_hash}|{canonical}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()
