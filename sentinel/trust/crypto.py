"""Ed25519 signatures, via pyca/cryptography. The only module that imports it.

Sentinel implements no cryptographic primitive. It uses Ed25519 (RFC 8032) as provided
by an established library for three things: issuers sign fact envelopes, policy signers
sign policy releases, and verifiers hold only public keys. A key is identified by the
SHA-256 fingerprint of its raw public bytes, so a trust-store entry cannot claim another
key's identity.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    """Strict unpadded base64url: anything that does not round-trip is rejected."""
    if not isinstance(text, str) or not text or len(text) > 4096:
        raise ValueError("not a base64url string")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as e:
        raise ValueError(f"not base64url: {e}") from None
    if b64e(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def key_id(public_raw: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:32]


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_raw(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def sign(private: Ed25519PrivateKey, message: bytes) -> bytes:
    return private.sign(message)


def verify(public: bytes, signature: bytes, message: bytes) -> bool:
    if len(public) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def private_pem(private: Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_private_pem(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key
