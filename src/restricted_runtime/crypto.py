"""KMS-shaped MAC and content encryption interfaces; no plaintext persistence."""
from __future__ import annotations

import hashlib
import hmac
import os
import threading
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .contracts import ContractError

SERVICE_MAC_DOMAIN = "restricted-service-idempotency.v1"
GATEWAY_MAC_DOMAIN = "restricted-gateway-envelope.v1"


def kms_mac_input(domain: str, canonical: bytes) -> bytes:
    if not domain.isascii() or "\x00" in domain:
        raise ContractError("invalid MAC domain")
    return domain.encode("ascii") + b"\x00" + len(canonical).to_bytes(8, "big") + hashlib.sha256(canonical).digest()


@dataclass(frozen=True)
class MacRecord:
    key_resource: str
    key_version: str
    mac: bytes


class MacKey(Protocol):
    key_resource: str
    key_version: str
    def sign(self, data: bytes) -> MacRecord: ...
    def verify(self, record: MacRecord, data: bytes) -> bool: ...


class LocalHmacKey:
    """Synthetic test adapter; production adapter calls KMS MAC sign/verify."""
    def __init__(self, resource: str, version: str, secret: bytes, *, can_sign: bool = True):
        self.key_resource, self.key_version, self._secret, self._can_sign = resource, version, secret, can_sign
    def sign(self, data: bytes) -> MacRecord:
        if not self._can_sign:
            raise PermissionError("retired MAC key is verify-only")
        return MacRecord(self.key_resource, self.key_version, hmac.digest(self._secret, data, "sha256"))
    def verify(self, record: MacRecord, data: bytes) -> bool:
        return record.key_resource == self.key_resource and record.key_version == self.key_version and hmac.compare_digest(record.mac, hmac.digest(self._secret, data, "sha256"))


@dataclass(frozen=True)
class Ciphertext:
    nonce: bytes
    ciphertext: bytes


_nonce_lock = threading.Lock()
_seen_nonces: dict[bytes, set[bytes]] = {}


def encrypt(data_key: bytes, plaintext: bytes, aad: bytes) -> Ciphertext:
    if len(data_key) != 32:
        raise ContractError("AES-256 requires a 256-bit data key")
    key_id = hashlib.sha256(data_key).digest()
    with _nonce_lock:
        used = _seen_nonces.setdefault(key_id, set())
        nonce = None
        for _ in range(4):
            candidate = os.urandom(12)
            if candidate not in used:
                used.add(candidate)
                nonce = candidate
                break
        if nonce is None:
            raise ContractError("content nonce reuse detected")
    return Ciphertext(nonce, AESGCM(data_key).encrypt(nonce, plaintext, aad))


def decrypt(data_key: bytes, record: Ciphertext, aad: bytes) -> bytes:
    if len(data_key) != 32 or len(record.nonce) != 12:
        raise ContractError("invalid content encryption metadata")
    try:
        return AESGCM(data_key).decrypt(record.nonce, record.ciphertext, aad)
    except Exception as exc:
        raise ContractError("content integrity failure") from exc
