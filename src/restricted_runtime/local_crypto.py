"""Fail-closed POSIX file-backed adapters for the self-hosted profile."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .contracts import ContractError, jcs_bytes, load_closed_json
from .crypto import MacRecord

_ROOT = PurePosixPath("/run/restricted-keys")
_ENVELOPE = "restricted-local-wrapped-data-key.v1"


@dataclass(frozen=True)
class LocalKeyRef:
    key_resource: str
    key_version: str
    path: str

    def __post_init__(self) -> None:
        value = PurePosixPath(self.path)
        if not self.key_resource or not self.key_version or str(value) != self.path or not value.is_absolute() or value.parent != _ROOT:
            raise ContractError("local key reference is outside the closed key directory")


def _read(ref: LocalKeyRef) -> bytes:
    path = Path(ref.path)
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ContractError("local key is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(opened.st_mode):
                raise ContractError("local key inode changed during open")
            if opened.st_uid not in {0, os.geteuid()} or opened.st_mode & 0o077:
                raise ContractError("local key ownership or mode rejected")
            data = os.read(descriptor, 33)
            if len(data) != 32 or os.read(descriptor, 1):
                raise ContractError("local key must be exactly 32 bytes")
            return data
        finally:
            os.close(descriptor)
    except ContractError:
        raise
    except OSError as exc:
        raise ContractError("local key is unavailable") from exc


def _refs(active: LocalKeyRef, retired: tuple[LocalKeyRef, ...]) -> dict[tuple[str, str], LocalKeyRef]:
    refs = (active, *retired)
    indexed = {(ref.key_resource, ref.key_version): ref for ref in refs}
    if len(indexed) != len(refs):
        raise ContractError("duplicate local key identifier")
    return indexed


def load_retired_key_refs(path: str) -> tuple[LocalKeyRef, ...]:
    """Read only key metadata from a protected local file; never key bytes."""
    metadata = LocalKeyRef("retired-manifest", "v1", path)
    try:
        target = Path(metadata.path); before = target.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o077:
            raise ValueError
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino): raise ValueError
            raw = os.read(descriptor, 8193)
        finally: os.close(descriptor)
        if len(raw) > 8192: raise ValueError
        value = load_closed_json(raw)
        if not isinstance(value, list): raise ValueError
        refs = tuple(LocalKeyRef(item["key_resource"], item["key_version"], item["path"]) for item in value if isinstance(item, dict) and set(item) == {"key_resource", "key_version", "path"})
        if len(refs) != len(value): raise ValueError
        return refs
    except Exception as exc:
        raise ContractError("retired local key manifest rejected") from exc


class LocalFileHmacKey:
    def __init__(self, active: LocalKeyRef, retired: tuple[LocalKeyRef, ...] = ()):
        self.active, self._refs = active, _refs(active, retired)
        self.key_resource, self.key_version = active.key_resource, active.key_version
        _read(active)
        for ref in retired: _read(ref)
    def sign(self, data: bytes) -> MacRecord:
        return MacRecord(self.key_resource, self.key_version, hmac.digest(_read(self.active), data, "sha256"))
    def verify(self, record: MacRecord, data: bytes) -> bool:
        ref = self._refs.get((record.key_resource, record.key_version))
        return bool(ref) and hmac.compare_digest(record.mac, hmac.digest(_read(ref), data, "sha256"))


class LocalAesDataKeyWrapper:
    def __init__(self, active: LocalKeyRef, retired: tuple[LocalKeyRef, ...] = ()):
        self.active, self._refs = active, _refs(active, retired)
        _read(active)
        for ref in retired: _read(ref)
    @staticmethod
    def _aad(ref: LocalKeyRef) -> bytes:
        return jcs_bytes({"schema_version": _ENVELOPE, "key_resource": ref.key_resource, "key_version": ref.key_version})
    def wrap(self, data_key: bytes) -> bytes:
        if len(data_key) != 32: raise ContractError("local data key must be 32 bytes")
        nonce = os.urandom(12); ref = self.active
        cipher = AESGCM(_read(ref)).encrypt(nonce, data_key, self._aad(ref))
        return jcs_bytes({"schema_version":_ENVELOPE,"key_resource":ref.key_resource,"key_version":ref.key_version,"nonce":base64.b64encode(nonce).decode("ascii"),"ciphertext":base64.b64encode(cipher).decode("ascii")})
    def unwrap(self, wrapped: bytes) -> bytes:
        try:
            value = load_closed_json(wrapped)
            if not isinstance(value, dict) or set(value) != {"schema_version","key_resource","key_version","nonce","ciphertext"} or value["schema_version"] != _ENVELOPE:
                raise ValueError
            ref = self._refs[(value["key_resource"], value["key_version"])]
            nonce = base64.b64decode(value["nonce"], validate=True); cipher = base64.b64decode(value["ciphertext"], validate=True)
            if len(nonce) != 12: raise ValueError
            plain = AESGCM(_read(ref)).decrypt(nonce, cipher, self._aad(ref))
            if len(plain) != 32: raise ValueError
            return plain
        except Exception as exc:
            raise ContractError("local wrapped data key rejected") from exc
