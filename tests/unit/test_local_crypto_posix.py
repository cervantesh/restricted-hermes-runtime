"""POSIX-only local key-file rotation and tamper matrix."""
import os
from pathlib import Path
import pytest

from restricted_runtime.contracts import ContractError
from restricted_runtime.local_crypto import LocalAesDataKeyWrapper, LocalFileHmacKey, LocalKeyRef

pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires POSIX protected /run key files")


def _key(path: str, resource: str, version: str) -> LocalKeyRef:
    target = Path(path); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(bytes(range(32))); target.chmod(0o600)
    return LocalKeyRef(resource, version, path)


def test_local_keys_rotate_verify_unwrap_and_reject_tamper_or_duplicates():
    root = Path("/run/restricted-keys"); root.mkdir(parents=True, exist_ok=True)
    active, retired = _key(str(root / "active.bin"), "content", "v2"), _key(str(root / "retired.bin"), "content", "v1")
    try:
        mac = LocalFileHmacKey(active, (retired,)); record = mac.sign(b"input")
        assert mac.verify(record, b"input") and not mac.verify(record, b"other")
        wrapper = LocalAesDataKeyWrapper(active, (retired,)); wrapped = wrapper.wrap(b"d" * 32)
        assert wrapper.unwrap(wrapped) == b"d" * 32
        with pytest.raises(ContractError): wrapper.unwrap(wrapped[:-1] + b"x")
        with pytest.raises(ContractError): LocalFileHmacKey(active, (active,))
        (root / "bad.bin").write_bytes(b"x"); (root / "bad.bin").chmod(0o600)
        with pytest.raises(ContractError): LocalFileHmacKey(LocalKeyRef("bad", "v1", str(root / "bad.bin")))
        (root / "link.bin").symlink_to(root / "active.bin")
        with pytest.raises(ContractError): LocalFileHmacKey(LocalKeyRef("link", "v1", str(root / "link.bin")))
    finally:
        for item in root.glob("*.bin"): item.unlink(missing_ok=True)
