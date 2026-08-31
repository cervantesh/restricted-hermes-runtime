"""POSIX fail-closed matrix for deployment-protected artifacts."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from restricted_runtime.contracts import ContractError
from restricted_runtime.local_deployment_preflight import _protected_file


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires a root POSIX runner for ownership mutations",
)


def _configure(monkeypatch: pytest.MonkeyPatch, path: Path, digest: str) -> None:
    monkeypatch.setenv("TEST_PROTECTED_PATH", str(path))
    monkeypatch.setenv("TEST_PROTECTED_SHA256", digest)


def _valid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "protected.bin"
    payload = b"SYNTHETIC_NON_PHI_ONLY protected artifact"
    path.write_bytes(payload)
    path.chmod(0o600)
    _configure(monkeypatch, path, hashlib.sha256(payload).hexdigest())
    return path


def _check() -> None:
    _protected_file("TEST_PROTECTED_PATH", "TEST_PROTECTED_SHA256")


def test_valid_protected_artifact_passes(tmp_path, monkeypatch):
    _valid(tmp_path, monkeypatch)
    _check()


def test_missing_artifact_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "missing.bin"
    _configure(monkeypatch, path, hashlib.sha256(b"missing").hexdigest())
    with pytest.raises(ContractError, match="unavailable"):
        _check()


def test_symlink_artifact_fails_closed(tmp_path, monkeypatch):
    target = _valid(tmp_path, monkeypatch)
    link = tmp_path / "protected-link.bin"
    link.symlink_to(target)
    _configure(monkeypatch, link, hashlib.sha256(target.read_bytes()).hexdigest())
    with pytest.raises(ContractError, match="not a regular file"):
        _check()


def test_wrong_owner_artifact_fails_closed(tmp_path, monkeypatch):
    path = _valid(tmp_path, monkeypatch)
    os.chown(path, 1, path.stat().st_gid)
    with pytest.raises(ContractError, match="ownership or mode"):
        _check()


@pytest.mark.parametrize("mode", (0o620, 0o602))
def test_group_or_world_writable_artifact_fails_closed(tmp_path, monkeypatch, mode):
    path = _valid(tmp_path, monkeypatch)
    path.chmod(mode)
    with pytest.raises(ContractError, match="ownership or mode"):
        _check()


def test_digest_mismatch_fails_closed(tmp_path, monkeypatch):
    path = _valid(tmp_path, monkeypatch)
    _configure(monkeypatch, path, "0" * 64)
    with pytest.raises(ContractError, match="digest mismatch"):
        _check()
