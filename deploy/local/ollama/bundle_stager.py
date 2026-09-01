"""Offline copier/verifier for the exact synthetic Ollama bundle.

It is intentionally independent from the serving adapter: staging succeeds
only after both the Windows source and the new external volume verify the same
closed manifest and blob set.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any


MANIFEST_SHA256 = "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
MAIN_BLOB_SHA256 = "2bada8a7450677000f678be90653b85d364de7db25eb5ea54136ada5f3933730"
MANIFEST_RELATIVE = Path("manifests/registry.ollama.ai/library/qwen2.5/7b")
MAX_MANIFEST_BYTES = 1_048_576
MAX_DESCRIPTORS = 16
MAX_BUNDLE_BYTES = 6_000_000_000
CHUNK = 1_048_576


class StageError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StageError("duplicate JSON key")
        result[key] = value
    return result


def _under(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise StageError("path traversal")
    resolved_root = root.resolve(strict=True)
    target = resolved_root / relative
    parent = target.parent
    while not parent.exists():
        parent = parent.parent
    try:
        parent.resolve(strict=True).relative_to(resolved_root)
    except (FileNotFoundError, ValueError) as exc:
        raise StageError("path escapes bundle root") from exc
    return target


def _open_regular(path: Path) -> tuple[int, tuple[int, int, int, int]]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise StageError("non-regular bundle path")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    opened = os.fstat(fd)
    identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    if identity != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
        os.close(fd)
        raise StageError("bundle changed during open")
    return fd, identity


def _read(path: Path, maximum: int) -> tuple[bytes, str, tuple[int, int, int, int]]:
    fd, identity = _open_regular(path)
    try:
        with os.fdopen(fd, "rb") as source:
            raw = source.read(maximum + 1)
    finally:
        # fdopen owns fd on success; this branch only handles a failed fdopen.
        try:
            os.close(fd)
        except OSError:
            pass
    if len(raw) > maximum:
        raise StageError("metadata limit")
    after = path.lstat()
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise StageError("bundle changed during read")
    return raw, hashlib.sha256(raw).hexdigest(), identity


def _descriptor(value: Any) -> tuple[str, int]:
    if not isinstance(value, dict) or set(value) != {"mediaType", "digest", "size"}:
        raise StageError("descriptor shape")
    digest, size = value["digest"], value["size"]
    if not isinstance(value["mediaType"], str) or not isinstance(digest, str) or not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise StageError("descriptor value")
    if not digest.startswith("sha256:") or len(digest) != 71 or any(char not in "0123456789abcdef" for char in digest[7:]):
        raise StageError("descriptor digest")
    return digest[7:], size


def manifest_descriptors(root: Path) -> tuple[bytes, list[tuple[str, int]]]:
    raw, digest, _ = _read(_under(root, MANIFEST_RELATIVE), MAX_MANIFEST_BYTES)
    if digest != MANIFEST_SHA256:
        raise StageError("manifest digest")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, StageError) as exc:
        raise StageError("manifest JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "mediaType", "config", "layers"} or value["schemaVersion"] != 2 or value["mediaType"] != "application/vnd.docker.distribution.manifest.v2+json" or not isinstance(value["layers"], list):
        raise StageError("manifest shape")
    descriptors = [_descriptor(value["config"]), *(_descriptor(layer) for layer in value["layers"])]
    if not 1 <= len(descriptors) <= MAX_DESCRIPTORS or MAIN_BLOB_SHA256 not in {digest for digest, _ in descriptors} or sum(size for _, size in descriptors) > MAX_BUNDLE_BYTES:
        raise StageError("manifest limits")
    return raw, descriptors


def _hash(path: Path, expected_digest: str, expected_size: int) -> None:
    fd, identity = _open_regular(path)
    try:
        with os.fdopen(fd, "rb") as source:
            hasher = hashlib.sha256()
            size = 0
            while chunk := source.read(CHUNK):
                hasher.update(chunk)
                size += len(chunk)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    after = path.lstat()
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != expected_size or hasher.hexdigest() != expected_digest:
        raise StageError("blob verification")


def verify(root: Path) -> tuple[bytes, list[tuple[str, int]]]:
    raw, descriptors = manifest_descriptors(root)
    for digest, size in descriptors:
        _hash(_under(root, Path("blobs") / f"sha256-{digest}"), digest, size)
    # The source/destination manifest itself must remain exact after all blobs.
    final, descriptors_again = manifest_descriptors(root)
    if final != raw or descriptors_again != descriptors:
        raise StageError("manifest changed")
    return raw, descriptors


def _fsync_parent(path: Path) -> None:
    """Persist a rename on Linux; directory descriptors are not portable to NT."""
    try:
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except PermissionError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_exact(source: Path, destination: Path, expected_digest: str, expected_size: int) -> None:
    source_fd, source_identity = _open_regular(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.stage-{uuid.uuid4().hex}")
    target_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(source_fd, "rb") as origin, os.fdopen(target_fd, "wb") as target:
            hasher = hashlib.sha256(); size = 0
            while chunk := origin.read(CHUNK):
                hasher.update(chunk); size += len(chunk); target.write(chunk)
            target.flush(); os.fsync(target.fileno())
    finally:
        for fd in (source_fd, target_fd):
            try: os.close(fd)
            except OSError: pass
    after = source.lstat()
    if source_identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != expected_size or hasher.hexdigest() != expected_digest:
        temporary.unlink(missing_ok=True)
        raise StageError("source changed during copy")
    os.replace(temporary, destination); _fsync_parent(destination)


def _publish_manifest(raw: bytes, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.stage-{uuid.uuid4().hex}")
    try:
        with open(temporary, "xb") as target:
            target.write(raw); target.flush(); os.fsync(target.fileno())
        os.replace(temporary, destination); _fsync_parent(destination)
    finally:
        temporary.unlink(missing_ok=True)


def stage(source: Path, destination: Path) -> None:
    if any(destination.iterdir()):
        raise StageError("destination volume is not empty")
    try:
        manifest, descriptors = verify(source)
        target_manifest = _under(destination, MANIFEST_RELATIVE)
        _publish_manifest(manifest, target_manifest)
        for digest, size in descriptors:
            _copy_exact(_under(source, Path("blobs") / f"sha256-{digest}"), _under(destination, Path("blobs") / f"sha256-{digest}"), digest, size)
        verify(source)
        verify(destination)
    except Exception:
        for partial in destination.rglob(".*.stage-*"):
            partial.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    stage(Path("/source"), Path("/bundle"))
