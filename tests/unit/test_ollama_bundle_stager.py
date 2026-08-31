"""Adversarial checks for the offline exact-bundle staging helper."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ollama_bundle_stager", ROOT / "deploy" / "local" / "ollama" / "bundle_stager.py")
stager = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(stager)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    source = tmp_path / "source"; manifest = source / "manifests/registry.ollama.ai/library/qwen2.5/7b"
    config, main = b"config", b"main"
    descriptors = [{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:" + _digest(config), "size": len(config)}, {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:" + _digest(main), "size": len(main)}]
    for raw in (config, main):
        target = source / "blobs" / ("sha256-" + _digest(raw)); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
    raw_manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": descriptors[0], "layers": descriptors[1:]}, separators=(",", ":")).encode()
    manifest.parent.mkdir(parents=True, exist_ok=True); manifest.write_bytes(raw_manifest)
    monkeypatch.setattr(stager, "MANIFEST_SHA256", _digest(raw_manifest)); monkeypatch.setattr(stager, "MAIN_BLOB_SHA256", _digest(main))
    return source


def test_stage_copies_only_verified_manifest_and_referenced_blobs(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch); destination = tmp_path / "bundle"; destination.mkdir()
    (source / "unreferenced").write_bytes(b"must not copy")
    stager.stage(source, destination)
    assert stager.verify(destination)
    assert not (destination / "unreferenced").exists()
    assert sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()) == sorted(["manifests/registry.ollama.ai/library/qwen2.5/7b", *("blobs/" + path.name for path in (source / "blobs").iterdir())])


def test_stage_rejects_nonempty_destination_and_source_drift(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch); destination = tmp_path / "bundle"; destination.mkdir(); (destination / "foreign").write_text("x")
    with pytest.raises(stager.StageError):
        stager.stage(source, destination)
    (destination / "foreign").unlink()
    next((source / "blobs").iterdir()).write_bytes(b"drift")
    with pytest.raises(stager.StageError):
        stager.stage(source, destination)


def test_stage_rejects_manifest_traversal_and_descriptor_limits(tmp_path, monkeypatch):
    source = _source(tmp_path, monkeypatch)
    with pytest.raises(stager.StageError):
        stager._under(source, Path("../outside"))
    monkeypatch.setattr(stager, "MAX_DESCRIPTORS", 1)
    with pytest.raises(stager.StageError):
        stager.verify(source)
