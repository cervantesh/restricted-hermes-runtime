#!/usr/bin/env python3
"""Export a canonical, content-safe clinical assessment bundle from allowlisted inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from typing import Any

from verify_assessment_bundle import (
    MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, PROFILE_FILES, README_CONTENT, SAFE_FILE, SCHEMA, SCOPE,
    _secret_bearing, _safe_relative, canonical_json, verify,
)


HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "verify_assessment_bundle.py"
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _is_reparse_point(stat_result: object) -> bool:
    """Windows junctions are links too, even though S_ISLNK is false."""
    return bool(getattr(stat_result, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _die(message: str) -> None:
    raise SystemExit("assessment bundle export: " + message)


def _load(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            _die("declaration file limit exceeded")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _die(f"unreadable declaration: {exc}")
    if not isinstance(value, dict):
        _die("declaration must be an object")
    return value


def _read_regular(source: Path, context: str, *, root: Path | None = None) -> bytes:
    """Read one regular file without following an untrusted input path."""
    relative: Path | None = None
    if root is not None:
        try:
            relative = source.relative_to(root)
        except ValueError:
            _die(f"{context}: path escapes input root")
        cursor = root
        for part in relative.parts[:-1]:
            cursor /= part
            try:
                mode = cursor.lstat().st_mode
            except OSError as exc:
                _die(f"{context}: ancestor unavailable: {exc}")
            if stat.S_ISLNK(mode) or _is_reparse_point(cursor.lstat()) or not stat.S_ISDIR(mode):
                _die(f"{context}: symlinked or invalid ancestor is forbidden")
    try:
        mode = source.lstat().st_mode
    except OSError as exc:
        _die(f"{context}: unavailable: {exc}")
    if stat.S_ISLNK(mode) or _is_reparse_point(source.lstat()) or not stat.S_ISREG(mode):
        _die(f"{context}: regular non-symlink file required")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
    try:
        if root is not None and relative is not None and os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY"):
            directory = os.open(root, directory_flags)
            try:
                for part in relative.parts[:-1]:
                    next_directory = os.open(part, directory_flags, dir_fd=directory)
                    os.close(directory)
                    directory = next_directory
                descriptor = os.open(relative.name, flags, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            descriptor = os.open(source, flags)
    except OSError as exc:
        _die(f"{context}: unreadable or symlinked: {exc}")
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            _die(f"{context}: regular file required")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                _die(f"{context}: file limit exceeded")
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if _secret_bearing(raw):
        _die(f"{context}: secret-bearing content is forbidden")
    return raw


def _copy_regular(source: Path, destination: Path, context: str, *, root: Path | None = None) -> bytes:
    raw = _read_regular(source, context, root=root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return raw


def _media_type(relative: str) -> str:
    if relative.endswith(".json"):
        return "application/json"
    if relative.endswith(".md"):
        return "text/markdown"
    if relative.endswith(".py"):
        return "text/x-python"
    _die(f"{relative}: unsupported media type")


def _input_path(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    return candidate


def _declared_files(declaration: dict[str, Any]) -> list[str]:
    files = declaration.get("files")
    if not isinstance(files, list) or not files:
        _die("declaration files must be a non-empty list")
    paths: list[str] = []
    for item in files:
        relative = _safe_relative(item)
        if relative is None or not SAFE_FILE.fullmatch(relative):
            _die("declaration files must use the closed content allowlist")
        paths.append(relative)
    if paths != sorted(paths) or len(set(paths)) != len(paths) or set(paths) != PROFILE_FILES or len(paths) + 2 > MAX_FILES:
        _die("declaration files must be uniquely sorted and bounded")
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--declaration", type=Path, required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        _die("output directory must not already exist")
    declaration = _load(args.declaration)
    input_root = args.input_dir.absolute()
    try:
        root_mode = input_root.lstat().st_mode
    except OSError as exc:
        _die(f"input directory unavailable: {exc}")
    if stat.S_ISLNK(root_mode) or _is_reparse_point(input_root.lstat()) or not stat.S_ISDIR(root_mode):
        _die("input directory must be a real directory")
    paths = _declared_files(declaration)
    temporary = Path(tempfile.mkdtemp(prefix="assessment-bundle-", dir=args.output_dir.parent))
    try:
        records: list[dict[str, object]] = []
        for relative, source in (("README.md", None), ("verify_assessment_bundle.py", VERIFIER)):
            raw = README_CONTENT.encode("ascii") if source is None else _copy_regular(source, temporary / relative, relative)
            if source is None:
                (temporary / relative).write_bytes(raw)
            records.append({"path": relative, "size": len(raw), "media_type": _media_type(relative), "sha256": hashlib.sha256(raw).hexdigest()})
        for relative in paths:
            raw = _copy_regular(_input_path(input_root, relative), temporary / relative, relative, root=input_root)
            records.append({"path": relative, "size": len(raw), "media_type": _media_type(relative), "sha256": hashlib.sha256(raw).hexdigest()})
        if sum(int(record["size"]) for record in records) > MAX_TOTAL_BYTES:
            _die("total content limit exceeded")
        payload = {key: value for key, value in declaration.items() if key != "files"}
        payload.update({"schema_version": SCHEMA, "scope": SCOPE, "files": sorted(records, key=lambda record: str(record["path"]))})
        payload["candidate_id"] = "sha256:" + hashlib.sha256(canonical_json({key: value for key, value in payload.items() if key != "candidate_id"})).hexdigest()
        raw_manifest = canonical_json(payload)
        if len(raw_manifest) > MAX_FILE_BYTES or len(raw_manifest) + sum(int(record["size"]) for record in records) > MAX_TOTAL_BYTES:
            _die("manifest or total content limit exceeded")
        if _secret_bearing(raw_manifest):
            _die("manifest: secret-bearing content is forbidden")
        (temporary / "assessment.manifest.json").write_bytes(raw_manifest)
        expected = hashlib.sha256(raw_manifest).hexdigest()
        result = verify(temporary, expected_manifest_sha256=expected)
        if result.errors:
            _die("invalid declaration: " + "; ".join(result.errors))
        temporary.replace(args.output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print("assessment bundle export: PASS manifest_sha256=" + expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
