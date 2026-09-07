#!/usr/bin/env python3
"""Synthetic-only operator lifecycle for the composed clinical witness."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import posixpath
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


RUNTIME_BASE_SHA = "41464aee8748f857153ba2b47377515d4847d210"
REQUIRED_HRH_SHA = "ad13735e9881a48580a9e138daac137f8c865dea"
REQUIRED_HRH_TREE = "f217b0b1cf7f438422528dfe178d81b78212c68b"
SCHEMA = "restricted-synthetic-clinical-staging.v1"
MARKER_NAME = "staging-state.json"
PROJECT_LABEL = "io.cervantesh.restricted-runtime.project"
STATE_LABEL = "io.cervantesh.restricted-runtime.state-id"
SYNTHETIC_LABEL = "io.cervantesh.restricted-runtime.synthetic-clinical"
PROJECT_RE = re.compile(r"^clinicalstaging[a-z0-9]{1,32}$")
VOLUME_KEYS = (
    "mattermost_db", "mattermost_data", "mattermost_tls", "hrh_db",
    "hrh_tls", "hrh_secret", "clinical_config", "clinical_socket",
    "ingress_config", "ingress_outbox", "controller_state",
)
EXCLUDED_RECOVERY_VOLUME = "clinical_socket"
BACKED_UP_VOLUME_KEYS = tuple(key for key in VOLUME_KEYS if key != EXCLUDED_RECOVERY_VOLUME)
BACKUP_SCHEMA = "restricted-synthetic-clinical-cold-backup.v1"
BACKUP_MANIFEST_NAME = "backup-manifest.json"
BACKUP_COMPLETE_NAME = "COMPLETE"
BACKUP_STATE_ARCHIVE = "state.tar"
BACKUP_VOLUME_DIR = "volumes"
# This is also the pinned PostgreSQL image used by the composed witness. It
# supplies GNU tar inside a networkless, ephemeral helper for volume exports.
RECOVERY_HELPER_IMAGE = (
    "postgres:17.10-bookworm@sha256:"
    "9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f"
)
LONG_RUNNING_SERVICES = (
    "mattermost-postgres", "mattermost", "hrh-postgres", "hrh", "hrh-tls",
    "clinical-adapter", "ingress", "operator-proxy",
)
ONE_SHOT_SERVICES = ("hrh-migrate", "clinical-socket-init")
ALLOWED_SERVICES = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES) | {"controller"}
INTERNAL_NETWORK_KEYS = ("mattermost_edge", "mattermost_backend", "hrh_backend", "clinical_upstream")
NETWORK_KEYS = (*INTERNAL_NETWORK_KEYS, "operator_access")
EXPECTED_NETWORK_KEYS_BY_SERVICE = {
    "mattermost-postgres": {"mattermost_backend"},
    "mattermost": {"mattermost_edge", "mattermost_backend"},
    "hrh-postgres": {"hrh_backend"},
    "hrh": {"hrh_backend"},
    "hrh-tls": {"hrh_backend", "clinical_upstream"},
    "clinical-adapter": {"clinical_upstream"},
    "ingress": {"mattermost_edge"},
    "operator-proxy": {"operator_access", "mattermost_edge"},
}
RESTRICTED_CONTAINER_CONTROLS = {
    "clinical-adapter": {
        "user": "restricted-clinical-adapter",
        "uid": 10008,
        "gid": 20007,
        "read_only_mounts": {"/run/clinical-config", "/run/hrh-secret", "/run/hrh-tls"},
        "writable_mounts": {"/run/restricted-clinical"},
    },
    "ingress": {
        "user": "restricted-mattermost-ingress",
        "uid": 10007,
        "gid": 20005,
        "read_only_mounts": {"/run/ingress"},
        "writable_mounts": {
            "/run/restricted-clinical",
            "/var/lib/restricted-mattermost-outbox",
        },
    },
}


class SafetyError(RuntimeError):
    pass


class CommandError(RuntimeError):
    pass


class Shell:
    def run(
        self,
        *args: str,
        cwd: Path | None = None,
        check: bool = True,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        if check and result.returncode:
            detail = (result.stdout + result.stderr)[-1600:]
            raise CommandError(f"{args[0]} exited {result.returncode}: {detail}")
        return result

    def git(self, cwd: Path, *args: str) -> str:
        return self.run("git", *args, cwd=cwd).stdout.strip()


def validate_project(project: str) -> str:
    if not PROJECT_RE.fullmatch(project) or project == "clinicalstaging":
        raise SafetyError("project must match clinicalstaging[a-z0-9]{1,32}")
    return project


def validate_state_path(
    path: Path,
    project: str,
    *,
    forbidden_roots: Iterable[Path] = (),
) -> Path:
    validate_project(project)
    if not path.is_absolute():
        raise SafetyError("state path must be absolute")
    resolved = path.resolve()
    if resolved.name != f"{project}.synthetic-clinical-staging":
        raise SafetyError("state path basename must bind the exact project")
    repo = Path(__file__).resolve().parents[2]
    home = Path.home().resolve()
    if resolved in {resolved.anchor and Path(resolved.anchor), repo, home}:
        raise SafetyError("state path is too broad")
    for root in (repo, *(Path(item).resolve() for item in forbidden_roots)):
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise SafetyError("state path must remain outside every repository build context")
    return resolved


def validate_backup_path(
    path: Path,
    *,
    state_dir: Path,
    forbidden_roots: Iterable[Path] = (),
) -> Path:
    """A backup is a new sibling-owned directory, never build or live state input."""
    if not path.is_absolute():
        raise SafetyError("backup path must be absolute")
    resolved = path.resolve()
    if resolved.name in {"", ".", resolved.anchor} or resolved == state_dir.resolve():
        raise SafetyError("backup path is too broad or conflicts with staging state")
    for root in (state_dir, *(Path(item).resolve() for item in forbidden_roots)):
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise SafetyError("backup path must remain outside state and repository build contexts")
    return resolved


def volume_names(project: str) -> dict[str, str]:
    validate_project(project)
    return {key: f"{project}_{key}" for key in VOLUME_KEYS}


def new_marker(
    *,
    project: str,
    state_dir: Path,
    state_id: str,
    env_sha256: str,
    runtime_head: str,
    runtime_tree: str,
    hrh_head: str,
    hrh_tree: str,
    lifecycle: str = "initializing",
    expected_images: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    validate_state_path(state_dir, project)
    return {
        "schema": SCHEMA,
        "synthetic_only": True,
        "project": project,
        "state_dir": str(state_dir.resolve()),
        "state_id": state_id,
        "compose_env_sha256": env_sha256,
        "lifecycle": lifecycle,
        "runtime_head": runtime_head,
        "runtime_tree": runtime_tree,
        "hrh_head": hrh_head,
        "hrh_tree": hrh_tree,
        "volumes": volume_names(project),
        "expected_images": dict(expected_images or {}),
    }


def fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json_atomic(path: Path, value: Mapping[str, Any], *, mode: int) -> None:
    tmp = path.with_name(path.name + ".tmp")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fsync_directory(path.parent)
    finally:
        if tmp.exists():
            tmp.unlink()


def read_marker(state_dir: Path, project: str) -> dict[str, Any]:
    state_dir = validate_state_path(state_dir, project)
    path = state_dir / MARKER_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("closed staging marker is missing or invalid") from exc
    expected_keys = {
        "schema", "synthetic_only", "project", "state_dir", "state_id",
        "compose_env_sha256", "lifecycle", "runtime_head", "runtime_tree",
        "hrh_head", "hrh_tree", "volumes", "expected_images",
    }
    if set(value) != expected_keys:
        raise SafetyError("staging marker has unknown or missing fields")
    if (
        value["schema"] != SCHEMA
        or value["synthetic_only"] is not True
        or value["project"] != project
        or value["state_dir"] != str(state_dir)
        or value["hrh_head"] != REQUIRED_HRH_SHA
        or value["volumes"] != volume_names(project)
        or not re.fullmatch(r"[a-f0-9]{32}", value["state_id"])
        or not re.fullmatch(r"[a-f0-9]{64}", value["compose_env_sha256"])
        or value["lifecycle"] not in {"initializing", "recovering", "ready", "stopped"}
        or not isinstance(value["expected_images"], dict)
    ):
        raise SafetyError("staging marker does not match the requested synthetic target")
    return value


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SafetyError(f"required file is unavailable: {path.name}") from exc


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _require_sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise SafetyError(f"{name} must be a lowercase SHA-256")
    return value


def _backup_member_names() -> tuple[str, ...]:
    return (
        BACKUP_MANIFEST_NAME,
        BACKUP_COMPLETE_NAME,
        BACKUP_STATE_ARCHIVE,
        *(f"{BACKUP_VOLUME_DIR}/{key}.tar" for key in BACKED_UP_VOLUME_KEYS),
    )


def _safe_archive_name(name: str) -> str:
    """Return a normalized relative tar member name or fail before extraction."""
    if not isinstance(name, str) or not name or "\\" in name or name.startswith("/"):
        raise SafetyError("backup archive contains an unsafe path")
    normalized = posixpath.normpath(name)
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        return ""
    if normalized == ".." or normalized.startswith("../") or normalized.startswith("/"):
        raise SafetyError("backup archive contains a path traversal member")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise SafetyError("backup archive contains an unsafe path")
    return normalized


def inspect_safe_tar(path: Path, *, require_regular_file: bool) -> tuple[str, ...]:
    """Validate an archive without extracting it into an operator destination."""
    try:
        with tarfile.open(path, "r:") as archive:
            names: list[str] = []
            has_regular = False
            for member in archive.getmembers():
                name = _safe_archive_name(member.name)
                if not name:
                    if member.isdir():
                        continue
                    raise SafetyError("backup archive has an invalid root member")
                if not (member.isdir() or member.isreg()):
                    raise SafetyError("backup archive contains a link or special member")
                if name in names:
                    raise SafetyError("backup archive contains duplicate members")
                names.append(name)
                has_regular = has_regular or member.isreg()
    except (OSError, tarfile.TarError) as exc:
        raise SafetyError("backup archive is unreadable or corrupt") from exc
    if require_regular_file and not has_regular:
        raise SafetyError("backup archive does not contain a regular file")
    return tuple(sorted(names))


def archive_ownership_sha256(path: Path) -> str:
    """Bind archive ownership/mode metadata without disclosing member paths."""
    try:
        with tarfile.open(path, "r:") as archive:
            records: list[dict[str, Any]] = []
            for member in archive.getmembers():
                name = _safe_archive_name(member.name)
                if not name:
                    if member.isdir():
                        continue
                    raise SafetyError("backup archive has an invalid root member")
                if not (member.isdir() or member.isreg()):
                    raise SafetyError("backup archive contains a link or special member")
                records.append({
                    "name": name,
                    "kind": "directory" if member.isdir() else "file",
                    "uid": member.uid,
                    "gid": member.gid,
                    "mode": member.mode & 0o7777,
                })
    except (OSError, tarfile.TarError) as exc:
        raise SafetyError("backup archive is unreadable or corrupt") from exc
    return hashlib.sha256(canonical_json_bytes({"entries": sorted(records, key=lambda item: item["name"])})).hexdigest()


def _iter_safe_tree(root: Path) -> Iterable[tuple[Path, str, os.stat_result]]:
    """Yield a deterministic, symlink-free tree for the private state archive."""
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            path = current_path / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise SafetyError("state directory contains a link or special file")
            yield path, relative, info


def create_state_archive(state_dir: Path, archive_path: Path) -> None:
    """Archive only regular private state files with explicit metadata."""
    if archive_path.exists():
        raise SafetyError("backup state archive already exists")
    try:
        with tarfile.open(archive_path, "x") as archive:
            for path, relative, info in _iter_safe_tree(state_dir):
                member = tarfile.TarInfo(relative)
                member.mode = stat.S_IMODE(info.st_mode)
                member.uid = info.st_uid
                member.gid = info.st_gid
                member.mtime = int(info.st_mtime)
                if stat.S_ISDIR(info.st_mode):
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                else:
                    member.size = info.st_size
                    with path.open("rb") as stream:
                        archive.addfile(member, stream)
    except OSError as exc:
        raise SafetyError("could not write private state archive") from exc
    inspect_safe_tar(archive_path, require_regular_file=True)


def _manifest_members(backup_dir: Path) -> dict[str, dict[str, Any]]:
    members: dict[str, dict[str, Any]] = {}
    for name in _backup_member_names():
        if name in {BACKUP_MANIFEST_NAME, BACKUP_COMPLETE_NAME}:
            continue
        path = backup_dir / name
        if not path.is_file():
            raise SafetyError(f"backup member is missing: {name}")
        members[name] = {
            "sha256": file_sha256(path),
            "size": path.stat().st_size,
            "ownership_sha256": archive_ownership_sha256(path),
        }
    return members


def build_backup_manifest(
    marker: Mapping[str, Any], state_dir: Path, backup_dir: Path,
) -> dict[str, Any]:
    """Create the content-safe manifest; its SHA is recorded externally by the operator."""
    members = _manifest_members(backup_dir)
    return {
        "schema": BACKUP_SCHEMA,
        "synthetic_only": True,
        "complete": True,
        "project": marker["project"],
        "state_id": marker["state_id"],
        "state_dir": str(state_dir.resolve()),
        "compose_env_sha256": marker["compose_env_sha256"],
        "source": {key: marker[key] for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")},
        "expected_images": dict(marker["expected_images"]),
        "volumes": dict(marker["volumes"]),
        "excluded_volume": EXCLUDED_RECOVERY_VOLUME,
        "members": members,
    }


def write_backup_manifest(backup_dir: Path, manifest: Mapping[str, Any]) -> None:
    write_json_atomic(backup_dir / BACKUP_MANIFEST_NAME, manifest, mode=0o600)


def write_backup_completion(backup_dir: Path) -> None:
    path = backup_dir / BACKUP_COMPLETE_NAME
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"complete\n")
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(backup_dir)
    except OSError as exc:
        raise SafetyError("could not publish backup completion marker") from exc


def _read_backup_manifest(backup_dir: Path) -> dict[str, Any]:
    try:
        value = json.loads((backup_dir / BACKUP_MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("backup manifest is missing or invalid") from exc
    if not isinstance(value, dict):
        raise SafetyError("backup manifest must be an object")
    return value


def _validate_backup_manifest_shape(
    manifest: Mapping[str, Any], *, project: str, state_dir: Path,
) -> dict[str, Any]:
    expected_keys = {
        "schema", "synthetic_only", "complete", "project", "state_id", "state_dir",
        "compose_env_sha256", "source", "expected_images", "volumes", "excluded_volume", "members",
    }
    if set(manifest) != expected_keys:
        raise SafetyError("backup manifest has unknown or missing fields")
    if (
        manifest["schema"] != BACKUP_SCHEMA
        or manifest["synthetic_only"] is not True
        or manifest["complete"] is not True
        or manifest["project"] != project
        or manifest["state_dir"] != str(state_dir.resolve())
        or manifest["excluded_volume"] != EXCLUDED_RECOVERY_VOLUME
        or not re.fullmatch(r"[a-f0-9]{32}", str(manifest["state_id"]))
        or not isinstance(manifest["expected_images"], dict)
        or manifest["volumes"] != volume_names(project)
    ):
        raise SafetyError("backup manifest does not bind the requested synthetic target")
    _require_sha256(manifest["compose_env_sha256"], name="backup compose environment hash")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree"}:
        raise SafetyError("backup source frame is invalid")
    for key, value in source.items():
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
            raise SafetyError(f"backup source frame has an invalid {key}")
    if source["hrh_head"] != REQUIRED_HRH_SHA or source["hrh_tree"] != REQUIRED_HRH_TREE:
        raise SafetyError("backup source frame does not match the required HRH source")
    expected_members = set(_backup_member_names()) - {BACKUP_MANIFEST_NAME, BACKUP_COMPLETE_NAME}
    members = manifest["members"]
    if not isinstance(members, dict) or set(members) != expected_members:
        raise SafetyError("backup manifest members are not the exact allowlist")
    for name, value in members.items():
        if not isinstance(value, dict) or set(value) != {"sha256", "size", "ownership_sha256"}:
            raise SafetyError(f"backup manifest member metadata is invalid: {name}")
        _require_sha256(value["sha256"], name=f"backup member hash for {name}")
        _require_sha256(value["ownership_sha256"], name=f"backup ownership hash for {name}")
        if not isinstance(value["size"], int) or value["size"] <= 0:
            raise SafetyError(f"backup member size is invalid: {name}")
    return dict(manifest)


def _archive_member_bytes(path: Path, name: str) -> bytes:
    try:
        with tarfile.open(path, "r:") as archive:
            matching = [member for member in archive.getmembers() if _safe_archive_name(member.name) == name]
            if len(matching) != 1 or not matching[0].isreg():
                raise SafetyError("backup state archive does not contain the required marker")
            stream = archive.extractfile(matching[0])
            if stream is None:
                raise SafetyError("backup state archive member is unreadable")
            return stream.read()
    except (OSError, tarfile.TarError) as exc:
        raise SafetyError("backup state archive is unreadable") from exc


def _validate_archived_marker(state_archive: Path, *, project: str, state_dir: Path, manifest: Mapping[str, Any]) -> None:
    inspect_safe_tar(state_archive, require_regular_file=True)
    try:
        marker = json.loads(_archive_member_bytes(state_archive, MARKER_NAME))
    except json.JSONDecodeError as exc:
        raise SafetyError("backup state marker is invalid") from exc
    if not isinstance(marker, dict):
        raise SafetyError("backup state marker is invalid")
    expected_keys = {
        "schema", "synthetic_only", "project", "state_dir", "state_id", "compose_env_sha256",
        "lifecycle", "runtime_head", "runtime_tree", "hrh_head", "hrh_tree", "volumes", "expected_images",
    }
    if set(marker) != expected_keys:
        raise SafetyError("backup state marker has unknown or missing fields")
    if (
        marker["schema"] != SCHEMA
        or marker["synthetic_only"] is not True
        or marker["project"] != project
        or marker["state_dir"] != str(state_dir.resolve())
        or marker["state_id"] != manifest["state_id"]
        or marker["compose_env_sha256"] != manifest["compose_env_sha256"]
        or marker["lifecycle"] != "stopped"
        or marker["volumes"] != manifest["volumes"]
        or marker["expected_images"] != manifest["expected_images"]
    ):
        raise SafetyError("backup state marker conflicts with the manifest")
    for key, value in manifest["source"].items():
        if marker[key] != value:
            raise SafetyError("backup state marker source frame conflicts with the manifest")


def validate_backup_bundle(
    backup_dir: Path, expected_manifest_sha256: str, project: str, state_dir: Path,
) -> dict[str, Any]:
    """Validate every recovery input while the destination remains untouched."""
    validate_project(project)
    backup_dir = backup_dir.resolve()
    if not backup_dir.is_dir():
        raise SafetyError("backup directory is unavailable")
    _require_sha256(expected_manifest_sha256, name="external manifest hash")
    completion_path = backup_dir / BACKUP_COMPLETE_NAME
    try:
        completed = completion_path.read_bytes()
    except OSError as exc:
        raise SafetyError("backup complete marker is missing") from exc
    if completed != b"complete\n":
        raise SafetyError("backup complete marker is invalid")
    entries = list(backup_dir.rglob("*"))
    if any(item.is_symlink() for item in entries):
        raise SafetyError("backup directory must not contain symbolic links")
    actual_members = {item.relative_to(backup_dir).as_posix() for item in entries if item.is_file()}
    actual_directories = {item.relative_to(backup_dir).as_posix() for item in entries if item.is_dir()}
    expected_members = set(_backup_member_names())
    if actual_members != expected_members:
        raise SafetyError("backup directory has unexpected or missing members")
    if actual_directories != {BACKUP_VOLUME_DIR}:
        raise SafetyError("backup directory has unexpected or missing directories")
    manifest_path = backup_dir / BACKUP_MANIFEST_NAME
    if file_sha256(manifest_path) != expected_manifest_sha256:
        raise SafetyError("external manifest hash does not match the backup")
    manifest = _validate_backup_manifest_shape(
        _read_backup_manifest(backup_dir), project=project, state_dir=state_dir,
    )
    for name, metadata in manifest["members"].items():
        member_path = backup_dir / name
        if (
            member_path.stat().st_size != metadata["size"]
            or file_sha256(member_path) != metadata["sha256"]
            or archive_ownership_sha256(member_path) != metadata["ownership_sha256"]
        ):
            raise SafetyError(f"backup member hash or size differs: {name}")
    _validate_archived_marker(backup_dir / BACKUP_STATE_ARCHIVE, project=project, state_dir=state_dir, manifest=manifest)
    for key in BACKED_UP_VOLUME_KEYS:
        inspect_safe_tar(backup_dir / BACKUP_VOLUME_DIR / f"{key}.tar", require_regular_file=True)
    return manifest


def verify_effective_env(state_dir: Path, marker: Mapping[str, Any]) -> None:
    if file_sha256(state_dir / "compose.env") != marker["compose_env_sha256"]:
        raise SafetyError("compose.env differs from the initialized exact content")


def verify_source_frame(runtime: Path, hrh: Path, shell: Any) -> dict[str, str]:
    runtime = runtime.resolve()
    hrh = hrh.resolve()
    runtime_head = shell.git(runtime, "rev-parse", "HEAD")
    runtime_tree = shell.git(runtime, "rev-parse", "HEAD^{tree}")
    hrh_head = shell.git(hrh, "rev-parse", "HEAD")
    hrh_tree = shell.git(hrh, "rev-parse", "HEAD^{tree}")
    try:
        shell.git(runtime, "merge-base", "--is-ancestor", RUNTIME_BASE_SHA, runtime_head)
    except CommandError as exc:
        raise SafetyError("runtime does not descend from the frozen staging base") from exc
    if shell.git(runtime, "status", "--porcelain=v1"):
        raise SafetyError("runtime worktree must be clean")
    if shell.git(hrh, "status", "--porcelain=v1"):
        raise SafetyError("HRH worktree must be clean")
    if hrh_head != REQUIRED_HRH_SHA:
        raise SafetyError("HRH worktree must be at the exact required head")
    if REQUIRED_HRH_TREE and hrh_tree != REQUIRED_HRH_TREE:
        raise SafetyError("HRH tree does not match the exact required tree")
    return {
        "runtime_head": runtime_head,
        "runtime_tree": runtime_tree,
        "hrh_head": hrh_head,
        "hrh_tree": hrh_tree,
    }


def verify_destructive_volumes(
    project: str,
    state_id: str,
    expected: set[str],
    discovered: Mapping[str, Mapping[str, str]],
    lifecycle: str,
) -> list[str]:
    unexpected = set(discovered) - expected
    if unexpected:
        raise SafetyError("unexpected project volumes: " + ", ".join(sorted(unexpected)))
    required = {PROJECT_LABEL: project, STATE_LABEL: state_id, SYNTHETIC_LABEL: "true"}
    for name in discovered:
        if any(discovered[name].get(key) != value for key, value in required.items()):
            raise SafetyError(f"volume label mismatch: {name}")
    if lifecycle in {"ready", "stopped"} and set(discovered) != expected:
        raise SafetyError("ready/stopped staging requires the exact volume set")
    if lifecycle not in {"initializing", "recovering", "ready", "stopped"}:
        raise SafetyError("unknown lifecycle for destructive volume verification")
    return sorted(discovered)


def verify_destructive_resources(
    project: str,
    state_id: str,
    containers: Mapping[str, Mapping[str, str]],
    networks: Mapping[str, Mapping[str, str]],
    lifecycle: str,
) -> tuple[list[str], list[str]]:
    required = {PROJECT_LABEL: project, STATE_LABEL: state_id, SYNTHETIC_LABEL: "true"}
    allowed_networks = {f"{project}_{key}" for key in NETWORK_KEYS}
    unexpected_networks = set(networks) - allowed_networks
    if unexpected_networks:
        raise SafetyError("unexpected project network: " + ", ".join(sorted(unexpected_networks)))
    for name, labels in networks.items():
        if any(labels.get(key) != value for key, value in required.items()):
            raise SafetyError(f"network label mismatch: {name}")
    services: list[str] = []
    for name, labels in containers.items():
        service = labels.get("com.docker.compose.service")
        if service not in ALLOWED_SERVICES:
            raise SafetyError(f"unexpected project container: {name}")
        if any(labels.get(key) != value for key, value in required.items()):
            raise SafetyError(f"container label mismatch: {name}")
        services.append(service)
    duplicates = sorted({service for service in services if services.count(service) > 1})
    if duplicates:
        raise SafetyError("duplicate project service containers: " + ", ".join(duplicates))
    if lifecycle in {"ready", "stopped"}:
        if "controller" in services:
            raise SafetyError("controller must be absent from ready/stopped staging")
        expected_services = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(services) != expected_services:
            raise SafetyError("ready/stopped staging requires the exact service set")
        if set(networks) != allowed_networks:
            raise SafetyError("ready/stopped staging requires the exact network set")
    elif lifecycle not in {"initializing", "recovering"}:
        raise SafetyError("unknown lifecycle for destructive resource verification")
    return sorted(containers), sorted(networks)


def verify_publishers(
    inspected: Mapping[str, Mapping[str, Any]], port: int,
) -> dict[str, dict[str, str]]:
    expected_raw = {"18444/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}
    expected_receipt = {
        "container_port": "18444/tcp",
        "host_ip": "127.0.0.1",
        "host_port": str(port),
    }
    if set(inspected) != set(LONG_RUNNING_SERVICES):
        raise SafetyError("container inspection does not cover the exact running service set")
    for service, info in inspected.items():
        requested = info.get("HostConfig", {}).get("PortBindings")
        effective = info.get("NetworkSettings", {}).get("Ports")
        if service == "operator-proxy":
            if requested != expected_raw:
                raise SafetyError("proxy requested publisher is not the exact loopback binding")
            effective_bindings = (
                {key: value for key, value in effective.items() if value}
                if isinstance(effective, dict)
                else None
            )
            if effective_bindings != expected_raw:
                raise SafetyError("proxy effective publisher is not the exact loopback binding")
        else:
            if requested:
                raise SafetyError(f"non-proxy service requests a host port: {service}")
            effective_bindings = (
                any(value for value in effective.values()) if isinstance(effective, dict) else bool(effective)
            )
            if effective_bindings:
                raise SafetyError(f"non-proxy service has an effective host port: {service}")
    return {"requested": dict(expected_receipt), "effective": dict(expected_receipt)}


def verify_compose_rows(rows: Iterable[Mapping[str, Any]]) -> None:
    records = list(rows)
    services = [record.get("Service") for record in records]
    if len(services) != len(set(services)):
        raise SafetyError("Compose service rows contain a duplicate")
    expected = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
    if set(services) != expected:
        raise SafetyError("status requires the exact Compose service set")
    by_service = {record["Service"]: record for record in records}
    for service in LONG_RUNNING_SERVICES:
        if by_service[service].get("State") != "running":
            raise SafetyError(f"required service is not running: {service}")
    for service in ONE_SHOT_SERVICES:
        row = by_service[service]
        if row.get("State") != "exited" or row.get("ExitCode") != 0:
            raise SafetyError(f"required one-shot did not exit successfully: {service}")


def verify_network_topology(
    project: str,
    inspected: Mapping[str, Mapping[str, Any]],
    networks: Mapping[str, Mapping[str, Any]],
) -> None:
    if set(inspected) != set(EXPECTED_NETWORK_KEYS_BY_SERVICE):
        raise SafetyError("network membership inspection does not cover the exact service set")
    expected_names = {f"{project}_{key}" for key in NETWORK_KEYS}
    if set(networks) != expected_names:
        raise SafetyError("network inspection does not cover the exact staging network set")
    for key in INTERNAL_NETWORK_KEYS:
        if networks[f"{project}_{key}"].get("Internal") is not True:
            raise SafetyError(f"core network is not internal: {key}")
    access_name = f"{project}_operator_access"
    if networks[access_name].get("Internal") is not False:
        raise SafetyError("operator_access must be the explicit non-internal network")
    proxy = inspected.get("operator-proxy")
    if not proxy or not proxy.get("Id"):
        raise SafetyError("operator proxy inspection is unavailable")
    access_members = set((networks[access_name].get("Containers") or {}).keys())
    if access_members != {proxy["Id"]}:
        raise SafetyError("operator_access must contain only the proxy")
    for service, expected_keys in EXPECTED_NETWORK_KEYS_BY_SERVICE.items():
        info = inspected[service]
        memberships = set(info.get("NetworkSettings", {}).get("Networks") or {})
        expected_memberships = {f"{project}_{key}" for key in expected_keys}
        if memberships != expected_memberships:
            raise SafetyError(f"{service} has unexpected network membership")


def _tmpfs_is_confined(value: Any, *, uid: int, gid: int) -> bool:
    if not isinstance(value, str):
        return False
    tokens = [item.strip() for item in value.split(",")]
    if not tokens or any(not item for item in tokens):
        return False
    flags: set[str] = set()
    values: dict[str, str] = {}
    allowed_flags = {"rw", "ro", "noexec", "exec", "nosuid", "suid"}
    allowed_values = {"size", "mode", "uid", "gid"}
    for token in tokens:
        if "=" in token:
            key, item = token.split("=", 1)
            if key not in allowed_values or not item or key in values:
                return False
            values[key] = item
        else:
            if token not in allowed_flags or token in flags:
                return False
            flags.add(token)
    if {"ro", "rw"} <= flags or {"exec", "noexec"} <= flags or {"suid", "nosuid"} <= flags:
        return False
    size_is_16m = values.get("size") in {"16m", "16384k", "16777216"}
    mode_is_0700 = values.get("mode") in {"0700", "700"}
    return (
        {"rw", "noexec", "nosuid"} <= flags
        and values.get("uid") == str(uid)
        and values.get("gid") == str(gid)
        and size_is_16m
        and mode_is_0700
    )


def verify_restricted_container_controls(
    inspected: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Reject effective runtime drift for the two restricted long-lived services."""
    evidence: dict[str, dict[str, Any]] = {}
    for service, expected in RESTRICTED_CONTAINER_CONTROLS.items():
        info = inspected.get(service)
        if not isinstance(info, Mapping):
            raise SafetyError(f"{service} container inspection is unavailable")
        config = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        security = {
            str(value).replace(":", "=")
            for value in (host.get("SecurityOpt") or [])
        }
        tmpfs = host.get("Tmpfs") or {}
        mounts = info.get("Mounts") or []
        mount_modes: dict[str, bool] = {}
        for mount in mounts:
            if not isinstance(mount, Mapping) or not isinstance(mount.get("Destination"), str):
                raise SafetyError(f"{service} mount inspection is malformed")
            destination = str(mount["Destination"])
            if destination in mount_modes or not isinstance(mount.get("RW"), bool):
                raise SafetyError(f"{service} mount inspection is ambiguous")
            mount_modes[destination] = bool(mount["RW"])
        expected_modes = {
            **{path: False for path in expected["read_only_mounts"]},
            **{path: True for path in expected["writable_mounts"]},
        }
        if (
            config.get("User") != expected["user"]
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or {str(value).upper() for value in (host.get("CapDrop") or [])} != {"ALL"}
            or host.get("CapAdd") not in (None, [])
            or security != {"no-new-privileges=true"}
            or set(tmpfs) != {"/tmp"}
            or not _tmpfs_is_confined(
                tmpfs.get("/tmp"), uid=expected["uid"], gid=expected["gid"]
            )
            or mount_modes != expected_modes
        ):
            raise SafetyError(f"{service} effective container confinement rejected")
        evidence[service] = {
            "user": expected["user"],
            "privileged": False,
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "tmpfs": ["/tmp"],
            "read_only_mounts": sorted(expected["read_only_mounts"]),
            "writable_mounts": sorted(expected["writable_mounts"]),
        }
    return evidence


def _certificate_material(seed: Path) -> None:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic clinical staging CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def server(host: str, *, include_loopback_ip: bool = False) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        names: list[x509.GeneralName] = [x509.DNSName(host)]
        if include_loopback_ip:
            names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    material = {"ca.crt": ca.public_bytes(serialization.Encoding.PEM)}
    for host, prefix in (("mattermost", "mattermost"), ("hrh-tls", "hrh-tls")):
        material[f"{prefix}.crt"], material[f"{prefix}.key"] = server(
            host, include_loopback_ip=host == "mattermost"
        )
    for name, raw in material.items():
        path = seed / name
        path.write_bytes(raw)
        path.chmod(0o600)


class ClinicalStaging:
    def __init__(self, runtime: Path, hrh: Path, state_dir: Path, project: str, port: int, shell: Shell | None = None):
        self.runtime = runtime.resolve()
        self.hrh = hrh.resolve()
        self.project = validate_project(project)
        self.state_dir = validate_state_path(
            state_dir,
            project,
            forbidden_roots=(self.runtime, self.hrh),
        )
        if not 1024 <= port <= 65535:
            raise SafetyError("Mattermost loopback port must be 1024..65535")
        self.port = port
        self.shell = shell or Shell()
        self.base_compose = self.runtime / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"
        self.overlay = self.runtime / "deploy" / "clinical-staging" / "compose.yaml"
        self.harness = self.runtime / "tests" / "deployment" / "clinical-composed-e2e"
        self.env_file = self.state_dir / "compose.env"

    def _require_linux(self) -> None:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            raise SafetyError("operator staging lifecycle is supported only on local Linux")

    def _compose_args(self) -> tuple[str, ...]:
        return (
            "docker", "compose", "--env-file", str(self.env_file),
            "--project-name", self.project, "--file", str(self.base_compose),
            "--file", str(self.overlay),
        )

    def compose(self, *args: str, check: bool = True, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
        return self.shell.run(*self._compose_args(), *args, cwd=self.runtime, check=check, timeout=timeout)

    def control(self, *args: str, timeout: int = 600) -> str:
        result = self.compose(
            "--profile", "provision", "run", "--rm", "--no-deps", "controller", *args,
            timeout=timeout,
        )
        return result.stdout.strip()

    def _env_values(self, marker: Mapping[str, Any], *, seed_root: Path | None = None) -> dict[str, str]:
        material_seed = (seed_root or self.state_dir) / "seed"
        effective_seed = self.state_dir / "seed"
        private = serialization.load_pem_private_key(
            (material_seed / "policy-private.pem").read_bytes(), password=None
        )
        policy_public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
        values: dict[str, str] = {
            "CLINICAL_MM_DB_PASSWORD": secrets.token_hex(24),
            "CLINICAL_HRH_DB_PASSWORD": secrets.token_hex(24),
            "CLINICAL_HRH_SESSION_SECRET": secrets.token_hex(32),
            "CLINICAL_HRH_ENCRYPTION_KEY": secrets.token_hex(32),
            "CLINICAL_HRH_ROOT": self.hrh.as_posix(),
            "CLINICAL_HARNESS": self.harness.as_posix(),
            "CLINICAL_SEED": effective_seed.as_posix(),
            "CLINICAL_INGRESS_IMAGE": f"restricted-clinical-ingress:{self.project}",
            "CLINICAL_ADAPTER_IMAGE": f"restricted-clinical-adapter:{self.project}",
            "CLINICAL_POLICY_PUBLIC_KEY": policy_public,
            "CLINICAL_HRH_BUILD_SHA": marker["hrh_head"],
            "CLINICAL_STAGING_PROJECT": self.project,
            "CLINICAL_STAGING_STATE_ID": marker["state_id"],
            "CLINICAL_STAGING_PORT": str(self.port),
        }
        values.update({f"CLINICAL_VOLUME_{key.upper()}": name for key, name in marker["volumes"].items()})
        return values

    @staticmethod
    def _env_bytes(values: Mapping[str, str]) -> bytes:
        return "".join(f"{key}={value}\n" for key, value in values.items()).encode("utf-8")

    def _create_volumes(self, marker: Mapping[str, Any]) -> None:
        for name in marker["volumes"].values():
            self.shell.run(
                "docker", "volume", "create",
                "--label", f"{PROJECT_LABEL}={self.project}",
                "--label", f"{STATE_LABEL}={marker['state_id']}",
                "--label", f"{SYNTHETIC_LABEL}=true",
                name,
                cwd=self.runtime,
            )
        verify_destructive_volumes(
            self.project,
            marker["state_id"],
            set(marker["volumes"].values()),
            self._volume_labels(),
            marker["lifecycle"],
        )
        if set(self._volume_labels()) != set(marker["volumes"].values()):
            raise SafetyError("volume creation did not produce the exact initialized set")

    def _seed_material(self, root: Path) -> None:
        seed = root / "seed"
        seed.mkdir(mode=0o700)
        for name in ("admin_password", "actor_password", "denied_password", "hrh_api_key"):
            path = seed / name
            path.write_text("clinical_" + secrets.token_hex(24), encoding="ascii")
            path.chmod(0o600)
        _certificate_material(seed)
        policy_private = Ed25519PrivateKey.generate()
        policy_path = seed / "policy-private.pem"
        policy_path.write_bytes(
            policy_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        policy_path.chmod(0o600)

    def _prepare_new_state(self, frame: Mapping[str, str]) -> dict[str, Any]:
        if self.state_dir.exists():
            if any(self.state_dir.iterdir()):
                raise SafetyError("init requires a fresh target or a valid initializing marker")
            self.state_dir.rmdir()
        temporary = self.state_dir.parent / f".{self.state_dir.name}.init-{secrets.token_hex(8)}"
        temporary.mkdir(mode=0o700, parents=False)
        try:
            (temporary / "evidence").mkdir(mode=0o700)
            self._seed_material(temporary)
            marker = new_marker(
                project=self.project,
                state_dir=self.state_dir,
                state_id=secrets.token_hex(16),
                env_sha256="0" * 64,
                **frame,
            )
            values = self._env_values(marker, seed_root=temporary)
            env_raw = self._env_bytes(values)
            marker["compose_env_sha256"] = hashlib.sha256(env_raw).hexdigest()
            env_path = temporary / "compose.env"
            env_path.write_bytes(env_raw)
            env_path.chmod(0o600)
            write_json_atomic(temporary / MARKER_NAME, marker, mode=0o600)
            fsync_directory(temporary)
            os.replace(temporary, self.state_dir)
            fsync_directory(self.state_dir.parent)
            return marker
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _write_marker(self, marker: Mapping[str, Any]) -> None:
        write_json_atomic(self.state_dir / MARKER_NAME, marker, mode=0o600)

    def _build_images(self) -> None:
        # controller is FROM the locally tagged ingress image, so its build
        # cannot share a parallel Compose phase with ingress.
        self.compose("build", "ingress", "clinical-adapter", timeout=2400)
        self.compose("build", "controller", "hrh-migrate", "hrh", timeout=2400)

    def init(self) -> dict[str, Any]:
        self._require_linux()
        frame = verify_source_frame(self.runtime, self.hrh, self.shell)
        if self.state_dir.exists() and (self.state_dir / MARKER_NAME).exists():
            marker = read_marker(self.state_dir, self.project)
            if marker["lifecycle"] != "initializing":
                raise SafetyError("staging target is already initialized")
            verify_effective_env(self.state_dir, marker)
            if any(marker[key] != value for key, value in frame.items()):
                raise SafetyError("initializing marker source frame changed")
        else:
            self.state_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            marker = self._prepare_new_state(frame)
        state_stat = self.state_dir.stat()
        if state_stat.st_uid != os.getuid() or stat.S_IMODE(state_stat.st_mode) != 0o700:
            raise SafetyError("state directory must be owned by the operator with mode 0700")
        self._create_volumes(marker)
        self.compose("config", "--quiet")
        self._build_images()
        self.control("seed-volumes")
        self.compose("up", "--detach", "mattermost-postgres", "hrh-postgres", "hrh-migrate", timeout=900)
        migrated = self.compose("wait", "hrh-migrate", check=False, timeout=900)
        if migrated.returncode:
            raise CommandError("HRH migration did not complete successfully")
        self.compose("up", "--detach", "mattermost", timeout=600)
        self.control("wait-mm")
        password = (self.state_dir / "seed" / "admin_password").read_text(encoding="ascii")
        created = self.compose(
            "exec", "--no-TTY", "mattermost", "/mattermost/bin/mmctl", "--local", "user", "create",
            "--email", "admin@clinical.invalid", "--username", "clinicaladmin", "--password", password,
            "--system-admin", "--email-verified", "--disable-welcome-email", "--quiet", check=False,
        )
        if created.returncode and "already exists" not in (created.stdout + created.stderr).lower():
            raise CommandError("synthetic Mattermost administrator bootstrap failed")
        self.control("bootstrap-mm")
        self.control("seed-hrh")
        self.control("policy", "clinical-e1", "3600")
        self.control("outbox-init")
        public_key = self.control("public-key")
        base64.b64decode(public_key, validate=True)
        env_public = next(
            line.split("=", 1)[1]
            for line in self.env_file.read_text(encoding="utf-8").splitlines()
            if line.startswith("CLINICAL_POLICY_PUBLIC_KEY=")
        )
        if public_key != env_public:
            raise SafetyError("provisioned policy public key differs from the sealed environment")
        self.compose("up", "--detach", *ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        marker["expected_images"] = self._built_images()
        marker["lifecycle"] = "ready"
        self._write_marker(marker)
        self.up()
        return self.status()

    def up(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "up", {"ready", "stopped"})
        self.compose("up", "--detach", *ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        if marker["lifecycle"] == "stopped":
            marker["lifecycle"] = "ready"
            self._write_marker(marker)
        return self.status()

    def _verify_marker_and_source(self) -> dict[str, Any]:
        marker = read_marker(self.state_dir, self.project)
        verify_effective_env(self.state_dir, marker)
        frame = verify_source_frame(self.runtime, self.hrh, self.shell)
        for key, value in frame.items():
            if marker[key] != value:
                raise SafetyError(f"current source frame differs from initialized {key}")
        return marker

    @staticmethod
    def _require_lifecycle(marker: Mapping[str, Any], command: str, allowed: set[str]) -> None:
        lifecycle = marker.get("lifecycle")
        if lifecycle not in allowed:
            expected = ", ".join(sorted(allowed))
            raise SafetyError(
                f"{command} rejects marker lifecycle {lifecycle!r}; expected one of: {expected}"
            )

    def _containers(self, *, all_containers: bool = False) -> list[dict[str, Any]]:
        args = ["ps", "--format", "json"]
        if all_containers:
            args.insert(1, "--all")
        raw = self.compose(*args, check=False).stdout.strip()
        if not raw:
            return []
        try:
            value = json.loads(raw)
            return value if isinstance(value, list) else [value]
        except json.JSONDecodeError:
            return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def _built_images(self) -> dict[str, str]:
        result: dict[str, str] = {}
        records = {row.get("Service"): row for row in self._containers(all_containers=True)}
        for service in LONG_RUNNING_SERVICES:
            container_id = records.get(service, {}).get("ID")
            if not container_id:
                raise SafetyError(f"container unavailable for image evidence: {service}")
            info = json.loads(self.shell.run("docker", "container", "inspect", container_id).stdout)[0]
            result[service] = info["Image"]
        return result

    def _container_inspections(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for row in self._containers(all_containers=True):
            container_id = row.get("ID")
            service = row.get("Service")
            if container_id and service:
                result[str(service)] = json.loads(
                    self.shell.run("docker", "container", "inspect", str(container_id)).stdout
                )[0]
        return result

    def _network_inspections(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for key in NETWORK_KEYS:
            name = f"{self.project}_{key}"
            inspected = self.shell.run("docker", "network", "inspect", name)
            result[name] = json.loads(inspected.stdout)[0]
        return result

    def _probe_mattermost_tls(self) -> dict[str, Any]:
        ca_path = self.state_dir / "seed" / "ca.crt"
        try:
            context = ssl.create_default_context(cafile=str(ca_path))
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                    secured.settimeout(5)
                    secured.sendall(
                        b"GET /api/v4/system/ping HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
                    )
                    response = http.client.HTTPResponse(secured)
                    response.begin()
                    if response.status != 200:
                        raise SafetyError("Mattermost TLS probe did not return HTTP 200")
                    body = response.read(65537)
                    if len(body) > 65536:
                        raise SafetyError("Mattermost TLS probe response exceeded 64 KiB")
            payload = json.loads(body)
            if not isinstance(payload, dict) or payload.get("status") != "OK":
                raise SafetyError("Mattermost TLS probe returned an unexpected payload")
        except SafetyError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, json.JSONDecodeError, ValueError) as exc:
            raise SafetyError("Mattermost CA-verified TLS probe failed") from exc
        return {
            "verified": True,
            "hostname": "127.0.0.1",
            "path": "/api/v4/system/ping",
        }

    def _assert_no_controller(self) -> None:
        containers = self._labeled_resources("container")
        if any(labels.get("com.docker.compose.service") == "controller" for labels in containers.values()):
            raise SafetyError("privileged provisioner must not remain after initialization")

    def status(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "status", {"ready"})
        rows = self._containers(all_containers=True)
        verify_compose_rows(rows)
        self._assert_no_controller()
        all_inspected = self._container_inspections()
        expected_inspections = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(all_inspected) != expected_inspections:
            raise SafetyError("container inspection does not cover the exact Compose service set")
        inspected = {service: all_inspected[service] for service in LONG_RUNNING_SERVICES}
        publisher = verify_publishers(inspected, self.port)
        verify_network_topology(self.project, inspected, self._network_inspections())
        restricted_controls = verify_restricted_container_controls(inspected)
        self.control("wait-mm")
        self.control("wait-hrh")
        tls_probe = self._probe_mattermost_tls()
        socket_raw = self.compose(
            "exec", "--no-TTY", "clinical-adapter", "python", "-c",
            "import json,os,stat; s=os.stat('/run/restricted-clinical/query.sock'); print(json.dumps({'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'socket':stat.S_ISSOCK(s.st_mode)}))",
        ).stdout
        socket_status = json.loads(socket_raw)
        if socket_status != {"uid": 10008, "gid": 20006, "mode": 0o660, "socket": True}:
            raise SafetyError("clinical socket metadata is not exact")
        ingress_started_at = all_inspected["ingress"].get("State", {}).get("StartedAt")
        if not isinstance(ingress_started_at, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z",
            ingress_started_at,
        ) or ingress_started_at.startswith("0001-"):
            raise SafetyError("current Mattermost ingress start time is unavailable")
        logs = self.compose(
            "logs",
            "--no-color",
            "--since",
            ingress_started_at,
            "ingress",
            check=False,
        ).stdout
        if "mattermost_ingress_outcome=authenticated_ready" not in logs:
            raise SafetyError("Mattermost ingress is not authenticated-ready")
        current_images = self._built_images()
        if not marker["expected_images"] or current_images != marker["expected_images"]:
            raise SafetyError("running service image identities differ from initialized receipt")
        evidence = {
            "schema": SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "source": {key: marker[key] for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")},
            "built_images": current_images,
            "compose_env_sha256": marker["compose_env_sha256"],
            "policy_digest": self.control("policy-digest"),
            "lifecycle": "ready",
            "mattermost": f"https://127.0.0.1:{self.port}",
            "mattermost_publisher": publisher,
            "ingress_started_at": ingress_started_at,
            "tls_probe": tls_probe,
            "network_exception": "operator-proxy only: operator_access is non-internal",
            "restricted_container_controls": restricted_controls,
            "privileged_provisioner_running": False,
            "nonclaims": ["not HIPAA", "not PHI-authorized", "not production"],
            "observed_at": datetime.now(UTC).isoformat(),
        }
        self._assert_no_controller()
        write_json_atomic(self.state_dir / "evidence" / "status.json", evidence, mode=0o600)
        return evidence

    def refresh_policy(self, epoch: str) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "refresh-policy", {"ready"})
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", epoch):
            raise SafetyError("policy epoch has an invalid shape")
        self.compose("stop", "ingress")
        self.control("policy", epoch, "3600")
        installed_digest = self.control("policy-verify")
        if not re.fullmatch(r"[a-f0-9]{64}", installed_digest):
            raise SafetyError("installed policy pair did not verify")
        self.compose("up", "--detach", "ingress")
        return self.status()

    def stop(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "stop", {"ready"})
        stopped = self.compose("stop", *LONG_RUNNING_SERVICES, check=False)
        if stopped.returncode:
            raise CommandError("Compose could not stop every required staging service")
        marker["lifecycle"] = "stopped"
        self._write_marker(marker)
        evidence = {"schema": SCHEMA, "project": self.project, "state_id": marker["state_id"], "lifecycle": "stopped", "observed_at": datetime.now(UTC).isoformat()}
        write_json_atomic(self.state_dir / "evidence" / "last-transition.json", evidence, mode=0o600)
        return evidence

    def _verify_cold_quiescence(self, marker: Mapping[str, Any]) -> None:
        """A stopped marker alone is not a fence; Docker state must agree."""
        self._require_lifecycle(marker, "backup", {"stopped"})
        expected_volumes = set(marker["volumes"].values())
        verify_destructive_volumes(
            self.project, marker["state_id"], expected_volumes, self._volume_labels(), "stopped",
        )
        containers = self._labeled_resources("container")
        networks = self._labeled_resources("network")
        verify_destructive_resources(self.project, marker["state_id"], containers, networks, "stopped")
        rows = self._containers(all_containers=True)
        by_service = {str(row.get("Service")): row for row in rows}
        expected_services = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(by_service) != expected_services:
            raise SafetyError("backup quiescence does not cover the exact Compose service set")
        running = sorted(
            service for service in LONG_RUNNING_SERVICES
            if str(by_service[service].get("State", "")).lower() in {"running", "restarting", "created"}
        )
        if running:
            raise SafetyError("backup requires fully stopped staging services: " + ", ".join(running))

    def _backup_volume(self, key: str, volume: str, backup_dir: Path) -> None:
        if key not in BACKED_UP_VOLUME_KEYS or volume != volume_names(self.project)[key]:
            raise SafetyError("backup volume is outside the exact allowlist")
        archive = f"/{BACKUP_VOLUME_DIR}/{key}.tar"
        self.shell.run(
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--entrypoint", "sh",
            "--mount", f"type=volume,src={volume},dst=/source,readonly",
            "--mount", f"type=bind,src={backup_dir},dst=/backup",
            RECOVERY_HELPER_IMAGE,
            "-ec", f"tar --numeric-owner -C /source -cf {archive} .",
            cwd=self.runtime, timeout=1200,
        )
        inspect_safe_tar(backup_dir / BACKUP_VOLUME_DIR / f"{key}.tar", require_regular_file=True)

    def backup(self, backup_dir: Path) -> dict[str, Any]:
        """Create an atomically published, cold-only backup.  No overwrite exists."""
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._verify_cold_quiescence(marker)
        backup_dir = validate_backup_path(
            backup_dir, state_dir=self.state_dir, forbidden_roots=(self.runtime, self.hrh),
        )
        if backup_dir.exists():
            raise SafetyError("backup target must be a new directory")
        if not backup_dir.parent.is_dir():
            raise SafetyError("backup parent directory must already exist")
        temporary = backup_dir.parent / f".{backup_dir.name}.partial-{secrets.token_hex(8)}"
        try:
            temporary.mkdir(mode=0o700)
            (temporary / BACKUP_VOLUME_DIR).mkdir(mode=0o700)
            create_state_archive(self.state_dir, temporary / BACKUP_STATE_ARCHIVE)
            for key in BACKED_UP_VOLUME_KEYS:
                self._backup_volume(key, marker["volumes"][key], temporary)
            manifest = build_backup_manifest(marker, self.state_dir, temporary)
            write_backup_manifest(temporary, manifest)
            write_backup_completion(temporary)
            fsync_directory(temporary)
            os.replace(temporary, backup_dir)
            fsync_directory(backup_dir.parent)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise
        manifest_sha256 = file_sha256(backup_dir / BACKUP_MANIFEST_NAME)
        return {
            "schema": BACKUP_SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "backup_dir": str(backup_dir),
            "manifest_sha256": manifest_sha256,
            "excluded_volume": EXCLUDED_RECOVERY_VOLUME,
            "lifecycle": "stopped",
            "nonclaims": ["not a scheduled backup", "not encrypted", "not production"],
        }

    def _require_empty_restore_destination(self) -> None:
        if self.state_dir.exists() and any(self.state_dir.iterdir()):
            raise SafetyError("restore requires an absent or empty state destination")
        if not self.state_dir.parent.is_dir():
            raise SafetyError("restore state parent directory must already exist")
        existing_labeled = self._labeled_resources("container") | self._labeled_resources("network")
        if existing_labeled:
            raise SafetyError("restore destination conflicts with labeled Docker resources")
        for volume in volume_names(self.project).values():
            if self.shell.run("docker", "volume", "inspect", volume, check=False).returncode == 0:
                raise SafetyError(f"restore destination conflicts with existing Docker volume: {volume}")
        for key in NETWORK_KEYS:
            name = f"{self.project}_{key}"
            if self.shell.run("docker", "network", "inspect", name, check=False).returncode == 0:
                raise SafetyError(f"restore destination conflicts with existing Docker network: {name}")
        names = self.shell.run("docker", "container", "ls", "--all", "--format", "{{.Names}}")
        conflict_prefix = f"{self.project}-"
        if any(line.strip().startswith(conflict_prefix) for line in names.stdout.splitlines()):
            raise SafetyError("restore destination conflicts with a project-named Docker container")

    @staticmethod
    def _extract_safe_state_archive(archive_path: Path, destination: Path) -> None:
        """Extract a previously validated regular-file archive without tarfile.extractall."""
        try:
            with tarfile.open(archive_path, "r:") as archive:
                for member in archive.getmembers():
                    name = _safe_archive_name(member.name)
                    if not name:
                        if member.isdir():
                            continue
                        raise SafetyError("backup state archive has an invalid root member")
                    if not (member.isdir() or member.isreg()):
                        raise SafetyError("backup state archive contains a non-regular member")
                    target = destination.joinpath(*name.split("/"))
                    try:
                        target.resolve().relative_to(destination.resolve())
                    except ValueError as exc:
                        raise SafetyError("backup state archive escapes its destination") from exc
                    if member.isdir():
                        target.mkdir(mode=member.mode & 0o777, parents=True, exist_ok=False)
                        continue
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise SafetyError("backup state archive member is unreadable")
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, member.mode & 0o777)
                    with os.fdopen(fd, "wb") as output:
                        shutil.copyfileobj(stream, output)
                        output.flush()
                        os.fsync(output.fileno())
        except (OSError, tarfile.TarError) as exc:
            raise SafetyError("could not safely restore private state") from exc

    def _restore_volume(self, key: str, volume: str, backup_dir: Path) -> None:
        if key not in BACKED_UP_VOLUME_KEYS or volume != volume_names(self.project)[key]:
            raise SafetyError("restore volume is outside the exact allowlist")
        archive = f"/{BACKUP_VOLUME_DIR}/{key}.tar"
        self.shell.run(
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--entrypoint", "sh",
            "--mount", f"type=volume,src={volume},dst=/destination",
            "--mount", f"type=bind,src={backup_dir},dst=/backup,readonly",
            RECOVERY_HELPER_IMAGE,
            "-ec", f"tar --numeric-owner -C /destination -xf {archive}",
            cwd=self.runtime, timeout=1200,
        )

    def _start_restored_stack(self) -> None:
        """The explicit dependency order is part of the cold-restore witness."""
        self.compose("up", "--detach", "mattermost-postgres", "hrh-postgres", "hrh-migrate", timeout=900)
        migrated = self.compose("wait", "hrh-migrate", check=False, timeout=900)
        if migrated.returncode:
            raise CommandError("restored HRH migration did not complete successfully")
        self.compose("up", "--detach", "mattermost", "operator-proxy", timeout=600)
        self.control("wait-mm")
        self.compose("up", "--detach", "clinical-socket-init", "hrh", "hrh-tls", "clinical-adapter", timeout=900)
        self.control("wait-hrh")
        self.compose("up", "--detach", "ingress", timeout=600)

    def restore(self, backup_dir: Path, expected_manifest_sha256: str) -> dict[str, Any]:
        """Restore only a fully validated cold bundle into a clean destination."""
        self._require_linux()
        backup_dir = validate_backup_path(
            backup_dir, state_dir=self.state_dir, forbidden_roots=(self.runtime, self.hrh),
        )
        manifest = validate_backup_bundle(backup_dir, expected_manifest_sha256, self.project, self.state_dir)
        frame = verify_source_frame(self.runtime, self.hrh, self.shell)
        if frame != manifest["source"]:
            raise SafetyError("current source frame differs from the validated backup source frame")
        self._require_empty_restore_destination()

        temporary = self.state_dir.parent / f".{self.state_dir.name}.recovering-{secrets.token_hex(8)}"
        published_state = False
        try:
            temporary.mkdir(mode=0o700)
            self._extract_safe_state_archive(backup_dir / BACKUP_STATE_ARCHIVE, temporary)
            marker = _read_backup_manifest(backup_dir)  # manifest bytes were validated before mutation
            del marker  # make accidental use of untrusted backup metadata impossible below
            restored_marker = json.loads((temporary / MARKER_NAME).read_text(encoding="utf-8"))
            if not isinstance(restored_marker, dict):
                raise SafetyError("restored marker is invalid")
            # The bundle validator bound every value below before this extraction.
            restored_marker["lifecycle"] = "recovering"
            write_json_atomic(temporary / MARKER_NAME, restored_marker, mode=0o600)
            if file_sha256(temporary / "compose.env") != manifest["compose_env_sha256"]:
                raise SafetyError("restored compose environment differs from the validated backup")
            fsync_directory(temporary)
            if self.state_dir.exists():
                self.state_dir.rmdir()
            os.replace(temporary, self.state_dir)
            fsync_directory(self.state_dir.parent)
            published_state = True

            marker = read_marker(self.state_dir, self.project)
            self._create_volumes(marker)
            for key in BACKED_UP_VOLUME_KEYS:
                self._restore_volume(key, marker["volumes"][key], backup_dir)
            # The excluded transport socket is recreated empty by _create_volumes;
            # clinical-socket-init rebuilds its socket during the ordered startup.
            marker["lifecycle"] = "stopped"
            self._write_marker(marker)
            self._start_restored_stack()
            marker["lifecycle"] = "ready"
            self._write_marker(marker)
            status = self.status()
            receipt = {
                "schema": BACKUP_SCHEMA,
                "synthetic_only": True,
                "project": self.project,
                "state_id": marker["state_id"],
                "manifest_sha256": expected_manifest_sha256,
                "excluded_volume": EXCLUDED_RECOVERY_VOLUME,
                "source": manifest["source"],
                "status_observed_at": status["observed_at"],
                "restored_at": datetime.now(UTC).isoformat(),
                "nonclaims": ["not a hot restore", "not encrypted", "not production"],
            }
            receipt_dir = self.state_dir / "evidence" / "recovery"
            receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_json_atomic(receipt_dir / f"restore-{expected_manifest_sha256}.json", receipt, mode=0o600)
            return receipt
        except Exception as exc:
            if published_state:
                raise SafetyError(
                    "restore failed after controlled recovery state was published; run destroy before retrying"
                ) from exc
            raise
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _volume_labels(self) -> dict[str, dict[str, str]]:
        names: set[str] = set(volume_names(self.project).values())
        for key, value in ((PROJECT_LABEL, self.project), ("com.docker.compose.project", self.project)):
            raw = self.shell.run("docker", "volume", "ls", "--quiet", "--filter", f"label={key}={value}").stdout
            names.update(line.strip() for line in raw.splitlines() if line.strip())
        result: dict[str, dict[str, str]] = {}
        for name in names:
            inspected = self.shell.run("docker", "volume", "inspect", name, check=False)
            if inspected.returncode:
                continue
            item = json.loads(inspected.stdout)[0]
            result[name] = item.get("Labels") or {}
        return result

    def _labeled_resources(self, kind: str) -> dict[str, dict[str, str]]:
        command = "container" if kind == "container" else "network"
        ids: set[str] = set()
        for key, value in ((PROJECT_LABEL, self.project), ("com.docker.compose.project", self.project)):
            args = ["docker", command, "ls", "--quiet", "--filter", f"label={key}={value}"]
            if command == "container":
                args.insert(3, "--all")
            raw = self.shell.run(*args).stdout
            ids.update(line.strip() for line in raw.splitlines() if line.strip())
        result: dict[str, dict[str, str]] = {}
        for resource_id in ids:
            item = json.loads(self.shell.run("docker", command, "inspect", resource_id).stdout)[0]
            labels = item.get("Config", {}).get("Labels") if command == "container" else item.get("Labels")
            result[item["Name"].lstrip("/")] = labels or {}
        return result

    def _destroy_resources(self) -> None:
        marker = self._verify_marker_and_source()
        expected = set(marker["volumes"].values())
        volume_names_to_remove = verify_destructive_volumes(
            self.project, marker["state_id"], expected, self._volume_labels(), marker["lifecycle"],
        )
        containers = self._labeled_resources("container")
        networks = self._labeled_resources("network")
        verify_destructive_resources(
            self.project, marker["state_id"], containers, networks, marker["lifecycle"]
        )
        self.compose("down", timeout=600)
        remaining_containers = self._labeled_resources("container")
        remaining_networks = self._labeled_resources("network")
        if remaining_containers or remaining_networks:
            raise SafetyError("Compose resources remain after successful down")
        for name in volume_names_to_remove:
            self.shell.run("docker", "volume", "rm", name, cwd=self.runtime)

    def reset(self) -> dict[str, Any]:
        self._require_linux()
        self._destroy_resources()
        for name in ("seed", "evidence"):
            shutil.rmtree(self.state_dir / name, ignore_errors=False)
        for name in (MARKER_NAME, "compose.env"):
            (self.state_dir / name).unlink()
        return self.init()

    def destroy(self) -> dict[str, Any]:
        self._require_linux()
        marker = read_marker(self.state_dir, self.project)
        self._destroy_resources()
        result = {"schema": SCHEMA, "project": self.project, "state_id": marker["state_id"], "lifecycle": "destroyed"}
        shutil.rmtree(self.state_dir)
        return result


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--hrh-root", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", type=int, default=18443)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "up", "status", "stop", "reset", "destroy"):
        sub.add_parser(name)
    refresh = sub.add_parser("refresh-policy")
    refresh.add_argument("--epoch", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("--backup-dir", type=Path, required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--backup-dir", type=Path, required=True)
    restore.add_argument("--expected-manifest-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    staging = ClinicalStaging(args.runtime_root, args.hrh_root, args.state_dir, args.project, args.port)
    try:
        if args.command == "refresh-policy":
            result = staging.refresh_policy(args.epoch)
        elif args.command == "backup":
            result = staging.backup(args.backup_dir)
        elif args.command == "restore":
            result = staging.restore(args.backup_dir, args.expected_manifest_sha256)
        else:
            result = getattr(staging, args.command)()
    except (SafetyError, CommandError) as exc:
        print(f"clinical_staging outcome=denied reason={exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
