"""Cold backup-bundle codec with explicit, immutable dependencies."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import secrets
import shutil
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


@dataclass(frozen=True)
class BackupContract:
    error_type: type[Exception]
    schema: str
    marker_name: str
    backup_schema: str
    manifest_name: str
    complete_name: str
    state_archive_name: str
    volume_directory: str
    volume_keys: tuple[str, ...]
    backup_volume_keys: tuple[str, ...]
    excluded_volume: str
    required_hrh_head: str
    required_hrh_tree: str
    volume_names: Callable[[str], dict[str, str]]
    validate_project: Callable[[str], str]
    fsync_file: Callable[[Path], None]
    fsync_directory: Callable[[Path], None]
    write_json_atomic: Callable[..., None]


def file_sha256(contract: BackupContract, path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise contract.error_type(f"required file is unavailable: {path.name}") from exc


def canonical_json_bytes(contract: BackupContract, value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _require_sha256(contract: BackupContract, value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value):
        raise contract.error_type(f"{name} must be a lowercase SHA-256")
    return value


def _backup_member_names(contract: BackupContract) -> tuple[str, ...]:
    return (
        contract.manifest_name,
        contract.complete_name,
        contract.state_archive_name,
        *(
            f"{contract.volume_directory}/{key}.tar"
            for key in contract.backup_volume_keys
        ),
    )


def _safe_archive_name(contract: BackupContract, name: str) -> str:
    """Return a normalized relative tar member name or fail before extraction."""
    if not isinstance(name, str) or not name or "\\" in name or name.startswith("/"):
        raise contract.error_type("backup archive contains an unsafe path")
    normalized = posixpath.normpath(name)
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        return ""
    if normalized == ".." or normalized.startswith("../") or normalized.startswith("/"):
        raise contract.error_type("backup archive contains a path traversal member")
    if any((part in {"", ".", ".."} for part in normalized.split("/"))):
        raise contract.error_type("backup archive contains an unsafe path")
    return normalized


def inspect_safe_tar(
    contract: BackupContract, path: Path, *, require_regular_file: bool
) -> tuple[str, ...]:
    """Validate an archive without extracting it into an operator destination."""
    try:
        with tarfile.open(path, "r:") as archive:
            names: list[str] = []
            has_regular = False
            for member in archive.getmembers():
                name = _safe_archive_name(contract, member.name)
                if not name:
                    if member.isdir():
                        continue
                    raise contract.error_type(
                        "backup archive has an invalid root member"
                    )
                if not (member.isdir() or member.isreg()):
                    raise contract.error_type(
                        "backup archive contains a link or special member"
                    )
                if name in names:
                    raise contract.error_type(
                        "backup archive contains duplicate members"
                    )
                names.append(name)
                has_regular = has_regular or member.isreg()
    except (OSError, tarfile.TarError) as exc:
        raise contract.error_type("backup archive is unreadable or corrupt") from exc
    if require_regular_file and (not has_regular):
        raise contract.error_type("backup archive does not contain a regular file")
    return tuple(sorted(names))


def archive_ownership_sha256(contract: BackupContract, path: Path) -> str:
    """Bind archive ownership/mode metadata without disclosing member paths."""
    try:
        with tarfile.open(path, "r:") as archive:
            records: list[dict[str, Any]] = []
            for member in archive.getmembers():
                name = _safe_archive_name(contract, member.name)
                if not name:
                    if member.isdir():
                        continue
                    raise contract.error_type(
                        "backup archive has an invalid root member"
                    )
                if not (member.isdir() or member.isreg()):
                    raise contract.error_type(
                        "backup archive contains a link or special member"
                    )
                records.append(
                    {
                        "name": name,
                        "kind": "directory" if member.isdir() else "file",
                        "uid": member.uid,
                        "gid": member.gid,
                        "mode": member.mode & 4095,
                    }
                )
    except (OSError, tarfile.TarError) as exc:
        raise contract.error_type("backup archive is unreadable or corrupt") from exc
    return hashlib.sha256(
        canonical_json_bytes(
            contract, {"entries": sorted(records, key=lambda item: item["name"])}
        )
    ).hexdigest()


def _iter_safe_tree(
    contract: BackupContract, root: Path
) -> Iterable[tuple[Path, str, os.stat_result]]:
    """Yield a deterministic, symlink-free tree for the private state archive."""
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            path = current_path / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise contract.error_type(
                    "state directory contains a link or special file"
                )
            yield (path, relative, info)


def create_state_archive(
    contract: BackupContract, state_dir: Path, archive_path: Path
) -> None:
    """Archive only regular private state files with explicit metadata."""
    if archive_path.exists():
        raise contract.error_type("backup state archive already exists")
    try:
        with tarfile.open(archive_path, "x") as archive:
            for path, relative, info in _iter_safe_tree(contract, state_dir):
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
        raise contract.error_type("could not write private state archive") from exc
    inspect_safe_tar(contract, archive_path, require_regular_file=True)
    contract.fsync_file(archive_path)


def _manifest_members(
    contract: BackupContract, backup_dir: Path
) -> dict[str, dict[str, Any]]:
    members: dict[str, dict[str, Any]] = {}
    for name in _backup_member_names(contract):
        if name in {contract.manifest_name, contract.complete_name}:
            continue
        path = backup_dir / name
        if not path.is_file():
            raise contract.error_type(f"backup member is missing: {name}")
        members[name] = {
            "sha256": file_sha256(contract, path),
            "size": path.stat().st_size,
            "ownership_sha256": archive_ownership_sha256(contract, path),
        }
    return members


def build_backup_manifest(
    contract: BackupContract,
    marker: Mapping[str, Any],
    state_dir: Path,
    backup_dir: Path,
) -> dict[str, Any]:
    """Create the content-safe manifest; its SHA is recorded externally by the operator."""
    members = _manifest_members(contract, backup_dir)
    return {
        "schema": contract.backup_schema,
        "synthetic_only": True,
        "complete": True,
        "project": marker["project"],
        "state_id": marker["state_id"],
        "state_dir": str(state_dir.resolve()),
        "compose_env_sha256": marker["compose_env_sha256"],
        "source": {
            key: marker[key]
            for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")
        },
        "expected_images": dict(marker["expected_images"]),
        "volumes": dict(marker["volumes"]),
        "excluded_volume": contract.excluded_volume,
        "members": members,
    }


def write_backup_manifest(
    contract: BackupContract, backup_dir: Path, manifest: Mapping[str, Any]
) -> None:
    contract.write_json_atomic(backup_dir / contract.manifest_name, manifest, mode=384)


def write_backup_completion(contract: BackupContract, backup_dir: Path) -> None:
    path = backup_dir / contract.complete_name
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"complete\n")
            stream.flush()
            os.fsync(stream.fileno())
        contract.fsync_directory(backup_dir)
    except OSError as exc:
        raise contract.error_type("could not publish backup completion marker") from exc


def _read_backup_manifest(contract: BackupContract, backup_dir: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            (backup_dir / contract.manifest_name).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise contract.error_type("backup manifest is missing or invalid") from exc
    if not isinstance(value, dict):
        raise contract.error_type("backup manifest must be an object")
    return value


def _validate_backup_manifest_shape(
    contract: BackupContract,
    manifest: Mapping[str, Any],
    *,
    project: str,
    state_dir: Path,
) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "synthetic_only",
        "complete",
        "project",
        "state_id",
        "state_dir",
        "compose_env_sha256",
        "source",
        "expected_images",
        "volumes",
        "excluded_volume",
        "members",
    }
    if set(manifest) != expected_keys:
        raise contract.error_type("backup manifest has unknown or missing fields")
    if (
        manifest["schema"] != contract.backup_schema
        or manifest["synthetic_only"] is not True
        or manifest["complete"] is not True
        or (manifest["project"] != project)
        or (manifest["state_dir"] != str(state_dir.resolve()))
        or (manifest["excluded_volume"] != contract.excluded_volume)
        or (not re.fullmatch("[a-f0-9]{32}", str(manifest["state_id"])))
        or (not isinstance(manifest["expected_images"], dict))
        or (manifest["volumes"] != contract.volume_names(project))
    ):
        raise contract.error_type(
            "backup manifest does not bind the requested synthetic target"
        )
    _require_sha256(
        contract, manifest["compose_env_sha256"], name="backup compose environment hash"
    )
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {
        "runtime_head",
        "runtime_tree",
        "hrh_head",
        "hrh_tree",
    }:
        raise contract.error_type("backup source frame is invalid")
    for key, value in source.items():
        if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{40}", value):
            raise contract.error_type(f"backup source frame has an invalid {key}")
    if (
        source["hrh_head"] != contract.required_hrh_head
        or source["hrh_tree"] != contract.required_hrh_tree
    ):
        raise contract.error_type(
            "backup source frame does not match the required HRH source"
        )
    expected_members = set(_backup_member_names(contract)) - {
        contract.manifest_name,
        contract.complete_name,
    }
    members = manifest["members"]
    if not isinstance(members, dict) or set(members) != expected_members:
        raise contract.error_type("backup manifest members are not the exact allowlist")
    for name, value in members.items():
        if not isinstance(value, dict) or set(value) != {
            "sha256",
            "size",
            "ownership_sha256",
        }:
            raise contract.error_type(
                f"backup manifest member metadata is invalid: {name}"
            )
        _require_sha256(
            contract, value["sha256"], name=f"backup member hash for {name}"
        )
        _require_sha256(
            contract,
            value["ownership_sha256"],
            name=f"backup ownership hash for {name}",
        )
        if not isinstance(value["size"], int) or value["size"] <= 0:
            raise contract.error_type(f"backup member size is invalid: {name}")
    return dict(manifest)


def _archive_member_bytes(contract: BackupContract, path: Path, name: str) -> bytes:
    try:
        with tarfile.open(path, "r:") as archive:
            matching = [
                member
                for member in archive.getmembers()
                if _safe_archive_name(contract, member.name) == name
            ]
            if len(matching) != 1 or not matching[0].isreg():
                raise contract.error_type(
                    "backup state archive does not contain the required marker"
                )
            stream = archive.extractfile(matching[0])
            if stream is None:
                raise contract.error_type("backup state archive member is unreadable")
            return stream.read()
    except (OSError, tarfile.TarError) as exc:
        raise contract.error_type("backup state archive is unreadable") from exc


def _validate_archived_marker(
    contract: BackupContract,
    state_archive: Path,
    *,
    project: str,
    state_dir: Path,
    manifest: Mapping[str, Any],
) -> None:
    inspect_safe_tar(contract, state_archive, require_regular_file=True)
    try:
        marker = json.loads(
            _archive_member_bytes(contract, state_archive, contract.marker_name)
        )
    except json.JSONDecodeError as exc:
        raise contract.error_type("backup state marker is invalid") from exc
    if not isinstance(marker, dict):
        raise contract.error_type("backup state marker is invalid")
    expected_keys = {
        "schema",
        "synthetic_only",
        "project",
        "state_dir",
        "state_id",
        "compose_env_sha256",
        "lifecycle",
        "runtime_head",
        "runtime_tree",
        "hrh_head",
        "hrh_tree",
        "volumes",
        "expected_images",
    }
    if set(marker) != expected_keys:
        raise contract.error_type("backup state marker has unknown or missing fields")
    if (
        marker["schema"] != contract.schema
        or marker["synthetic_only"] is not True
        or marker["project"] != project
        or (marker["state_dir"] != str(state_dir.resolve()))
        or (marker["state_id"] != manifest["state_id"])
        or (marker["compose_env_sha256"] != manifest["compose_env_sha256"])
        or (marker["lifecycle"] != "stopped")
        or (marker["volumes"] != manifest["volumes"])
        or (marker["expected_images"] != manifest["expected_images"])
    ):
        raise contract.error_type("backup state marker conflicts with the manifest")
    for key, value in manifest["source"].items():
        if marker[key] != value:
            raise contract.error_type(
                "backup state marker source frame conflicts with the manifest"
            )


def validate_backup_bundle(
    contract: BackupContract,
    backup_dir: Path,
    expected_manifest_sha256: str,
    project: str,
    state_dir: Path,
) -> dict[str, Any]:
    """Validate every recovery input while the destination remains untouched."""
    contract.validate_project(project)
    backup_dir = backup_dir.resolve()
    if not backup_dir.is_dir():
        raise contract.error_type("backup directory is unavailable")
    _require_sha256(contract, expected_manifest_sha256, name="external manifest hash")
    completion_path = backup_dir / contract.complete_name
    try:
        completed = completion_path.read_bytes()
    except OSError as exc:
        raise contract.error_type("backup complete marker is missing") from exc
    if completed != b"complete\n":
        raise contract.error_type("backup complete marker is invalid")
    entries = list(backup_dir.rglob("*"))
    if any((item.is_symlink() for item in entries)):
        raise contract.error_type("backup directory must not contain symbolic links")
    actual_members = {
        item.relative_to(backup_dir).as_posix() for item in entries if item.is_file()
    }
    actual_directories = {
        item.relative_to(backup_dir).as_posix() for item in entries if item.is_dir()
    }
    expected_members = set(_backup_member_names(contract))
    if actual_members != expected_members:
        raise contract.error_type("backup directory has unexpected or missing members")
    if actual_directories != {contract.volume_directory}:
        raise contract.error_type(
            "backup directory has unexpected or missing directories"
        )
    manifest_path = backup_dir / contract.manifest_name
    if file_sha256(contract, manifest_path) != expected_manifest_sha256:
        raise contract.error_type("external manifest hash does not match the backup")
    manifest = _validate_backup_manifest_shape(
        contract,
        _read_backup_manifest(contract, backup_dir),
        project=project,
        state_dir=state_dir,
    )
    for name, metadata in manifest["members"].items():
        member_path = backup_dir / name
        if (
            member_path.stat().st_size != metadata["size"]
            or file_sha256(contract, member_path) != metadata["sha256"]
            or archive_ownership_sha256(contract, member_path)
            != metadata["ownership_sha256"]
        ):
            raise contract.error_type(f"backup member hash or size differs: {name}")
    _validate_archived_marker(
        contract,
        backup_dir / contract.state_archive_name,
        project=project,
        state_dir=state_dir,
        manifest=manifest,
    )
    for key in contract.backup_volume_keys:
        inspect_safe_tar(
            contract,
            backup_dir / contract.volume_directory / f"{key}.tar",
            require_regular_file=True,
        )
    return manifest


def _copy_regular_file(
    contract: BackupContract, source: Path, destination: Path
) -> None:
    """Copy one archive input through a no-follow descriptor into private storage."""
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, os.O_RDONLY | no_follow)
    except OSError as exc:
        raise contract.error_type(
            f"backup input is unavailable or unsafe: {source.name}"
        ) from exc
    try:
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise contract.error_type(
                f"backup input is not a regular file: {source.name}"
            )
        try:
            destination_fd = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384
            )
        except OSError as exc:
            raise contract.error_type(
                f"could not create private backup snapshot: {destination.name}"
            ) from exc
        try:
            with (
                os.fdopen(source_fd, "rb", closefd=False) as input_stream,
                os.fdopen(destination_fd, "wb") as output_stream,
            ):
                shutil.copyfileobj(input_stream, output_stream)
                output_stream.flush()
                os.fsync(output_stream.fileno())
        except OSError as exc:
            raise contract.error_type(
                f"could not copy backup input: {source.name}"
            ) from exc
    finally:
        os.close(source_fd)


def materialize_backup_snapshot(
    contract: BackupContract,
    backup_dir: Path,
    snapshot_parent: Path,
    *,
    snapshot_stem: str,
) -> Path:
    """Copy the complete bundle before validation so later restore reads are immutable.

    The external directory is deliberately never consumed after this function
    returns.  The externally supplied manifest digest binds the snapshot's
    manifest; member digests then bind its archives before any destination or
    Docker mutation is allowed.
    """
    backup_dir = backup_dir.resolve()
    if not backup_dir.is_dir():
        raise contract.error_type("backup directory is unavailable")
    if not snapshot_parent.is_dir():
        raise contract.error_type("restore state parent directory must already exist")
    expected_root_files = {
        contract.manifest_name,
        contract.complete_name,
        contract.state_archive_name,
    }
    try:
        root_entries = {item.name: item for item in backup_dir.iterdir()}
    except OSError as exc:
        raise contract.error_type("backup directory is unreadable") from exc
    if set(root_entries) != expected_root_files | {contract.volume_directory}:
        raise contract.error_type("backup directory has unexpected or missing members")
    if (
        any((item.is_symlink() for item in root_entries.values()))
        or not root_entries[contract.volume_directory].is_dir()
    ):
        raise contract.error_type("backup directory contains an unsafe member")
    try:
        volume_entries = {
            item.name: item
            for item in root_entries[contract.volume_directory].iterdir()
        }
    except OSError as exc:
        raise contract.error_type("backup volume directory is unreadable") from exc
    expected_volume_files = {f"{key}.tar" for key in contract.backup_volume_keys}
    if set(volume_entries) != expected_volume_files or any(
        (item.is_symlink() for item in volume_entries.values())
    ):
        raise contract.error_type("backup directory has unexpected or missing members")
    snapshot = snapshot_parent / f".{snapshot_stem}.bundle-{secrets.token_hex(8)}"
    try:
        snapshot.mkdir(mode=448)
        (snapshot / contract.volume_directory).mkdir(mode=448)
        for name in sorted(expected_root_files):
            _copy_regular_file(contract, root_entries[name], snapshot / name)
        for name in sorted(expected_volume_files):
            _copy_regular_file(
                contract,
                volume_entries[name],
                snapshot / contract.volume_directory / name,
            )
        contract.fsync_directory(snapshot / contract.volume_directory)
        contract.fsync_directory(snapshot)
        return snapshot
    except Exception:
        if snapshot.exists():
            shutil.rmtree(snapshot)
        raise
