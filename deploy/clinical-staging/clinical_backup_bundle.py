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


def verify_recovery_helper_boundary(
    error_type: type[Exception], command: tuple[str, ...], *, source_mount: str,
    backup_mount: str, capabilities: frozenset[str],
) -> None:
    if command[:3] != ("docker", "run", "--rm") or command.count("--read-only") != 1:
        raise error_type("recovery helper command is not ephemeral and read-only")
    expected = {"--network": "none", "--cap-drop": "ALL", "--security-opt": "no-new-privileges:true", "--user": "0:0", "--entrypoint": "sh"}
    if any(command.count(flag) != 1 or command[command.index(flag) + 1] != value for flag, value in expected.items()):
        raise error_type("recovery helper command has an unexpected security authority")
    cap_adds = {command[index + 1] for index, item in enumerate(command[:-1]) if item == "--cap-add"}
    if cap_adds != capabilities or command.count("--cap-add") != len(capabilities):
        raise error_type("recovery helper command has an unexpected security authority")
    mounts = [command[index + 1] for index, item in enumerate(command[:-1]) if item == "--mount"]
    if len(mounts) != 2 or set(mounts) != {source_mount, backup_mount}:
        raise error_type("recovery helper command has an unexpected mount")
    if any(item in command for item in ("--privileged", "-v", "--volume")):
        raise error_type("recovery helper command has an unexpected authority")


def extract_safe_state_archive(contract: BackupContract, archive_path: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:") as archive:
            for member in archive.getmembers():
                name = _safe_archive_name(contract, member.name)
                if not name:
                    if member.isdir():
                        continue
                    raise contract.error_type("backup state archive has an invalid root member")
                if not (member.isdir() or member.isreg()):
                    raise contract.error_type("backup state archive contains a non-regular member")
                target = destination.joinpath(*name.split("/"))
                try:
                    target.resolve().relative_to(destination.resolve())
                except ValueError as exc:
                    raise contract.error_type("backup state archive escapes its destination") from exc
                if member.isdir():
                    target.mkdir(mode=member.mode & 0o777, parents=True, exist_ok=False)
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise contract.error_type("backup state archive member is unreadable")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, member.mode & 0o777)
                with os.fdopen(fd, "wb") as output:
                    shutil.copyfileobj(stream, output)
                    output.flush()
                    os.fsync(output.fileno())
    except (OSError, tarfile.TarError) as exc:
        raise contract.error_type("could not safely restore private state") from exc


PUBLISHED_BACKUP_RECEIPT_SCHEMA = "restricted-synthetic-clinical-cold-backup-receipt-published.v1"
PUBLISHED_RESTORE_RECEIPT_SCHEMA = "restricted-synthetic-clinical-cold-restore-published.v1"
PUBLISHED_CAUSAL_RECEIPT_SCHEMA = "restricted-synthetic-clinical-cold-restore-verification-published.v1"
PUBLISHED_BACKUP_NONCLAIMS = ["not a scheduled backup", "not PHI-authorized", "not production", "not a compliance certification"]
PUBLISHED_RESTORE_NONCLAIMS = ["not a causal recovery verification", "not PHI-authorized", "not production", "not a compliance certification"]
PUBLISHED_CAUSAL_NONCLAIMS = ["not PHI-authorized", "not production", "not a compliance certification"]


def _published_common(
    contract: BackupContract, manifest: Mapping[str, Any], identity: Mapping[str, Any], manifest_sha256: str,
) -> dict[str, Any]:
    try:
        capsule = manifest["recovery_capsule"]
        if manifest["backup_identity_sha256"] != hashlib.sha256(canonical_json_bytes(contract, identity)).hexdigest():
            raise contract.error_type("published receipt identity binding differs")
        if identity["recovery_trust_sha256"] != manifest["recovery_trust_sha256"]:
            raise contract.error_type("published receipt trust authority differs")
        return {
            "project": identity["project"], "state_id": identity["state_id"],
            "manifest_sha256": _require_sha256(contract, manifest_sha256, name="published manifest hash"),
            "backup_identity_sha256": manifest["backup_identity_sha256"], "capsule_id": capsule["capsule_id"],
            "capsule_ciphertext_sha256": capsule["ciphertext_sha256"],
            "backup_recovery_trust_sha256": identity["recovery_trust_sha256"],
            "backup_recovery_policy_epoch": identity["recovery_policy_epoch"],
            "recipient_sha256": identity["recipient_sha256"], "runtime_source": identity["runtime_source"],
            "hrh_candidate": identity["hrh_candidate"], "effective_images": identity["effective_images"],
        }
    except (KeyError, TypeError) as exc:
        raise contract.error_type("published receipt binding is incomplete") from exc


def build_backup_receipt(
    contract: BackupContract, manifest: Mapping[str, Any], backup_dir: Path, *, identity: Mapping[str, Any],
    manifest_sha256: str, backed_up_at: str,
) -> dict[str, Any]:
    del backup_dir
    return {
        "schema": PUBLISHED_BACKUP_RECEIPT_SCHEMA, "synthetic_only": True,
        **_published_common(contract, manifest, identity, manifest_sha256), "mode": "published_backup",
        "capsule_ciphertext_size": manifest["recovery_capsule"]["ciphertext_size"],
        "sealer_sha256": identity["sealer_sha256"], "excluded_volume": identity["excluded_volume"],
        "backed_up_at": backed_up_at, "nonclaims": list(PUBLISHED_BACKUP_NONCLAIMS),
    }


def _recipient_status(contract: BackupContract, trust: Mapping[str, Any], recipient_sha256: str) -> str:
    recipients = trust.get("recipients")
    if not isinstance(recipients, list):
        raise contract.error_type("restore trust authority is invalid")
    matches = [item for item in recipients if isinstance(item, dict) and item.get("recipient_sha256") == recipient_sha256]
    if len(matches) != 1 or matches[0].get("status") not in {"active", "retired"}:
        raise contract.error_type("restore trust authority does not bind recipient")
    return matches[0]["status"]


def build_restore_receipt(
    contract: BackupContract, manifest: Mapping[str, Any], manifest_sha256: str, *, identity: Mapping[str, Any],
    restore_trust: Mapping[str, Any], restore_trust_sha256: str, status_observed_at: str, restored_at: str,
) -> dict[str, Any]:
    return {
        "schema": PUBLISHED_RESTORE_RECEIPT_SCHEMA, "synthetic_only": True,
        **_published_common(contract, manifest, identity, manifest_sha256), "mode": "published_restore",
        "restore_recovery_trust_sha256": _require_sha256(contract, restore_trust_sha256, name="restore trust hash"),
        "restore_recovery_policy_epoch": restore_trust["policy_epoch"],
        "restore_recipient_status": _recipient_status(contract, restore_trust, identity["recipient_sha256"]),
        "excluded_volume": identity["excluded_volume"], "status_observed_at": status_observed_at,
        "verification": "mechanical_restore_only", "restored_at": restored_at,
        "nonclaims": list(PUBLISHED_RESTORE_NONCLAIMS),
    }


_MECHANICAL_FIELDS = {
    "schema", "synthetic_only", "project", "state_id", "mode", "manifest_sha256", "backup_identity_sha256",
    "capsule_id", "capsule_ciphertext_sha256", "backup_recovery_trust_sha256", "backup_recovery_policy_epoch",
    "restore_recovery_trust_sha256", "restore_recovery_policy_epoch", "restore_recipient_status", "recipient_sha256",
    "runtime_source", "hrh_candidate", "effective_images", "excluded_volume", "status_observed_at", "verification",
    "restored_at", "nonclaims",
}


def _closed_mechanical(contract: BackupContract, raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise contract.error_type("duplicate mechanical receipt field")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except contract.error_type:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise contract.error_type("mechanical receipt is invalid") from exc
    if not isinstance(value, dict) or set(value) != _MECHANICAL_FIELDS:
        raise contract.error_type("mechanical receipt fields are not closed")
    return value


def _zulu(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        return False
    try:
        __import__("datetime").datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def validate_causal_receipt(
    contract: BackupContract, mechanical_receipt_bytes: bytes, manifest: Mapping[str, Any], identity: Mapping[str, Any],
    restore_trust: Mapping[str, Any] | None, restore_trust_sha256: str, causal_checks: Mapping[str, bool], *, verified_at: str,
    current_marker: Mapping[str, Any] | None = None, expected_manifest_sha256: str | None = None,
    expected_mechanical_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    mechanical = _closed_mechanical(contract, mechanical_receipt_bytes)
    mechanical_sha256 = hashlib.sha256(mechanical_receipt_bytes).hexdigest()
    if expected_manifest_sha256 is not None and mechanical["manifest_sha256"] != expected_manifest_sha256:
        raise contract.error_type("mechanical receipt does not bind external manifest")
    if expected_mechanical_receipt_sha256 is not None and mechanical_sha256 != expected_mechanical_receipt_sha256:
        raise contract.error_type("mechanical receipt does not bind external authority")
    if current_marker is not None:
        marker_bindings = {
            "project": identity["project"], "state_id": identity["state_id"],
            "runtime_head": identity["runtime_source"]["runtime_head"],
            "runtime_tree": identity["runtime_source"]["runtime_tree"],
            "hrh_candidate": identity["hrh_candidate"], "effective_images": identity["effective_images"],
        }
        if any(current_marker.get(key) != value for key, value in marker_bindings.items()):
            raise contract.error_type("current marker does not bind published identity")
    common = _published_common(contract, manifest, identity, mechanical["manifest_sha256"])
    if restore_trust is None:
        restore_epoch = mechanical.get("restore_recovery_policy_epoch")
        restore_status = mechanical.get("restore_recipient_status")
    else:
        restore_epoch = restore_trust.get("policy_epoch")
        restore_status = _recipient_status(contract, restore_trust, identity["recipient_sha256"])
    if (
        not re.fullmatch(r"[0-9a-f]{64}", restore_trust_sha256)
        or isinstance(restore_epoch, bool) or not isinstance(restore_epoch, int)
        or restore_epoch < identity["recovery_policy_epoch"]
        or restore_status not in {"active", "retired"}
    ):
        raise contract.error_type("restore trust authority is invalid")
    expected = {
        **common, "schema": PUBLISHED_RESTORE_RECEIPT_SCHEMA, "synthetic_only": True, "mode": "published_restore",
        "restore_recovery_trust_sha256": restore_trust_sha256,
        "restore_recovery_policy_epoch": restore_epoch,
        "restore_recipient_status": restore_status,
        "excluded_volume": identity["excluded_volume"], "verification": "mechanical_restore_only",
        "nonclaims": PUBLISHED_RESTORE_NONCLAIMS,
    }
    for key, value in expected.items():
        if mechanical.get(key) != value:
            raise contract.error_type(f"mechanical receipt does not bind {key}")
    if not _zulu(mechanical["status_observed_at"]) or not _zulu(mechanical["restored_at"]):
        raise contract.error_type("mechanical receipt time authority is invalid")
    return {
        **{key: mechanical[key] for key in (
            "project", "state_id", "manifest_sha256", "backup_identity_sha256", "capsule_id",
            "capsule_ciphertext_sha256", "backup_recovery_trust_sha256", "backup_recovery_policy_epoch",
            "restore_recovery_trust_sha256", "restore_recovery_policy_epoch", "restore_recipient_status",
            "recipient_sha256", "runtime_source", "hrh_candidate", "effective_images",
        )},
        "schema": PUBLISHED_CAUSAL_RECEIPT_SCHEMA, "synthetic_only": True,
        "mode": "published_restore_verification", "mechanical_receipt_sha256": mechanical_sha256,
        "verification": "causal_e2e_verified", "causal_checks": dict(causal_checks), "verified_at": verified_at,
        "nonclaims": list(PUBLISHED_CAUSAL_NONCLAIMS),
    }


def build_causal_receipt(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Build only from the same closed inputs accepted by the pure validator."""
    return validate_causal_receipt(*args, **kwargs)
