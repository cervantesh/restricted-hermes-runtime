#!/usr/bin/env python3
"""Synthetic-only operator lifecycle for the composed clinical witness."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import functools
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


_STAGING_MODULE_DIR = str(Path(__file__).resolve().parent)
if _STAGING_MODULE_DIR not in sys.path:
    sys.path.insert(0, _STAGING_MODULE_DIR)
from clinical_operator_lock import OperatorLockError, operator_lock_path, persistent_operator_lock
import clinical_hrh_mode as hrh_mode
import clinical_recovery_capsule as recovery_codec
from clinical_recovery_capsule import add_finalizer_arguments, add_recovery_arguments, dispatch_recovery_command, validate_recovery_arguments
from clinical_tls import TlsError, generate_material as _certificate_material, renew as _renew_tls

RUNTIME_BASE_SHA = "41464aee8748f857153ba2b47377515d4847d210"
REQUIRED_HRH_SHA = "e30a4f968de6727519f49c08369f561fdf269ec5"
REQUIRED_HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"
HRH_WEB_CANDIDATE_DOCKERFILE = "Dockerfile.web.clinical-candidate"
HRH_MIGRATE_CANDIDATE_DOCKERFILE = "Dockerfile.migrate.clinical-candidate"
HRH_NODE_BASE = "node:24-alpine@sha256:4caaaf42195bcd6f6f3559a413b20cb8f8ad089e231ee874cf7701643966689f"
HRH_MIGRATE_BASE = "alpine:3.21@sha256:f27cad9117495d32d067133afff942cb2dc745dfe9163e949f6bfe8a6a245339"
HRH_CANDIDATE_BASES = {
    HRH_WEB_CANDIDATE_DOCKERFILE: (HRH_NODE_BASE, HRH_NODE_BASE, HRH_NODE_BASE),
    HRH_MIGRATE_CANDIDATE_DOCKERFILE: (HRH_MIGRATE_BASE,),
}
SCHEMA = "restricted-synthetic-clinical-staging.v1"
MARKER_NAME = "staging-state.json"
INIT_ORPHAN_RE_TEMPLATE = r"^\.{state}\.init-[a-f0-9]{{16}}$"
MAX_INITIALIZATION_ORPHANS = 8
MAX_ABANDONED_ATOMIC_TEMPS = 8
PROJECT_LABEL = "io.cervantesh.restricted-runtime.project"
STATE_LABEL = "io.cervantesh.restricted-runtime.state-id"
SYNTHETIC_LABEL = "io.cervantesh.restricted-runtime.synthetic-clinical"
PROJECT_RE = re.compile(r"^clinicalstaging[a-z0-9]{1,32}$")
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)", re.MULTILINE | re.IGNORECASE)
COMPOSE_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SAFE_COMPOSE_PROCESS_ENV = (
    "PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
    "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR",
)
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
CAUSAL_RECOVERY_CHECKS = frozenset({
    "source_deletion_persisted",
    "unknown_delivery_is_ambiguous_once",
    "already_delivered_not_redelivered",
    "isolation_preserved",
    "expired_policy_fails_closed",
    "artifacts_clean",
    "duration_bounded",
})
# This is also the pinned PostgreSQL image used by the composed witness. It
# supplies GNU tar inside a networkless, ephemeral helper for volume exports.
RECOVERY_HELPER_IMAGE = (
    "postgres:17.10-bookworm@sha256:"
    "9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f"
)
INGRESS_READY_TIMEOUT_SECONDS = 60
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


def _serialized_mutator(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        try:
            with persistent_operator_lock(self.state_dir, self.project):
                if self._persisted_command is not None:
                    self._bind_fresh_marker()
                try:
                    return method(self, *args, **kwargs)
                finally:
                    self._locked_marker = None
        except OperatorLockError as exc:
            raise SafetyError(str(exc)) from exc
    return wrapped


_operator_lock = persistent_operator_lock  # Test seam for the shared boundary.


class Shell:
    def run(
        self,
        *args: str,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        if check and result.returncode:
            # Child output can contain credentials (or values derived from them).
            # Do not turn it into operator/CI output by copying it into the
            # exception.  This wrapper deliberately keeps no secondary
            # diagnostic receipt: its only public contract is a fixed command
            # class and exit code.
            command = Path(args[0]).name if args and Path(args[0]).name in {"docker", "git"} else "child"
            raise CommandError(f"command failed: {command} exit={result.returncode}")
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


def fsync_file(path: Path) -> None:
    """Durably flush an already-created regular recovery artifact."""
    if os.name != "posix":
        return
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SafetyError(f"could not fsync recovery artifact: {path.name}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SafetyError(f"recovery artifact is not a regular file: {path.name}")
        os.fsync(fd)
    except OSError as exc:
        raise SafetyError(f"could not fsync recovery artifact: {path.name}") from exc
    finally:
        os.close(fd)


def _assert_owned_regular(path: Path, *, mode: int, label: str) -> os.stat_result:
    """Return a no-follow stat only for the private files this wrapper owns."""
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise SafetyError(f"{label} is not a regular file")
    if os.name == "posix" and (
        metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise SafetyError(f"{label} is not an operator-owned mode-{mode:04o} file")
    return metadata


def _open_owned_lock(path: Path) -> int:
    """Open a persistent private advisory-lock file without following links."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(path, flags | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        _assert_owned_regular(path, mode=0o600, label="staging lock")
        fd = os.open(path, flags)
    try:
        if created and hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SafetyError("staging lock is not a regular file")
        if os.name == "posix" and (
            metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise SafetyError("staging lock is not an operator-owned mode-0600 file")
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _exclusive_operator_lock(path: Path) -> Iterator[None]:
    """Serialize recovery through a kernel-released, no-follow operator lock."""
    fd = _open_owned_lock(path)
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _discard_abandoned_atomic_temps(path: Path, *, mode: int) -> None:
    """Remove bounded wrapper-owned atomic temps only while their writer lock is held."""
    legacy = path.with_name(path.name + ".tmp")
    current_expression = re.compile(rf"^\.{re.escape(path.name)}\.tmp-[a-f0-9]{{32}}$")
    candidates = [legacy]
    candidates.extend(entry for entry in path.parent.iterdir() if current_expression.fullmatch(entry.name))
    present: list[Path] = []
    for candidate in candidates:
        try:
            _assert_owned_regular(candidate, mode=mode, label="abandoned atomic temporary")
        except FileNotFoundError:
            continue
        present.append(candidate)
    if len(present) > MAX_ABANDONED_ATOMIC_TEMPS:
        raise SafetyError("too many abandoned atomic temporaries; refusing unsafe cleanup")
    for candidate in present:
        candidate.unlink()
    if present:
        fsync_directory(path.parent)


def _atomic_lock_path(path: Path) -> Path:
    """Keep writer synchronization outside portable state/backup artifacts."""
    identity = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()
    return operator_lock_path(path.parent, f"atomic-{identity}")


def write_json_atomic(path: Path, value: Mapping[str, Any], *, mode: int) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    lock_path = _atomic_lock_path(path)
    with _exclusive_operator_lock(lock_path):
        # Releases before this change could leave this fixed name behind after
        # SIGKILL.  The lock makes cleanup non-racy; ownership/type checks make
        # a planted link or foreign file fail closed instead of being removed.
        _discard_abandoned_atomic_temps(path, mode=mode)
        tmp = path.with_name(f".{path.name}.tmp-{secrets.token_hex(16)}")
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            fsync_directory(path.parent)
        finally:
            try:
                _assert_owned_regular(tmp, mode=mode, label="atomic temporary")
            except FileNotFoundError:
                pass
            else:
                tmp.unlink()


def read_marker(state_dir: Path, project: str) -> dict[str, Any]:
    state_dir = validate_state_path(state_dir, project)
    path = state_dir / MARKER_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("closed staging marker is missing or invalid") from exc
    if isinstance(value, dict) and value.get("schema") == hrh_mode.PUBLISHED_MARKER_SCHEMA:
        try:
            return hrh_mode.validate_published_marker(
                value, project=project, state_dir=state_dir,
                expected_volumes=volume_names(project),
            )
        except hrh_mode.ModeError as exc:
            raise SafetyError(str(exc)) from exc
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
        or value["lifecycle"] not in {"initializing", "finalizing", "recovering", "ready", "stopped", "renewing_tls", "tls_prepared"}
        or not isinstance(value["expected_images"], dict)
    ):
        raise SafetyError("staging marker does not match the requested synthetic target")
    return value


from clinical_backup_bundle import (
    BackupContract,
    _read_backup_manifest as _codec_read_backup_manifest,
    _require_sha256 as _codec_require_sha256,
    _safe_archive_name as _codec_safe_archive_name,
    archive_ownership_sha256 as _codec_archive_ownership_sha256,
    build_backup_manifest as _codec_build_backup_manifest,
    build_backup_receipt as _codec_build_backup_receipt,
    build_causal_receipt as _codec_build_causal_receipt,
    validate_causal_receipt as _codec_validate_causal_receipt,
    build_restore_receipt as _codec_build_restore_receipt,
    canonical_json_bytes as _codec_canonical_json_bytes,
    create_state_archive as _codec_create_state_archive,
    extract_safe_state_archive as _codec_extract_safe_state_archive,
    file_sha256 as _codec_file_sha256,
    inspect_safe_tar as _codec_inspect_safe_tar,
    materialize_backup_snapshot as _codec_materialize_backup_snapshot,
    validate_backup_bundle as _codec_validate_backup_bundle,
    verify_recovery_helper_boundary as _codec_verify_recovery_helper_boundary,
    write_backup_completion as _codec_write_backup_completion,
    write_backup_manifest as _codec_write_backup_manifest,
)


def _backup_contract() -> BackupContract:
    return BackupContract(
        error_type=SafetyError,
        schema=SCHEMA,
        marker_name=MARKER_NAME,
        backup_schema=BACKUP_SCHEMA,
        manifest_name=BACKUP_MANIFEST_NAME,
        complete_name=BACKUP_COMPLETE_NAME,
        state_archive_name=BACKUP_STATE_ARCHIVE,
        volume_directory=BACKUP_VOLUME_DIR,
        volume_keys=VOLUME_KEYS,
        backup_volume_keys=BACKED_UP_VOLUME_KEYS,
        excluded_volume=EXCLUDED_RECOVERY_VOLUME,
        required_hrh_head=REQUIRED_HRH_SHA,
        required_hrh_tree=REQUIRED_HRH_TREE,
        volume_names=volume_names,
        validate_project=validate_project,
        fsync_file=fsync_file,
        fsync_directory=fsync_directory,
        write_json_atomic=write_json_atomic,
    )


def file_sha256(path: Path) -> str:
    return _codec_file_sha256(_backup_contract(), path)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return _codec_canonical_json_bytes(_backup_contract(), value)


def _require_sha256(value: Any, *, name: str) -> str:
    return _codec_require_sha256(_backup_contract(), value, name=name)


def _read_backup_manifest(backup_dir: Path) -> dict[str, Any]:
    return _codec_read_backup_manifest(_backup_contract(), backup_dir)


def _safe_archive_name(name: str) -> str:
    return _codec_safe_archive_name(_backup_contract(), name)


def inspect_safe_tar(path: Path, *, require_regular_file: bool) -> tuple[str, ...]:
    return _codec_inspect_safe_tar(_backup_contract(), path, require_regular_file=require_regular_file)


def archive_ownership_sha256(path: Path) -> str:
    return _codec_archive_ownership_sha256(_backup_contract(), path)


def create_state_archive(state_dir: Path, archive_path: Path) -> None:
    return _codec_create_state_archive(_backup_contract(), state_dir, archive_path)


def build_backup_manifest(
    marker: Mapping[str, Any], state_dir: Path, backup_dir: Path,
) -> dict[str, Any]:
    return _codec_build_backup_manifest(_backup_contract(), marker, state_dir, backup_dir)


def write_backup_manifest(backup_dir: Path, manifest: Mapping[str, Any]) -> None:
    return _codec_write_backup_manifest(_backup_contract(), backup_dir, manifest)


def write_backup_completion(backup_dir: Path) -> None:
    return _codec_write_backup_completion(_backup_contract(), backup_dir)


def validate_backup_bundle(backup_dir: Path, expected_manifest_sha256: str, project: str, state_dir: Path) -> dict[str, Any]:
    return _codec_validate_backup_bundle(_backup_contract(), backup_dir, expected_manifest_sha256, project, state_dir)


def materialize_backup_snapshot(backup_dir: Path, snapshot_parent: Path, *, snapshot_stem: str) -> Path:
    return _codec_materialize_backup_snapshot(_backup_contract(), backup_dir, snapshot_parent, snapshot_stem=snapshot_stem)


verify_recovery_helper_boundary = functools.partial(_codec_verify_recovery_helper_boundary, SafetyError)


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


def verify_hrh_candidate_build_inputs(hrh: Path) -> None:
    """Fail before Compose when the frozen HRH build recipes are not closed."""
    for name, expected in HRH_CANDIDATE_BASES.items():
        try:
            images = tuple(match.group("image") for match in FROM_RE.finditer((hrh / name).read_text(encoding="utf-8")))
        except OSError as exc:
            raise SafetyError("candidate HRH Dockerfile is unavailable") from exc
        if not images or any("@sha256:" not in image for image in images):
            raise SafetyError("candidate HRH Dockerfile contains a mutable base")
        if images != expected:
            raise SafetyError("candidate HRH Dockerfile base digest differs from the frozen contract")


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
    if lifecycle in {"finalizing", "ready", "stopped"} and set(discovered) != expected:
        raise SafetyError("finalizing/ready/stopped staging requires the exact volume set")
    if lifecycle not in {"initializing", "finalizing", "recovering", "ready", "stopped", "renewing_tls", "tls_prepared"}:
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
    if lifecycle in {"finalizing", "ready"}:
        if "controller" in services:
            raise SafetyError("controller must be absent from finalizing/ready staging")
        expected_services = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(services) != expected_services:
            raise SafetyError("finalizing/ready staging requires the exact service set")
        if set(networks) != allowed_networks:
            raise SafetyError("finalizing/ready staging requires the exact network set")
    elif lifecycle == "stopped":
        # A normal stop retains the exact Compose resources, while a cold
        # backup intentionally tears them down after final quiescence.  Either
        # complete shape is destroyable; a partial shape is never accepted.
        if services or networks:
            if "controller" in services:
                raise SafetyError("controller must be absent from stopped staging")
            expected_services = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
            if set(services) != expected_services:
                raise SafetyError("stopped staging requires the exact service set or no resources")
            if set(networks) != allowed_networks:
                raise SafetyError("stopped staging requires the exact network set or no resources")
    elif lifecycle in {"recovering", "renewing_tls", "tls_prepared"}:
        # A failed restore is deliberately non-operational and may have only a
        # bounded partial stack.  It remains eligible solely for controlled
        # destroy; `up` never accepts this lifecycle.
        pass
    elif lifecycle == "initializing":
        pass
    else:
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


class ClinicalStaging:
    def __init__(self, runtime: Path, hrh: Path | None, state_dir: Path, project: str, port: int, shell: Shell | None = None, mode_plan: hrh_mode.HRHModePlan | None = None, persisted_command: str | None = None):
        self.runtime = runtime.resolve()
        marker = read_marker(state_dir, project) if persisted_command is not None else None
        if marker is not None:
            mode_plan = hrh_mode.persisted_plan(persisted_command, hrh, marker, os.environ)
        self.mode_plan = mode_plan or hrh_mode.HRHModePlan("init", "source-build", source_root=hrh)
        self._persisted_command, self._locked_marker = persisted_command, None
        self.hrh = hrh.resolve() if hrh is not None else None
        self.project = validate_project(project)
        forbidden = (self.runtime,) if self.hrh is None else (self.runtime, self.hrh)
        self.state_dir = validate_state_path(
            state_dir,
            project,
            forbidden_roots=forbidden,
        )
        if not 1024 <= port <= 65535:
            raise SafetyError("Mattermost loopback port must be 1024..65535")
        self.port = port
        self.shell = shell or Shell()
        self.base_compose = self.runtime / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"
        self.hrh_overlay = (
            self.runtime
            / "tests"
            / "deployment"
            / "clinical-composed-e2e"
            / self.mode_plan.overlay
        )
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
            "--file", str(self.hrh_overlay),
            "--file", str(self.overlay),
        )

    def _sealed_compose_environment(self) -> dict[str, str]:
        try:
            lines = self.env_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise SafetyError("sealed compose environment is unavailable") from exc
        sealed: dict[str, str] = {}
        for line in lines:
            if not line or "=" not in line:
                raise SafetyError("sealed compose environment is malformed")
            key, value = line.split("=", 1)
            if not COMPOSE_ENV_RE.fullmatch(key) or key in sealed:
                raise SafetyError("sealed compose environment is malformed")
            sealed[key] = value
        if not sealed:
            raise SafetyError("sealed compose environment is empty")
        process = {key: os.environ[key] for key in SAFE_COMPOSE_PROCESS_ENV if key in os.environ}
        process.update(sealed)
        return process

    def compose(self, *args: str, check: bool = True, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
        args = hrh_mode.compose_arguments(self.mode_plan, args)
        return self.shell.run(*self._compose_args(), *args, cwd=self.runtime, env=self._sealed_compose_environment(), check=check, timeout=timeout)

    def _bind_fresh_marker(self) -> None:
        marker = read_marker(self.state_dir, self.project)
        self.mode_plan = hrh_mode.persisted_plan(self._persisted_command, self.hrh, marker, os.environ)
        self.hrh_overlay = self.runtime / "tests" / "deployment" / "clinical-composed-e2e" / self.mode_plan.overlay
        self._locked_marker = marker

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
            "CLINICAL_HARNESS": self.harness.as_posix(),
            "CLINICAL_SEED": effective_seed.as_posix(),
            "CLINICAL_INGRESS_IMAGE": f"restricted-clinical-ingress:{self.project}",
            "CLINICAL_ADAPTER_IMAGE": f"restricted-clinical-adapter:{self.project}",
            "CLINICAL_POLICY_PUBLIC_KEY": policy_public,
            "CLINICAL_STAGING_PROJECT": self.project,
            "CLINICAL_STAGING_STATE_ID": marker["state_id"],
            "CLINICAL_STAGING_PORT": str(self.port),
        }
        if self.mode_plan.mode == "source-build":
            values.update(CLINICAL_HRH_ROOT=self.hrh.as_posix(), CLINICAL_HRH_BUILD_SHA=marker["hrh_head"])
        else:
            values.update(
                CLINICAL_HRH_WEB_IMAGE=marker["hrh_candidate"]["subjects"]["web"],
                CLINICAL_HRH_MIGRATE_IMAGE=marker["hrh_candidate"]["subjects"]["migrate"],
            )
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

    def _initialization_lock_path(self) -> Path:
        return self.state_dir.parent / f".{self.state_dir.name}.initialization.lock"

    def _owned_initialization_orphans(self) -> list[Path]:
        """List only this target's exact private pre-rename initialization dirs."""
        expression = re.compile(INIT_ORPHAN_RE_TEMPLATE.format(state=re.escape(self.state_dir.name)))
        candidates = [entry for entry in self.state_dir.parent.iterdir() if expression.fullmatch(entry.name)]
        if len(candidates) > MAX_INITIALIZATION_ORPHANS:
            raise SafetyError("too many owned initialization remnants; refusing unsafe cleanup")
        return candidates

    @staticmethod
    def _assert_orphan_tree_unlinked(root: Path) -> None:
        """Reject anything but normal directories/files before delegated removal."""
        with os.scandir(root) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise SafetyError("initialization remnant contains a symlink")
                if stat.S_ISDIR(metadata.st_mode):
                    ClinicalStaging._assert_orphan_tree_unlinked(Path(entry.path))
                elif not stat.S_ISREG(metadata.st_mode):
                    raise SafetyError("initialization remnant contains an unsafe filesystem entry")

    def _remove_owned_initialization_orphan(self, path: Path) -> None:
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise SafetyError("initialization remnant is not an operator-owned mode-0700 directory")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise SafetyError("platform cannot safely remove an initialization remnant")
        self._assert_orphan_tree_unlinked(path)
        shutil.rmtree(path)
        fsync_directory(path.parent)

    def _reconcile_owned_initialization_orphans(self) -> None:
        """Erase bounded abandoned seed directories; never promote/reuse their seed."""
        for orphan in self._owned_initialization_orphans():
            self._remove_owned_initialization_orphan(orphan)

    def _prepare_new_state(self, frame: Mapping[str, str], acquisition: hrh_mode.PublishedAcquisition | None = None) -> dict[str, Any]:
        self._reconcile_owned_initialization_orphans()
        if self.state_dir.exists():
            if any(self.state_dir.iterdir()):
                raise SafetyError("init requires a fresh target or a valid initializing marker")
            self.state_dir.rmdir()
        temporary = self.state_dir.parent / f".{self.state_dir.name}.init-{secrets.token_hex(8)}"
        temporary.mkdir(mode=0o700, parents=False)
        try:
            (temporary / "evidence").mkdir(mode=0o700)
            self._seed_material(temporary)
            marker = (
                new_marker(project=self.project, state_dir=self.state_dir, state_id=secrets.token_hex(16), env_sha256="0" * 64, **frame)
                if acquisition is None else
                hrh_mode.new_published_marker(project=self.project, state_dir=self.state_dir, state_id=secrets.token_hex(16), env_sha256="0" * 64, volumes=volume_names(self.project), acquisition=acquisition, **frame)
            )
            if acquisition is not None:
                hrh_mode.retain_published_evidence(temporary / "evidence", acquisition)
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
        services = ("controller", "hrh-migrate", "hrh") if self.mode_plan.build_hrh else ("controller",)
        self.compose("build", *services, timeout=2400)

    def _provision_initial_mattermost_admin(self) -> None:
        """Create the initial admin inside the provisioner boundary.

        The controller reads the mode-0600 seed file from its private,
        read-only mount and sends the password only as the HTTPS request body.
        The host never reads it for a child command, so neither host argv nor
        Docker's container command metadata receives the value.
        """
        self.control("create-initial-admin", timeout=180)

    def _erase_initial_admin_password(self) -> None:
        """Discard the bootstrap-only secret while the marker is finalizing."""
        password = self.state_dir / "seed" / "admin_password"
        try:
            metadata = password.stat(follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SafetyError("bootstrap password artifact is not an operator-owned mode-0600 regular file")
        password.unlink()
        fsync_directory(password.parent)

    def _finalize_initialization(self, marker: dict[str, Any]) -> None:
        """Durably complete the one-way bootstrap-secret cleanup protocol.

        ``finalizing`` is deliberately not an operational lifecycle.  It is a
        recoverable checkpoint after every service has started, but before the
        marker can advertise ``ready``.  An interrupt before unlink leaves the
        protected seed and a finalizing marker; an interrupt after unlink but
        before the atomic ready marker leaves only that finalizing marker.  A
        subsequent ``init`` repeats this idempotent finalizer and cannot leave
        a ready staging target with a reusable bootstrap secret.
        """
        self._require_lifecycle(marker, "initialization finalization", {"finalizing"})
        self._erase_initial_admin_password()
        marker["lifecycle"] = "ready"
        self._write_marker(marker)

    @_serialized_mutator
    def init(self) -> dict[str, Any]:
        self._require_linux()
        if self.mode_plan.mode == "source-build":
            self.state_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            frame = verify_source_frame(self.runtime, self.hrh, self.shell)
            verify_hrh_candidate_build_inputs(self.hrh)
            acquisition = None
        else:
            try:
                frame = hrh_mode.verify_runtime_frame(self.runtime, self.shell, base_sha=RUNTIME_BASE_SHA)
                acquisition = hrh_mode.acquire_published_candidate(
                    self.runtime, self.mode_plan.published_inputs,
                    operator_lock_path(self.state_dir, self.project).parent,
                    runner=subprocess.run, snapshot_key=self.project,
                )
            except hrh_mode.ModeError as exc:
                raise SafetyError(str(exc)) from exc
            self.state_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Kernel advisory locking is released on SIGKILL.  It serializes both
        # abandoned-temp cleanup and pre-rename seed reconciliation, so a
        # second operator cannot observe or remove a live initializer's state.
        with _exclusive_operator_lock(self._initialization_lock_path()):
            self._reconcile_owned_initialization_orphans()
            if self.state_dir.exists() and (self.state_dir / MARKER_NAME).exists():
                marker = read_marker(self.state_dir, self.project)
                if marker.get("schema", SCHEMA) != (SCHEMA if self.mode_plan.mode == "source-build" else hrh_mode.PUBLISHED_MARKER_SCHEMA):
                    raise SafetyError("initializing marker mode changed after selection")
                if marker["lifecycle"] not in {"initializing", "finalizing"}:
                    raise SafetyError("staging target is already initialized")
                verify_effective_env(self.state_dir, marker)
                if any(marker[key] != value for key, value in frame.items()):
                    raise SafetyError("initializing marker source frame changed")
                if acquisition is not None and (
                    marker["hrh_candidate"] != acquisition.candidate
                    or marker["effective_images"] != acquisition.effective_images
                ):
                    raise SafetyError("published resume candidate differs from initialized identity")
            else:
                marker = self._prepare_new_state(frame, acquisition)
            state_stat = self.state_dir.stat()
            if state_stat.st_uid != os.getuid() or stat.S_IMODE(state_stat.st_mode) != 0o700:
                raise SafetyError("state directory must be owned by the operator with mode 0700")
            if marker["lifecycle"] == "finalizing":
                self._finalize_initialization(marker)
                return self.up()
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
            self._provision_initial_mattermost_admin()
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
            if self.mode_plan.mode == "source-build":
                marker["expected_images"] = self._built_images()
            marker["lifecycle"] = "finalizing"
            self._write_marker(marker)
            self._finalize_initialization(marker)
            return self.up()
    @_serialized_mutator
    def up(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "up", {"ready", "stopped"})
        pull = ("--pull", "never") if self.mode_plan.compose_pull_policy else ()
        self.compose("up", *pull, "--detach", *ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        if marker["lifecycle"] == "stopped":
            marker["lifecycle"] = "ready"
            self._write_marker(marker)
        return self.status()

    def _verify_marker_and_source(self) -> dict[str, Any]:
        marker = self._locked_marker or read_marker(self.state_dir, self.project)
        verify_effective_env(self.state_dir, marker)
        try:
            frame = (
                verify_source_frame(self.runtime, self.hrh, self.shell)
                if marker["schema"] == SCHEMA else
                hrh_mode.verify_runtime_frame(self.runtime, self.shell, base_sha=RUNTIME_BASE_SHA)
            )
        except hrh_mode.ModeError as exc:
            raise SafetyError(str(exc)) from exc
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

    def _wait_for_authenticated_ingress(self, started_at: str) -> None:
        """Wait only for the current ingress generation's non-sensitive readiness marker."""
        deadline = time.monotonic() + INGRESS_READY_TIMEOUT_SECONDS
        while True:
            state = self._container_inspections().get("ingress", {}).get("State", {})
            if state.get("Running") is False or state.get("Status") in {"exited", "dead"}:
                raise SafetyError("Mattermost ingress exited before authenticated readiness")
            logs = self.compose(
                "logs", "--no-color", "--since", started_at, "ingress", check=False,
            ).stdout
            if "mattermost_ingress_outcome=authenticated_ready" in logs:
                return
            if time.monotonic() >= deadline:
                raise SafetyError("Mattermost ingress did not become authenticated-ready in time")
            time.sleep(0.25)

    @_serialized_mutator
    def status(self, *, _allow_recovering: bool = False) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        allowed_lifecycles = {"ready", "recovering"} if _allow_recovering else {"ready"}
        self._require_lifecycle(marker, "status", allowed_lifecycles)
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
        self._wait_for_authenticated_ingress(ingress_started_at)
        current_images = self._built_images()
        if marker.get("schema", SCHEMA) == SCHEMA:
            if not marker["expected_images"] or current_images != marker["expected_images"]:
                raise SafetyError("running service image identities differ from initialized receipt")
        else:
            try:
                hrh_mode.verify_effective_containers(marker, all_inspected)
            except hrh_mode.ModeError as exc:
                raise SafetyError(str(exc)) from exc
        evidence = {
            "schema": marker.get("schema", SCHEMA),
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "source": {key: marker[key] for key in (("runtime_head", "runtime_tree", "hrh_head", "hrh_tree") if marker.get("schema", SCHEMA) == SCHEMA else ("runtime_head", "runtime_tree"))},
            "compose_env_sha256": marker["compose_env_sha256"],
            "policy_digest": self.control("policy-digest"),
            "lifecycle": marker["lifecycle"],
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
        evidence["built_images" if marker.get("schema", SCHEMA) == SCHEMA else "effective_images"] = current_images if marker.get("schema", SCHEMA) == SCHEMA else marker["effective_images"]
        self._assert_no_controller()
        write_json_atomic(self.state_dir / "evidence" / "status.json", evidence, mode=0o600)
        return evidence

    @_serialized_mutator
    def renew_tls(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "renew-tls", {"ready", "stopped", "renewing_tls", "tls_prepared"})
        return self._renew_tls_material(marker)

    def _renew_tls_material(self, marker: dict[str, Any], *, restoring: bool = False) -> dict[str, Any]:
        try:
            return _renew_tls(self, marker, LONG_RUNNING_SERVICES, restoring=restoring)
        except TlsError as exc:
            raise SafetyError(str(exc)) from exc
        except (OSError, ValueError) as exc:
            raise SafetyError("TLS renewal failed with incomplete state") from exc

    @_serialized_mutator
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

    @_serialized_mutator
    def stop(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "stop", {"ready"})
        stopped = self.compose("stop", *LONG_RUNNING_SERVICES, check=False)
        if stopped.returncode:
            raise CommandError("Compose could not stop every required staging service")
        marker["lifecycle"] = "stopped"
        self._write_marker(marker)
        evidence = {"schema": marker["schema"], "project": self.project, "state_id": marker["state_id"], "lifecycle": "stopped", "observed_at": datetime.now(UTC).isoformat()}
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

    def _assert_unmounted_backup_volumes(self, volumes: Mapping[str, str]) -> None:
        """Refuse archival while *any* container retains an in-scope volume mount.

        Compose labels are not sufficient: a manually-created or orphaned
        container can be unlabeled yet still write an exact project volume.
        This check runs after Compose has removed its stopped containers and
        immediately before every archive read.
        """
        expected = set(volumes.values())
        if expected != set(volume_names(self.project).values()):
            raise SafetyError("backup volume fence does not cover the exact volume set")
        for volume in sorted(expected):
            raw = self.shell.run(
                "docker", "container", "ls", "--all", "--quiet", "--filter", f"volume={volume}",
            ).stdout
            for container_id in (line.strip() for line in raw.splitlines() if line.strip()):
                inspected = self.shell.run("docker", "container", "inspect", container_id)
                try:
                    item = json.loads(inspected.stdout)[0]
                    mounts = item["Mounts"]
                except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise SafetyError("could not verify backup volume mount fence") from exc
                matching = [
                    mount for mount in mounts
                    if isinstance(mount, Mapping) and mount.get("Type") == "volume" and mount.get("Name") == volume
                ]
                if not matching:
                    raise SafetyError("volume-filtered container inspection is inconsistent")
                modes = {"rw" if mount.get("RW") is True else "ro" if mount.get("RW") is False else "unknown" for mount in matching}
                raise SafetyError(
                    f"backup volume remains mounted by container {container_id}: {volume} ({', '.join(sorted(modes))})"
                )

    def _backup_volume(self, key: str, volume: str, backup_dir: Path) -> None:
        if key not in BACKED_UP_VOLUME_KEYS or volume != volume_names(self.project)[key]:
            raise SafetyError("backup volume is outside the exact allowlist")
        archive = f"/backup/{BACKUP_VOLUME_DIR}/{key}.tar"
        # The private bind is mode 0700 and source files may be owned by a
        # service UID.  Root plus this single DAC capability is the minimum
        # needed for this read/export endpoint; network, writable rootfs and
        # every other capability remain unavailable.
        source_mount = f"type=volume,src={volume},dst=/source,readonly"
        backup_mount = f"type=bind,src={backup_dir},dst=/backup"
        command = (
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
            "--security-opt", "no-new-privileges:true", "--user", "0:0",
            "--entrypoint", "sh",
            "--mount", source_mount,
            "--mount", backup_mount,
            RECOVERY_HELPER_IMAGE,
            "-ec", f"tar --numeric-owner -C /source -cf {archive} .",
        )
        verify_recovery_helper_boundary(
            command, source_mount=source_mount, backup_mount=backup_mount,
            capabilities=frozenset({"DAC_OVERRIDE"}),
        )
        self.shell.run(*command, cwd=self.runtime, timeout=1200)
        inspect_safe_tar(backup_dir / BACKUP_VOLUME_DIR / f"{key}.tar", require_regular_file=True)
        fsync_file(backup_dir / BACKUP_VOLUME_DIR / f"{key}.tar")

    @_serialized_mutator
    def backup(self, backup_dir: Path, *, recovery_trust: Path | None = None, recovery_sealer: Path | None = None, recovery_capsule: Path | None = None) -> dict[str, Any]:
        """Create an atomically published, cold-only backup.  No overwrite exists."""
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "backup", {"stopped"})
        self._verify_cold_quiescence(marker)
        backup_dir = validate_backup_path(
            backup_dir, state_dir=self.state_dir, forbidden_roots=(self.runtime,) if self.hrh is None else (self.runtime, self.hrh),
        )
        if backup_dir.exists():
            raise SafetyError("backup target must be a new directory")
        if not backup_dir.parent.is_dir():
            raise SafetyError("backup parent directory must already exist")
        temporary = backup_dir.parent / f".{backup_dir.name}.partial-{secrets.token_hex(8)}"
        if self.mode_plan.mode == "published" and recovery_trust is not None:
            recovery_codec.reconcile_owned_staging(backup_dir.parent, project=self.project)
            private_builder = functools.partial(recovery_codec.build_private_backup_inputs, self, temporary, marker, volume_directory=BACKUP_VOLUME_DIR, state_archive=BACKUP_STATE_ARCHIVE, volume_keys=BACKED_UP_VOLUME_KEYS, create_state=create_state_archive)
            return recovery_codec.finish_published_backup(self, temporary, marker, backup_dir, recovery_trust_path=recovery_trust, recovery_sealer=recovery_sealer, capsule_path=recovery_capsule, contract=_backup_contract(), receipt_builder=_codec_build_backup_receipt, now=datetime.now(UTC), verifier_evidence_names=hrh_mode._verifier(self.runtime).EVIDENCE_FILES, private_builder=private_builder)
        try:
            temporary.mkdir(mode=0o700)
            (temporary / BACKUP_VOLUME_DIR).mkdir(mode=0o700)
            create_state_archive(self.state_dir, temporary / BACKUP_STATE_ARCHIVE)
            # Stop leaves Compose containers present.  Remove only the exact
            # already-validated stack, then reject every remaining mount,
            # including unlabeled debug/orphan containers, before each read.
            self.compose("down", timeout=600)
            self._assert_unmounted_backup_volumes(marker["volumes"])
            for key in BACKED_UP_VOLUME_KEYS:
                self._assert_unmounted_backup_volumes(marker["volumes"])
                self._backup_volume(key, marker["volumes"][key], temporary)
            fsync_directory(temporary / BACKUP_VOLUME_DIR)
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
        _codec_extract_safe_state_archive(_backup_contract(), archive_path, destination)

    def _restore_volume(self, key: str, volume: str, backup_dir: Path) -> None:
        if key not in BACKED_UP_VOLUME_KEYS or volume != volume_names(self.project)[key]:
            raise SafetyError("restore volume is outside the exact allowlist")
        archive = f"/backup/{BACKUP_VOLUME_DIR}/{key}.tar"
        # CHOWN/FOWNER are required only here: --numeric-owner must restore
        # archived service UIDs/GIDs (for example PostgreSQL's 999:999) and
        # their archived modes into the exact named destination volume.  The
        # command boundary rejects every fourth capability and every extra mount.
        source_mount = f"type=volume,src={volume},dst=/destination"
        backup_mount = f"type=bind,src={backup_dir},dst=/backup,readonly"
        command = (
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
            "--security-opt", "no-new-privileges:true", "--user", "0:0",
            "--entrypoint", "sh",
            "--mount", source_mount,
            "--mount", backup_mount,
            RECOVERY_HELPER_IMAGE,
            "-ec", f"tar --numeric-owner -C /destination -xf {archive}",
        )
        verify_recovery_helper_boundary(
            command, source_mount=source_mount, backup_mount=backup_mount,
            capabilities=frozenset({"DAC_OVERRIDE", "CHOWN", "FOWNER"}),
        )
        self.shell.run(*command, cwd=self.runtime, timeout=1200)

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

    def _contain_failed_restore(self) -> None:
        try:
            marker = read_marker(self.state_dir, self.project)
            marker["lifecycle"] = "recovering"
            self._write_marker(marker)
            self.compose("stop", *LONG_RUNNING_SERVICES, check=False)
        except Exception:
            pass

    @_serialized_mutator
    def restore(self, backup_dir: Path, expected_manifest_sha256: str, *, renew_tls: bool = False, recovery_trust: Path | None = None, recovery_sealer: Path | None = None, recovery_capsule: Path | None = None, recovery_identity_reader: Any = None) -> dict[str, Any]:
        """Restore only a fully validated cold bundle into a clean destination."""
        self._require_linux()
        backup_dir = validate_backup_path(backup_dir, state_dir=self.state_dir, forbidden_roots=(self.runtime,) if self.hrh is None else (self.runtime, self.hrh))
        if self.mode_plan.mode == "published" and recovery_trust is not None:
            prepared = None
            try:
                self._require_empty_restore_destination()
                prepared = recovery_codec.prepare_published_restore(self, backup_dir, recovery_capsule, recovery_trust, recovery_sealer, expected_manifest_sha256, now=datetime.now(UTC))
                try:
                    acquisition = hrh_mode.acquire_published_candidate(self.runtime, self.mode_plan.published_inputs, operator_lock_path(self.state_dir, self.project).parent, runner=subprocess.run, snapshot_key=self.project)
                except Exception:
                    recovery_codec.cleanup_prepared_restore(prepared)
                    raise
                return recovery_codec.restore_published_backup(self, backup_dir, expected_manifest_sha256, recovery_trust_path=recovery_trust, recovery_sealer=recovery_sealer, capsule_path=recovery_capsule, identity_reader=recovery_identity_reader, acquired_generation=acquisition.candidate, contract=_backup_contract(), receipt_builder=_codec_build_restore_receipt, renew_tls=renew_tls, now=datetime.now(UTC), prepared=prepared)
            except (hrh_mode.ModeError, recovery_codec.CapsuleError) as exc:
                if prepared is not None:
                    recovery_codec.cleanup_prepared_restore(prepared)
                raise SafetyError(str(exc)) from exc
        snapshot = materialize_backup_snapshot(
            backup_dir, self.state_dir.parent, snapshot_stem=self.state_dir.name,
        )
        temporary = self.state_dir.parent / f".{self.state_dir.name}.recovering-{secrets.token_hex(8)}"
        published_state = False
        try:
            manifest = validate_backup_bundle(snapshot, expected_manifest_sha256, self.project, self.state_dir)
            frame = verify_source_frame(self.runtime, self.hrh, self.shell)
            if frame != manifest["source"]:
                raise SafetyError("current source frame differs from the validated backup source frame")
            self._require_empty_restore_destination()
            temporary.mkdir(mode=0o700)
            self._extract_safe_state_archive(snapshot / BACKUP_STATE_ARCHIVE, temporary)
            marker = _read_backup_manifest(snapshot)  # manifest bytes were validated before mutation
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
                self._restore_volume(key, marker["volumes"][key], snapshot)
            if renew_tls:
                self._renew_tls_material(marker, restoring=True)
            # The excluded transport socket is recreated empty by _create_volumes;
            # clinical-socket-init rebuilds its socket during the ordered startup.
            self._start_restored_stack()
            status = self.status(_allow_recovering=True)
            marker["lifecycle"] = "ready"
            self._write_marker(marker)
            receipt = {
                "schema": BACKUP_SCHEMA,
                "synthetic_only": True,
                "project": self.project,
                "state_id": marker["state_id"],
                "manifest_sha256": expected_manifest_sha256,
                "excluded_volume": EXCLUDED_RECOVERY_VOLUME,
                "source": manifest["source"],
                "status_observed_at": status["observed_at"],
                "verification": "mechanical_restore_only",
                "restored_at": datetime.now(UTC).isoformat(),
                "nonclaims": [
                    "not a causal recovery verification", "not a hot restore", "not encrypted", "not production",
                ],
            }
            receipt_dir = self.state_dir / "evidence" / "recovery"
            receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            receipt_path = receipt_dir / f"restore-{expected_manifest_sha256}.json"
            write_json_atomic(receipt_path, receipt, mode=0o600)
            return receipt
        except Exception as exc:
            if published_state:
                self._contain_failed_restore()
                raise SafetyError(
                    "restore failed after controlled recovery state was published; run destroy before retrying"
                ) from exc
            raise
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
            if snapshot.exists():
                shutil.rmtree(snapshot)

    @_serialized_mutator
    def finalize_cold_recovery_verification(
        self, expected_manifest_sha256: str, causal_checks: Mapping[str, bool], *,
        backup_dir: Path | None = None, expected_mechanical_receipt_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Publish a verified receipt only after the external causal drill passes."""
        self._require_linux()
        _require_sha256(expected_manifest_sha256, name="external manifest hash")
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "finalize-cold-recovery-verification", {"ready"})
        if set(causal_checks) != CAUSAL_RECOVERY_CHECKS or any(value is not True for value in causal_checks.values()):
            raise SafetyError("causal recovery verification is incomplete or invalid")
        receipt_dir = self.state_dir / "evidence" / "recovery"
        mechanical_path = receipt_dir / f"restore-{expected_manifest_sha256}.json"
        if self.mode_plan.mode == "published":
            if backup_dir is None or expected_mechanical_receipt_sha256 is None:
                raise SafetyError("published causal finalization requires independent public anchors")
            try:
                validated = recovery_codec.snapshot_and_validate_public_bundle(
                    backup_dir, self.state_dir.parent, project=self.project, expected_manifest_sha256=expected_manifest_sha256,
                    verifier_evidence_names=hrh_mode._verifier(Path(__file__).resolve().parents[2]).EVIDENCE_FILES,
                )
                manifest, identity = validated["manifest"], validated["identity"]
                mechanical_bytes = recovery_codec.read_bounded_regular(
                    mechanical_path, limit=1024 * 1024, code="RECOVERY_MECHANICAL_RECEIPT_UNAVAILABLE",
                )
            except recovery_codec.CapsuleError as exc:
                raise SafetyError(str(exc)) from exc
            if hashlib.sha256(mechanical_bytes).hexdigest() != expected_mechanical_receipt_sha256:
                raise SafetyError("external mechanical receipt hash differs")
            if marker["project"] != identity["project"] or marker["state_id"] != identity["state_id"] or {"runtime_head": marker["runtime_head"], "runtime_tree": marker["runtime_tree"]} != identity["runtime_source"] or marker["hrh_candidate"] != identity["hrh_candidate"] or marker["effective_images"] != identity["effective_images"]:
                raise SafetyError("current marker differs from recovery identity")
            validation_kwargs = dict(
                mechanical_receipt_bytes=mechanical_bytes, manifest=manifest,
                identity=identity, current_marker=marker, restore_trust=None,
                restore_trust_sha256=json.loads(mechanical_bytes)["restore_recovery_trust_sha256"],
                causal_checks=causal_checks, expected_manifest_sha256=expected_manifest_sha256,
                expected_mechanical_receipt_sha256=expected_mechanical_receipt_sha256,
                current_compose_env_sha256=file_sha256(self.env_file),
                effective_mattermost_port=self.port,
                verified_at=datetime.now(UTC).isoformat(),
            )
            _codec_validate_causal_receipt(_backup_contract(), **validation_kwargs)
            receipt = _codec_build_causal_receipt(
                _backup_contract(), **validation_kwargs,
            )
            write_json_atomic(receipt_dir / f"verified-restore-{expected_manifest_sha256}.json", receipt, mode=0o600)
            return receipt
        try:
            mechanical = json.loads(mechanical_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SafetyError("mechanical restore receipt is unavailable") from exc
        if (
            not isinstance(mechanical, dict)
            or mechanical.get("manifest_sha256") != expected_manifest_sha256
            or mechanical.get("verification") != "mechanical_restore_only"
        ):
            raise SafetyError("mechanical restore receipt does not bind this verification")
        receipt = {
            "schema": BACKUP_SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "manifest_sha256": expected_manifest_sha256,
            "verification": "causal_e2e_verified",
            "causal_checks": {key: True for key in sorted(CAUSAL_RECOVERY_CHECKS)},
            "verified_at": datetime.now(UTC).isoformat(),
            "nonclaims": ["not PHI", "not production", "not a compliance certification"],
        }
        write_json_atomic(receipt_dir / f"verified-restore-{expected_manifest_sha256}.json", receipt, mode=0o600)
        return receipt

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

    def _assert_destroyed_absent(self) -> None:
        """Prove the exact bounded project namespace is gone after destroy.

        The check is deliberately narrower than a Docker-wide sweep: it covers
        only the fixed Compose-name prefix, fixed network names, and the
        marker-derived volume allowlist that ``destroy`` was authorized to
        remove.  A teardown that cannot establish this condition is a failed
        teardown, even though a later operator may still perform manual
        cleanup.
        """
        names = self.shell.run("docker", "container", "ls", "--all", "--format", "{{.Names}}")
        prefix = f"{self.project}-"
        remaining_containers = sorted(
            line.strip() for line in names.stdout.splitlines()
            if line.strip().startswith(prefix)
        )
        if remaining_containers:
            raise SafetyError("project containers remain after destroy: " + ", ".join(remaining_containers))
        for key in NETWORK_KEYS:
            name = f"{self.project}_{key}"
            if self.shell.run("docker", "network", "inspect", name, check=False).returncode == 0:
                raise SafetyError(f"project network remains after destroy: {name}")
        for name in volume_names(self.project).values():
            if self.shell.run("docker", "volume", "inspect", name, check=False).returncode == 0:
                raise SafetyError(f"project volume remains after destroy: {name}")

    @_serialized_mutator
    def reset(self) -> dict[str, Any]:
        self._require_linux()
        self._destroy_resources()
        for name in ("seed", "evidence"):
            shutil.rmtree(self.state_dir / name, ignore_errors=False)
        for name in (MARKER_NAME, "compose.env"):
            (self.state_dir / name).unlink()
        return self.init()

    @_serialized_mutator
    def destroy(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._locked_marker or read_marker(self.state_dir, self.project)
        self._destroy_resources()
        self._assert_destroyed_absent()
        result = {"schema": marker["schema"], "project": self.project, "state_id": marker["state_id"], "lifecycle": "destroyed"}
        shutil.rmtree(self.state_dir)
        return result


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=Path(__file__).resolve().parents[2])
    hrh_mode.add_root_argument(parser)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", type=int, default=18443)
    sub = parser.add_subparsers(dest="command", required=True)
    creation = []
    for name in ("init", "up", "status", "stop", "reset", "destroy", "renew-tls"):
        child = sub.add_parser(name)
        if name == "init":
            creation.append(child)
    refresh = sub.add_parser("refresh-policy")
    refresh.add_argument("--epoch", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("--backup-dir", type=Path, required=True)
    add_recovery_arguments(backup, restore=False)
    restore = sub.add_parser("restore")
    creation.append(restore)
    restore.add_argument("--backup-dir", type=Path, required=True)
    restore.add_argument("--expected-manifest-sha256", required=True)
    restore.add_argument("--renew-tls", action="store_true", help="renew synthetic TLS while restored workloads are still stopped")
    add_recovery_arguments(restore, restore=True)
    finalize = sub.add_parser("finalize-cold-recovery-verification")
    add_finalizer_arguments(finalize)
    for child in creation:
        hrh_mode.add_creation_arguments(child)
    parsed = parser.parse_args(argv)
    validate_recovery_arguments(parser, parsed)
    if parsed.command in {"init", "restore"} and parsed.hrh_mode is None:
        parsed.hrh_mode = "source-build"
    return parsed
def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        creation = args.command in {"init", "restore"}
        marker = read_marker(args.state_dir, args.project) if creation and (args.state_dir / MARKER_NAME).exists() else None
        plan = hrh_mode.plan_hrh_mode(args.command, hrh_mode.mode_tokens(args), marker_schema=marker and marker["schema"], marker_lifecycle=marker and marker["lifecycle"], environment=os.environ) if creation else None
        staging = ClinicalStaging(
            args.runtime_root, plan.source_root if plan else args.hrh_root, args.state_dir,
            args.project, args.port, mode_plan=plan,
            persisted_command=None if creation else args.command,
        )
        if args.command == "refresh-policy":
            result = staging.refresh_policy(args.epoch)
        elif args.command in {"backup", "restore", "finalize-cold-recovery-verification"}:
            result = dispatch_recovery_command(staging, args)
        elif args.command == "renew-tls":
            result = staging.renew_tls()
        else:
            result = getattr(staging, args.command)()
    except (hrh_mode.ModeError, recovery_codec.CapsuleError) as exc:
        print(f"clinical_staging outcome=denied reason={exc}", file=sys.stderr)
        return 2
    except CommandError:
        # CommandError is a boundary type: never let a future child-output
        # regression become public just because this CLI renders its message.
        print("clinical_staging outcome=denied reason=command_failed", file=sys.stderr)
        return 2
    except SafetyError as exc:
        print(f"clinical_staging outcome=denied reason={exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
