#!/usr/bin/env python3
"""Synthetic-only operator lifecycle for the composed clinical witness."""
from __future__ import annotations

import argparse
import base64
import contextlib
import functools
import hashlib
import importlib.util
import http.client
import ipaddress
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
import tarfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

try:
    import fcntl
except ImportError:  # pragma: no cover - the supported operator path is Linux.
    fcntl = None


# The candidate stack is rebased from this current common main ancestor.  Keep
# this in lockstep with the composed E2E product anchor below.
RUNTIME_BASE_SHA = "c0fc85d894700823deb92a085d36291589160028"
# This must match the composed E2E build subject.  Keeping a second staging
# subject here would make the two executable entry points disagree about what
# source the candidate is allowed to use.
REQUIRED_HRH_SHA = "ad13735e9881a48580a9e138daac137f8c865dea"
REQUIRED_HRH_TREE = "f217b0b1cf7f438422528dfe178d81b78212c68b"
SCHEMA = "restricted-synthetic-clinical-staging.v1"
MARKER_NAME = "staging-state.json"
# The exact closed marker contract.  Cold recovery validates archived markers
# against this same set, so a bundle cannot reintroduce an older marker shape.
MARKER_KEYS = (
    "schema", "synthetic_only", "project", "state_dir", "state_id",
    "compose_env_sha256", "lifecycle", "runtime_head", "runtime_tree",
    "hrh_head", "hrh_tree", "volumes", "expected_images", "image_mode",
    "subject_admission",
)
INIT_ORPHAN_RE_TEMPLATE = r"^\.{state}\.init-[a-f0-9]{{16}}$"
MAX_INITIALIZATION_ORPHANS = 8
PROJECT_LABEL = "io.cervantesh.restricted-runtime.project"
STATE_LABEL = "io.cervantesh.restricted-runtime.state-id"
SYNTHETIC_LABEL = "io.cervantesh.restricted-runtime.synthetic-clinical"
SUBJECT_ADMISSION_SCHEMA = "restricted-runtime-immutable-candidate.v1"
SUBJECT_IMAGES = {
    "ingress": "ghcr.io/cervantesh/restricted-mattermost-ingress",
    "clinical-adapter": "ghcr.io/cervantesh/restricted-clinical-adapter",
}
SUBJECT_NAMES = {
    "ingress": "restricted-mattermost-ingress",
    "clinical-adapter": "restricted-clinical-adapter",
}
OCI_SUBJECT_RE = re.compile(r"^ghcr\.io/cervantesh/[a-z0-9-]+@sha256:[a-f0-9]{64}$")
PROJECT_RE = re.compile(r"^clinicalstaging[a-z0-9]{1,32}$")
VOLUME_KEYS = (
    "mattermost_db", "mattermost_data", "mattermost_tls", "hrh_db",
    "hrh_tls", "hrh_secret", "clinical_config", "clinical_socket",
    "ingress_config", "ingress_outbox", "controller_state",
)
# The transport socket volume is recreated empty on restore; archiving a live
# UNIX socket directory would carry no recoverable state.
EXCLUDED_RECOVERY_VOLUME = "clinical_socket"
BACKED_UP_VOLUME_KEYS = tuple(key for key in VOLUME_KEYS if key != EXCLUDED_RECOVERY_VOLUME)
BACKUP_SCHEMA = "restricted-synthetic-clinical-cold-backup.v1"
BACKUP_MANIFEST_NAME = "backup-manifest.json"
BACKUP_COMPLETE_NAME = "COMPLETE"
BACKUP_STATE_ARCHIVE = "state.tar"
BACKUP_VOLUME_DIR = "volumes"
# The behaviors only a composed run can witness.  `restore` proves the bytes
# came back and the stack started; these say the behavior survived.
CAUSAL_RECOVERY_CHECKS = frozenset({
    "source_deletion_persisted",
    "unknown_delivery_is_ambiguous_once",
    "already_delivered_not_redelivered",
    "isolation_preserved",
    "expired_policy_fails_closed",
    "artifacts_clean",
    "duration_bounded",
})
# Deliberately the image the composed E2E already admits, so cold recovery adds
# no new supply-chain subject.  A static contract keeps the two in lockstep.
RECOVERY_HELPER_IMAGE = (
    "postgres:17.10-bookworm@sha256:"
    "9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f"
)
LIFECYCLE_STATES = (
    "initializing", "finalizing", "ready", "stopped", "cold", "recovering",
)
# `recovering` and `cold` are published-but-non-operational states.  They are
# deliberately treated like `initializing` by the destructive guards:
#
# * a restore that dies between publishing the state directory and creating
#   volumes must still be cleanable by `destroy`;
# * `backup` must remove the stopped Compose containers before it can archive
#   the volumes they still mount, which leaves a target whose volumes exist but
#   whose services and networks do not.
#
# An exact-set requirement in either state would strand the target: `destroy`
# and `reset` would refuse it and the volumes could only be removed out of
# band.  The allowlist and label checks still apply, and `_create_volumes`
# keeps its own exact post-check.
SETTLED_LIFECYCLES = frozenset({"finalizing", "ready", "stopped"})
# Remnant roots a dead lifecycle command can leave beside the state directory.
ORPHAN_RE_TEMPLATES = (
    r"^\.{state}\.init-[a-f0-9]{{16}}$",
    r"^\.{state}\.recovering-[a-f0-9]{{16}}$",
    r"^\.{state}\.bundle-[a-f0-9]{{16}}$",
    r"^\.{state}\.partial-[a-f0-9]{{16}}$",
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
        "groups": [20006, 20007],
        "read_only_mounts": {"/run/clinical-config", "/run/hrh-secret", "/run/hrh-tls"},
        "writable_mounts": {"/run/restricted-clinical"},
    },
    "ingress": {
        "user": "restricted-mattermost-ingress",
        "uid": 10007,
        "gid": 20005,
        "groups": [20000, 20001, 20005, 20006],
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


def _load_sibling(name: str):
    """Load a cold-recovery dependency by path, not by ``sys.path`` luck.

    This module is executed both as a script and through
    ``spec_from_file_location``; a bare sibling import would resolve only in
    the first case.
    """
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"clinical_staging_{name}", path)
    if spec is None or spec.loader is None:
        raise SafetyError(f"cold-recovery dependency is unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_bundle = _load_sibling("clinical_backup_bundle")
_operator_lock = _load_sibling("clinical_operator_lock")


def serialized_lifecycle(method):
    """Serialize every mutating/observing lifecycle command for one state target."""
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        self._require_linux()
        with self._lifecycle_lock():
            return method(self, *args, **kwargs)
    return wrapped


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
    image_mode: str = "exact-source",
    subject_admission: Mapping[str, Any] | None = None,
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
        "image_mode": image_mode,
        "subject_admission": dict(subject_admission or {}),
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
    finally:
        os.close(fd)


def _assert_owned_regular(path: Path, *, mode: int, label: str) -> None:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise SafetyError(f"{label} is not a regular file")
    if os.name == "posix" and (
        metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise SafetyError(f"{label} is not an operator-owned mode-{mode:04o} file")


@contextlib.contextmanager
def _atomic_write_lock(path: Path):
    """Serialize marker cleanup and replacement without following lock links."""
    lock = path.with_name(f".{path.name}.atomic.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(lock, flags | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        _assert_owned_regular(lock, mode=0o600, label="atomic marker lock")
        fd = os.open(lock, flags)
    try:
        if created and hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SafetyError("atomic marker lock is not a regular file")
        if os.name == "posix" and (
            metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise SafetyError("atomic marker lock is not an operator-owned mode-0600 file")
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _discard_abandoned_atomic_temp(path: Path, *, mode: int) -> None:
    """Remove only the legacy fixed temporary once its writer lock is held."""
    try:
        _assert_owned_regular(path, mode=mode, label="abandoned atomic temporary")
    except FileNotFoundError:
        return
    path.unlink()
    fsync_directory(path.parent)


def write_json_atomic(path: Path, value: Mapping[str, Any], *, mode: int) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with _atomic_write_lock(path):
        # Randomize the owned temporary so a killed prior writer cannot block
        # a later writer.  A legacy fixed temporary is cleaned only after the
        # lock and ownership/type checks establish that it is safe to touch.
        _discard_abandoned_atomic_temp(path.with_name(path.name + ".tmp"), mode=mode)
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
            if tmp.exists():
                _assert_owned_regular(tmp, mode=mode, label="atomic temporary")
                tmp.unlink()


def read_marker(state_dir: Path, project: str) -> dict[str, Any]:
    state_dir = validate_state_path(state_dir, project)
    path = state_dir / MARKER_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("closed staging marker is missing or invalid") from exc
    return validate_marker_value(value, project=project, state_dir=state_dir)


def validate_marker_value(
    value: object, *, project: str, state_dir: Path
) -> dict[str, Any]:
    """Apply the closed marker contract to an in-memory marker.

    ``read_marker`` is the live caller.  Cold recovery needs the same rules for
    a marker that has been archived rather than read from the live state
    directory, and must not be allowed to drift into a weaker copy of them.
    """
    if not isinstance(value, dict):
        raise SafetyError("staging marker must be an object")
    if set(value) != set(MARKER_KEYS):
        raise SafetyError("staging marker has unknown or missing fields")
    if (
        value["schema"] != SCHEMA
        or value["synthetic_only"] is not True
        or value["project"] != project
        or value["state_dir"] != str(state_dir.resolve())
        or value["hrh_head"] != REQUIRED_HRH_SHA
        or value["volumes"] != volume_names(project)
        or not re.fullmatch(r"[a-f0-9]{32}", value["state_id"])
        or not re.fullmatch(r"[a-f0-9]{64}", value["compose_env_sha256"])
        or value["lifecycle"] not in set(LIFECYCLE_STATES)
        or not isinstance(value["expected_images"], dict)
        or value["image_mode"] not in {"exact-source", "subject-admitted"}
        or not isinstance(value["subject_admission"], dict)
    ):
        raise SafetyError("staging marker does not match the requested synthetic target")
    if value["image_mode"] == "exact-source" and value["subject_admission"]:
        raise SafetyError("exact-source marker cannot retain subject admission")
    if value["image_mode"] == "subject-admitted":
        _validate_subject_admission(value["subject_admission"], require_executed=value["lifecycle"] != "initializing")
    return value


def _validate_subject_admission(value: object, *, require_executed: bool) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"manifest_sha256", "subjects", "executed_repo_digests"}:
        raise SafetyError("subject admission has unknown or missing fields")
    manifest_sha256 = value.get("manifest_sha256")
    subjects = value.get("subjects")
    executed = value.get("executed_repo_digests")
    if (not isinstance(manifest_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", manifest_sha256)
            or not isinstance(subjects, dict) or set(subjects) != set(SUBJECT_IMAGES)
            or not isinstance(executed, dict) or set(executed) != (set(SUBJECT_IMAGES) if require_executed else set())):
        raise SafetyError("subject admission is not closed")
    for service, image in SUBJECT_IMAGES.items():
        expected = image + "@sha256:"
        if not isinstance(subjects.get(service), str) or not subjects[service].startswith(expected) or not OCI_SUBJECT_RE.fullmatch(subjects[service]):
            raise SafetyError("subject admission image is invalid")
        if require_executed and executed.get(service) != subjects[service]:
            raise SafetyError("subject admission executed digest differs from manifest")
    return value


def _sealed_subject_binding(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """The pre-Docker admission identity; observed RepoDigests are not input."""
    if not value:
        return {}
    return {
        "manifest_sha256": value.get("manifest_sha256"),
        "subjects": value.get("subjects"),
    }


def _verify_subject_candidate(manifest: object, runtime: Path, evidence_root: Path) -> None:
    verifier_path = runtime / "tools" / "verify_immutable_candidate.py"
    spec = importlib.util.spec_from_file_location("clinical_staging_candidate_verifier", verifier_path)
    if spec is None or spec.loader is None:
        raise SafetyError("subject admission verifier is unavailable")
    verifier = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(verifier)
        # The staging admission is deliberately closed over the two OCI
        # subjects it will execute.  Health Record Hub remains a separately
        # pinned source frame, not a third OCI subject in this manifest.
        errors = verifier.verify(manifest, require_external=False, repo_root=runtime, evidence_root=evidence_root)
        if not errors:
            errors = verifier.verify_live_attestations(manifest, repo_root=runtime)
    except Exception as exc:
        raise SafetyError("subject admission verifier is unavailable") from exc
    if not isinstance(errors, list) or errors:
        raise SafetyError("subject admission manifest is not a valid immutable candidate")


def read_subject_admission(path: Path, *, runtime: Path | None = None) -> dict[str, Any]:
    """Read exactly the two immutable subjects accepted by clinical staging."""
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("subject admission manifest is unavailable") from exc
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != SUBJECT_ADMISSION_SCHEMA
            or manifest.get("platform") != "linux/amd64" or not isinstance(manifest.get("subjects"), list)):
        raise SafetyError("subject admission manifest is invalid")
    revision = manifest.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise SafetyError("subject admission source revision is invalid")
    if runtime is not None:
        try:
            current = subprocess.run(
                ("git", "-C", str(runtime), "rev-parse", "HEAD"), text=True, encoding="utf-8",
                errors="replace", capture_output=True, timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SafetyError("subject admission source frame is unavailable") from exc
        if current.returncode or current.stdout.strip() != revision:
            raise SafetyError("subject admission source revision differs from runtime")
        _verify_subject_candidate(manifest, runtime, path.parent.parent)
    by_name: dict[str, dict[str, Any]] = {}
    for subject in manifest["subjects"]:
        if not isinstance(subject, dict) or not isinstance(subject.get("name"), str) or subject["name"] in by_name:
            raise SafetyError("subject admission manifest is invalid")
        by_name[subject["name"]] = subject
    if set(by_name) != set(SUBJECT_NAMES.values()):
        raise SafetyError("subject admission manifest has unexpected subjects")
    subjects: dict[str, str] = {}
    for service, name in SUBJECT_NAMES.items():
        subject = by_name[name]
        digest, image = subject.get("digest"), subject.get("image")
        if (not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
                or image != f"{SUBJECT_IMAGES[service]}@{digest}" or subject.get("platform") != "linux/amd64"):
            raise SafetyError("subject admission subject is invalid")
        subjects[service] = image
    return {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "subjects": subjects,
        "executed_repo_digests": {},
    }


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SafetyError(f"required file is unavailable: {path.name}") from exc


def verify_recovery_helper_boundary(
    command: tuple[str, ...],
    *,
    source_mount: str,
    backup_mount: str,
    capabilities: frozenset[str],
) -> None:
    """Fail closed if the one-shot archive helper gains any authority."""
    if command[:3] != ("docker", "run", "--rm") or command.count("--read-only") != 1:
        raise SafetyError("recovery helper command is not ephemeral and read-only")
    expected_single = {
        "--network": "none",
        "--cap-drop": "ALL",
        "--security-opt": "no-new-privileges:true",
        "--user": "0:0",
        "--entrypoint": "sh",
    }
    for flag, value in expected_single.items():
        if command.count(flag) != 1 or command[command.index(flag) + 1] != value:
            raise SafetyError("recovery helper command has an unexpected security authority")
    cap_adds = {command[index + 1] for index, item in enumerate(command[:-1]) if item == "--cap-add"}
    if cap_adds != capabilities or command.count("--cap-add") != len(capabilities):
        raise SafetyError("recovery helper command has an unexpected security authority")
    mounts = [command[index + 1] for index, item in enumerate(command[:-1]) if item == "--mount"]
    if len(mounts) != 2 or set(mounts) != {source_mount, backup_mount}:
        raise SafetyError("recovery helper command has an unexpected mount")
    if RECOVERY_HELPER_IMAGE not in command:
        raise SafetyError("recovery helper command does not use the admitted helper image")
    if "--privileged" in command or "-v" in command or "--volume" in command:
        raise SafetyError("recovery helper command has an unexpected authority")


def backup_contract(project: str, state_dir: Path):
    """Bind the cold-recovery codec to the *current* staging contract."""
    def validate_marker(marker: Mapping[str, Any]) -> None:
        validate_marker_value(marker, project=project, state_dir=state_dir)

    return _bundle.BackupContract(
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
        marker_keys=frozenset(MARKER_KEYS),
        volume_names=volume_names,
        validate_project=validate_project,
        validate_marker=validate_marker,
        fsync_file=fsync_file,
        fsync_directory=fsync_directory,
    )


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
    if lifecycle in SETTLED_LIFECYCLES and set(discovered) != expected:
        raise SafetyError("finalizing/ready/stopped staging requires the exact volume set")
    if lifecycle not in set(LIFECYCLE_STATES):
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
    if lifecycle in SETTLED_LIFECYCLES:
        if "controller" in services:
            raise SafetyError("controller must be absent from finalizing/ready/stopped staging")
        expected_services = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(services) != expected_services:
            raise SafetyError("finalizing/ready/stopped staging requires the exact service set")
        if set(networks) != allowed_networks:
            raise SafetyError("finalizing/ready/stopped staging requires the exact network set")
    elif lifecycle not in {"initializing", "recovering", "cold"}:
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
    """Accept only the exact restrictive /tmp option grammar we rely on."""
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
    return (
        {"rw", "noexec", "nosuid"} <= flags
        and values.get("size") in {"16m", "16384k", "16777216"}
        and values.get("mode") in {"0700", "700"}
        and values.get("uid") == str(uid)
        and values.get("gid") == str(gid)
    )


def verify_restricted_container_controls(
    inspected: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Fail closed unless Docker reports the exact restricted service boundaries."""
    evidence: dict[str, dict[str, Any]] = {}
    for service, expected in RESTRICTED_CONTAINER_CONTROLS.items():
        info = inspected.get(service)
        if not isinstance(info, Mapping):
            raise SafetyError(f"{service} container inspection is unavailable")
        config = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        security = {str(value).replace(":", "=") for value in (host.get("SecurityOpt") or [])}
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
            or not _tmpfs_is_confined(tmpfs.get("/tmp"), uid=expected["uid"], gid=expected["gid"])
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


def verify_restricted_process_identities(
    observed: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Require the process actually running in each container to retain its identity."""
    evidence: dict[str, dict[str, Any]] = {}
    for service, expected in RESTRICTED_CONTAINER_CONTROLS.items():
        identity = observed.get(service)
        expected_identity = {
            "uid": expected["uid"],
            "gid": expected["gid"],
            "groups": expected["groups"],
        }
        if identity != expected_identity:
            raise SafetyError(f"{service} effective process identity rejected")
        evidence[service] = expected_identity
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
    def __init__(self, runtime: Path, hrh: Path, state_dir: Path, project: str, port: int, shell: Shell | None = None,
                 subject_admission: Mapping[str, Any] | None = None):
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
        self.subject_overlay = self.runtime / "deploy" / "clinical-staging" / "compose.subject-admitted.yaml"
        self.harness = self.runtime / "tests" / "deployment" / "clinical-composed-e2e"
        self.env_file = self.state_dir / "compose.env"
        self.subject_admission = dict(subject_admission or {})
        if self.subject_admission:
            _validate_subject_admission(self.subject_admission, require_executed=False)
        self._lifecycle_thread_lock = threading.RLock()
        self._lifecycle_thread_state = threading.local()

    @contextlib.contextmanager
    def _lifecycle_lock(self):
        """Take the one durable operator boundary for this staging target.

        Two locks are held, in this order, and every lifecycle command —
        including cold backup and restore — goes through both:

        * a persistent lock keyed by the *Compose project*, because two
          independently supplied state directories can name the same project
          and therefore race over the same external Docker volumes.  The
          per-state lock below cannot see that collision.
        * the per-state advisory lock, reentrant for nested command calls.
        """
        try:
            with _operator_lock.persistent_operator_lock(self.state_dir, self.project):
                with self._state_lifecycle_lock():
                    yield
        except _operator_lock.OperatorLockError as exc:
            raise SafetyError(str(exc)) from exc

    @contextlib.contextmanager
    def _state_lifecycle_lock(self):
        """Take a per-state advisory lock, reentrant for nested command calls."""
        # The process-local RLock remains held across the whole lifecycle
        # operation.  flock covers independent operators; RLock covers two
        # threads using this same ClinicalStaging instance.  Depth is local to
        # the owning thread, so a concurrent thread can never impersonate a
        # nested call and bypass either lock.
        with self._lifecycle_thread_lock:
            depth = getattr(self._lifecycle_thread_state, "depth", 0)
            if depth:
                self._lifecycle_thread_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._lifecycle_thread_state.depth = depth
                return

            # init may create a fresh state directory, so the lock lives beside it.
            self.state_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            lock_path = self.state_dir.parent / f".{self.state_dir.name}.lifecycle.lock"
            if fcntl is None:  # pragma: no cover - test portability only; Linux is required in production.
                self._lifecycle_thread_state.depth = 1
                try:
                    yield
                finally:
                    self._lifecycle_thread_state.depth = 0
                return

            fd = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise SafetyError("lifecycle lock is not a regular file")
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._lifecycle_thread_state.depth = 1
                try:
                    yield
                finally:
                    self._lifecycle_thread_state.depth = 0
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _require_linux(self) -> None:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            raise SafetyError("operator staging lifecycle is supported only on local Linux")

    def _compose_args(self) -> tuple[str, ...]:
        paths = (
            "docker", "compose", "--env-file", str(self.env_file),
            "--project-name", self.project, "--file", str(self.base_compose),
            "--file", str(self.overlay),
        )
        if self.subject_admission:
            return (*paths, "--file", str(self.subject_overlay))
        return paths

    @staticmethod
    def _sealed_compose_environment() -> dict[str, str]:
        """Keep host `CLINICAL_*` values out of Compose interpolation.

        The closed `compose.env` file is the only authority for this namespace.
        Passing the host environment through would let its values take
        precedence during Compose interpolation despite `--env-file`.
        """
        return {
            name: value
            for name, value in os.environ.items()
            if not name.upper().startswith("CLINICAL_")
        }

    def compose(self, *args: str, check: bool = True, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
        return self.shell.run(
            *self._compose_args(),
            *args,
            cwd=self.runtime,
            env=self._sealed_compose_environment(),
            check=check,
            timeout=timeout,
        )

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
            "CLINICAL_INGRESS_IMAGE": self.subject_admission.get("subjects", {}).get("ingress", f"restricted-clinical-ingress:{self.project}"),
            "CLINICAL_ADAPTER_IMAGE": self.subject_admission.get("subjects", {}).get("clinical-adapter", f"restricted-clinical-adapter:{self.project}"),
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

    def _owned_initialization_orphans(self) -> list[Path]:
        """Return only this target's bounded pre-rename remnant roots.

        The caller already holds the lifecycle lock.  The random suffix
        prevents an unrelated directory from becoming a cleanup target through
        a predictable name.

        Cold recovery adds two more shapes.  A process killed mid-restore can
        leave an extracted state tree (``.recovering-``) or a full private copy
        of the bundle (``.bundle-``), and a killed backup can leave a partial
        bundle (``.partial-``).  All three carry generated secret material, so
        they belong to the same bounded cleanup as a dead ``init``.
        """
        name = re.escape(self.state_dir.name)
        expressions = [
            re.compile(template.format(state=name)) for template in ORPHAN_RE_TEMPLATES
        ]
        if not self.state_dir.parent.is_dir():
            return []
        candidates = [
            entry for entry in self.state_dir.parent.iterdir()
            if any(expression.fullmatch(entry.name) for expression in expressions)
        ]
        if len(candidates) > MAX_INITIALIZATION_ORPHANS * len(ORPHAN_RE_TEMPLATES):
            raise SafetyError("too many initialization remnants; refusing cleanup")
        return candidates

    @staticmethod
    def _assert_owned_unlinked_tree(root: Path) -> None:
        """Reject links, special files, or foreign entries before deletion."""
        with os.scandir(root) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if metadata.st_uid != os.getuid():
                    raise SafetyError("initialization remnant contains a foreign entry")
                if stat.S_ISLNK(metadata.st_mode):
                    raise SafetyError("initialization remnant contains a symlink")
                if stat.S_ISDIR(metadata.st_mode):
                    ClinicalStaging._assert_owned_unlinked_tree(Path(entry.path))
                elif not stat.S_ISREG(metadata.st_mode):
                    raise SafetyError("initialization remnant contains an unsafe filesystem entry")

    def _reconcile_owned_initialization_orphans(self) -> None:
        """Erase only safely attributable pre-rename state left by a dead init."""
        for orphan in self._owned_initialization_orphans():
            metadata = orphan.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise SafetyError("initialization remnant is not an operator-owned mode-0700 directory")
            if not shutil.rmtree.avoids_symlink_attacks:
                raise SafetyError("platform cannot safely remove an initialization remnant")
            self._assert_owned_unlinked_tree(orphan)
            shutil.rmtree(orphan)
            fsync_directory(orphan.parent)

    def _prepare_new_state(self, frame: Mapping[str, str]) -> dict[str, Any]:
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
            marker = new_marker(
                project=self.project,
                state_dir=self.state_dir,
                state_id=secrets.token_hex(16),
                env_sha256="0" * 64,
                image_mode="subject-admitted" if self.subject_admission else "exact-source",
                subject_admission=self.subject_admission,
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

    def _subject_build_services(self) -> tuple[str, ...]:
        return ("controller", "hrh-migrate", "hrh") if self.subject_admission else ("ingress", "clinical-adapter", "controller", "hrh-migrate", "hrh")

    def _up_services(self, *services: str, timeout: int) -> subprocess.CompletedProcess[str]:
        if self.subject_admission:
            return self.compose("up", "--detach", "--no-build", *services, timeout=timeout)
        return self.compose("up", "--detach", *services, timeout=timeout)

    def _admit_published_subjects(self) -> None:
        """Pull and inspect immutable subjects before any service is started."""
        if not self.subject_admission:
            return
        self.compose("pull", "ingress", "clinical-adapter", "clinical-socket-init", timeout=2400)
        executed: dict[str, str] = {}
        for service, reference in self.subject_admission["subjects"].items():
            raw = self.shell.run("docker", "image", "inspect", reference, cwd=self.runtime).stdout
            try:
                value = json.loads(raw)
                repo_digests = value[0].get("RepoDigests") if isinstance(value, list) and len(value) == 1 else None
            except (json.JSONDecodeError, TypeError, IndexError) as exc:
                raise SafetyError("subject admission inspection is invalid") from exc
            if not isinstance(repo_digests, list) or reference not in repo_digests:
                raise SafetyError("subject admission RepoDigest differs from manifest")
            executed[service] = reference
        self.subject_admission["executed_repo_digests"] = executed

    def _build_images(self) -> None:
        # controller is FROM the locally tagged ingress image, so its build
        # cannot share a parallel Compose phase with ingress.
        if not self.subject_admission:
            self.compose("build", "ingress", "clinical-adapter", timeout=2400)
            self.compose("build", "controller", "hrh-migrate", "hrh", timeout=2400)
            return
        self._admit_published_subjects()
        self.compose("build", *self._subject_build_services(), timeout=2400)

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

    @serialized_lifecycle
    def init(self) -> dict[str, Any]:
        self._require_linux()
        frame = verify_source_frame(self.runtime, self.hrh, self.shell)
        if self.state_dir.exists() and (self.state_dir / MARKER_NAME).exists():
            marker = read_marker(self.state_dir, self.project)
            if marker["lifecycle"] not in {"initializing", "finalizing"}:
                raise SafetyError("staging target is already initialized")
            expected_mode = "subject-admitted" if self.subject_admission else "exact-source"
            if (marker["image_mode"] != expected_mode
                    or _sealed_subject_binding(marker["subject_admission"])
                    != _sealed_subject_binding(self.subject_admission)):
                raise SafetyError("resumed initialization subject admission differs from sealed target")
            verify_effective_env(self.state_dir, marker)
            if any(marker[key] != value for key, value in frame.items()):
                raise SafetyError("initializing marker source frame changed")
        else:
            self.state_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            marker = self._prepare_new_state(frame)
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
        self._up_services("mattermost-postgres", "hrh-postgres", "hrh-migrate", timeout=900)
        migrated = self.compose("wait", "hrh-migrate", check=False, timeout=900)
        if migrated.returncode:
            raise CommandError("HRH migration did not complete successfully")
        self._up_services("mattermost", timeout=600)
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
        self._up_services(*ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        marker["expected_images"] = self._built_images()
        if self.subject_admission:
            marker["subject_admission"] = dict(self.subject_admission)
        marker["lifecycle"] = "finalizing"
        self._write_marker(marker)
        self._finalize_initialization(marker)
        return self.up()

    @serialized_lifecycle
    def up(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        # `cold` is a stopped target whose Compose containers and networks were
        # removed so its volumes could be archived.  `up` recreates them.
        self._require_lifecycle(marker, "up", {"ready", "stopped", "cold"})
        self._up_services(*ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        if marker["lifecycle"] in {"stopped", "cold"}:
            marker["lifecycle"] = "ready"
            self._write_marker(marker)
        return self.status()

    def _verify_marker_and_source(self) -> dict[str, Any]:
        marker = read_marker(self.state_dir, self.project)
        marker_admission = marker["subject_admission"]
        if bool(marker_admission) != bool(self.subject_admission):
            raise SafetyError("subject-admitted marker requires the same admission manifest")
        if marker_admission and marker_admission.get("manifest_sha256") != self.subject_admission.get("manifest_sha256"):
            raise SafetyError("subject admission manifest differs from initialized target")
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

    def _restricted_process_identities(self) -> dict[str, dict[str, Any]]:
        observed: dict[str, Mapping[str, Any]] = {}
        probe = "import json,os; print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':sorted(os.getgroups())}))"
        for service in RESTRICTED_CONTAINER_CONTROLS:
            try:
                value = json.loads(
                    self.compose("exec", "--no-TTY", service, "python", "-c", probe).stdout
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise SafetyError(f"{service} effective process identity is unreadable") from exc
            observed[service] = value
        return verify_restricted_process_identities(observed)

    @serialized_lifecycle
    def status(self, *, _allow_recovering: bool = False) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        # `recovering` is accepted only from inside `restore`, which has
        # already validated the bundle and published controlled state.  The CLI
        # cannot reach this allowance.
        self._require_lifecycle(
            marker, "status", {"ready", "recovering"} if _allow_recovering else {"ready"}
        )
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
        restricted_identities = self._restricted_process_identities()
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
        policy_digest = self.control("policy-live")
        if not re.fullmatch(r"[a-f0-9]{64}", policy_digest):
            raise SafetyError("live policy verification did not return a digest")
        evidence = {
            "schema": SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "source": {key: marker[key] for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")},
            "built_images": current_images,
            "compose_env_sha256": marker["compose_env_sha256"],
            "policy_digest": policy_digest,
            "lifecycle": marker["lifecycle"],
            "mattermost": f"https://127.0.0.1:{self.port}",
            "mattermost_publisher": publisher,
            "ingress_started_at": ingress_started_at,
            "tls_probe": tls_probe,
            "network_exception": "operator-proxy only: operator_access is non-internal",
            "restricted_container_controls": restricted_controls,
            "restricted_process_identities": restricted_identities,
            "privileged_provisioner_running": False,
            "nonclaims": ["not HIPAA", "not PHI-authorized", "not production"],
            "observed_at": datetime.now(UTC).isoformat(),
        }
        self._assert_no_controller()
        write_json_atomic(self.state_dir / "evidence" / "status.json", evidence, mode=0o600)
        return evidence

    @serialized_lifecycle
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

    @serialized_lifecycle
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

    # ------------------------------------------------------------------
    # Cold backup / restore
    # ------------------------------------------------------------------

    def _backup_contract(self):
        return backup_contract(self.project, self.state_dir)

    def _verify_cold_quiescence(self, marker: Mapping[str, Any]) -> None:
        """A stopped marker alone is not a fence; Docker state must agree."""
        self._require_lifecycle(marker, "backup", {"stopped"})
        verify_destructive_volumes(
            self.project, marker["state_id"], set(marker["volumes"].values()),
            self._volume_labels(), "stopped",
        )
        verify_destructive_resources(
            self.project, marker["state_id"],
            self._labeled_resources("container"), self._labeled_resources("network"), "stopped",
        )
        by_service = {str(row.get("Service")): row for row in self._containers(all_containers=True)}
        if set(by_service) != set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES):
            raise SafetyError("backup quiescence does not cover the exact Compose service set")
        running = sorted(
            service for service in LONG_RUNNING_SERVICES
            if str(by_service[service].get("State", "")).lower() in {"running", "restarting", "created"}
        )
        if running:
            raise SafetyError("backup requires fully stopped staging services: " + ", ".join(running))

    def _assert_unmounted_backup_volumes(self, volumes: Mapping[str, str]) -> None:
        """Refuse archival while *any* container retains an in-scope volume mount.

        Compose labels are not sufficient: a manually created or orphaned
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
                    mounts = json.loads(inspected.stdout)[0]["Mounts"]
                except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise SafetyError("could not verify backup volume mount fence") from exc
                matching = [
                    mount for mount in mounts
                    if isinstance(mount, Mapping) and mount.get("Type") == "volume"
                    and mount.get("Name") == volume
                ]
                if not matching:
                    raise SafetyError("volume-filtered container inspection is inconsistent")
                modes = sorted({
                    "rw" if mount.get("RW") is True else "ro" if mount.get("RW") is False else "unknown"
                    for mount in matching
                })
                raise SafetyError(
                    f"backup volume remains mounted by container {container_id}: "
                    + f"{volume} (" + ", ".join(modes) + ")"
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
        produced = backup_dir / BACKUP_VOLUME_DIR / f"{key}.tar"
        _bundle.inspect_safe_tar(self._backup_contract(), produced, require_regular_file=True)
        fsync_file(produced)

    @serialized_lifecycle
    def backup(self, backup_dir: Path) -> dict[str, Any]:
        """Create an atomically published, cold-only backup.  No overwrite exists."""
        self._require_linux()
        contract = self._backup_contract()
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
            _bundle.create_state_archive(contract, self.state_dir, temporary / BACKUP_STATE_ARCHIVE)
            # Stop leaves Compose containers present.  Remove only the exact
            # already-validated stack, then reject every remaining mount,
            # including unlabeled debug/orphan containers, before each read.
            #
            # The marker records the teardown *before* it happens.  Afterwards
            # this target no longer has the exact service and network set that
            # a `stopped` marker promises, and `destroy`/`reset` would refuse a
            # target that still claimed to be `stopped`.
            marker["lifecycle"] = "cold"
            self._write_marker(marker)
            self.compose("down", timeout=600)
            for key in BACKED_UP_VOLUME_KEYS:
                self._assert_unmounted_backup_volumes(marker["volumes"])
                self._backup_volume(key, marker["volumes"][key], temporary)
            fsync_directory(temporary / BACKUP_VOLUME_DIR)
            manifest = _bundle.build_backup_manifest(contract, marker, self.state_dir, temporary)
            _bundle.write_backup_manifest(contract, temporary, manifest)
            _bundle.write_backup_completion(contract, temporary)
            fsync_directory(temporary)
            # A partially written bundle never carries the published name, so an
            # interrupted backup cannot later be mistaken for a restorable one.
            os.replace(temporary, backup_dir)
            fsync_directory(backup_dir.parent)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise
        return {
            "schema": BACKUP_SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "backup_dir": str(backup_dir),
            "manifest_sha256": file_sha256(backup_dir / BACKUP_MANIFEST_NAME),
            "excluded_volume": EXCLUDED_RECOVERY_VOLUME,
            # The bundle captures a stopped target; the target it was taken
            # from is now cold and must be brought `up` before it serves again.
            "archived_lifecycle": "stopped",
            "lifecycle": "cold",
            "nonclaims": ["not a scheduled backup", "not encrypted", "not production"],
        }

    def _require_empty_restore_destination(self) -> None:
        if self.state_dir.exists() and any(self.state_dir.iterdir()):
            raise SafetyError("restore requires an absent or empty state destination")
        if not self.state_dir.parent.is_dir():
            raise SafetyError("restore state parent directory must already exist")
        if self._labeled_resources("container") | self._labeled_resources("network"):
            raise SafetyError("restore destination conflicts with labeled Docker resources")
        for volume in volume_names(self.project).values():
            if self.shell.run("docker", "volume", "inspect", volume, check=False).returncode == 0:
                raise SafetyError(f"restore destination conflicts with existing Docker volume: {volume}")
        for key in NETWORK_KEYS:
            name = f"{self.project}_{key}"
            if self.shell.run("docker", "network", "inspect", name, check=False).returncode == 0:
                raise SafetyError(f"restore destination conflicts with existing Docker network: {name}")
        names = self.shell.run("docker", "container", "ls", "--all", "--format", "{{.Names}}")
        if any(line.strip().startswith(f"{self.project}-") for line in names.stdout.splitlines()):
            raise SafetyError("restore destination conflicts with a project-named Docker container")

    def _extract_safe_state_archive(self, archive_path: Path, destination: Path) -> None:
        """Extract an already validated archive without ``tarfile.extractall``."""
        contract = self._backup_contract()
        try:
            with tarfile.open(archive_path, "r:") as archive:
                for member in archive.getmembers():
                    name = _bundle.safe_archive_name(contract, member.name)
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
        archive = f"/backup/{BACKUP_VOLUME_DIR}/{key}.tar"
        # CHOWN/FOWNER are required only here: --numeric-owner must restore
        # archived service UIDs/GIDs (for example PostgreSQL's 999:999) and
        # their archived modes into the exact named destination volume.  The
        # command boundary rejects every fourth capability and every extra mount.
        source_mount = f"type=volume,src={volume},dst=/destination"
        backup_mount = f"type=bind,src={backup_dir},dst=/backup,readonly"
        command = (
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL",
            "--cap-add", "DAC_OVERRIDE", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
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
        self._up_services("mattermost-postgres", "hrh-postgres", "hrh-migrate", timeout=900)
        migrated = self.compose("wait", "hrh-migrate", check=False, timeout=900)
        if migrated.returncode:
            raise CommandError("restored HRH migration did not complete successfully")
        self._up_services("mattermost", "operator-proxy", timeout=600)
        self.control("wait-mm")
        self._up_services("clinical-socket-init", "hrh", "hrh-tls", "clinical-adapter", timeout=900)
        self.control("wait-hrh")
        self._up_services("ingress", timeout=600)

    def _assert_restored_admission(self, marker: Mapping[str, Any]) -> None:
        """A bundle may not move this target onto a different subject line.

        The historical cold-recovery path predates immutable subject admission,
        so it had nothing to check here.  On this line the archived marker must
        agree with the operator's sealed admission before any mutation.
        """
        expected_mode = "subject-admitted" if self.subject_admission else "exact-source"
        if marker["image_mode"] != expected_mode:
            raise SafetyError("restored marker image mode differs from the sealed target")
        if _sealed_subject_binding(marker["subject_admission"]) != _sealed_subject_binding(
            self.subject_admission
        ):
            raise SafetyError("restored subject admission differs from the sealed target")

    # Only these four values are freshly generated on every `_env_values`
    # call, so a restored environment cannot be compared against them.
    GENERATED_ENV_KEYS = (
        "CLINICAL_MM_DB_PASSWORD",
        "CLINICAL_HRH_DB_PASSWORD",
        "CLINICAL_HRH_SESSION_SECRET",
        "CLINICAL_HRH_ENCRYPTION_KEY",
    )

    def _assert_restored_environment(self, marker: Mapping[str, Any], root: Path) -> None:
        """The restored `compose.env` must select exactly the admitted target.

        `compose.env` is the sole authority for Compose interpolation, so it
        alone decides which images are started and which volumes are attached.
        The marker's `compose_env_sha256` only proves the file is the one the
        bundle carried -- whoever produced the bundle controls both. Matching
        the archived marker's subject admission therefore proves nothing about
        what Compose will actually run.

        Restore does not pull and inspect RepoDigests the way `init` does, so
        this is the check that keeps a bundle from starting an unadmitted image
        or attaching a foreign volume.
        """
        try:
            raw = (root / "compose.env").read_text(encoding="utf-8")
        except OSError as exc:
            raise SafetyError("restored compose environment is unreadable") from exc
        values: dict[str, str] = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            if not separator or not key or key in values:
                raise SafetyError("restored compose environment is malformed")
            values[key] = value
        expected = self._env_values(marker, seed_root=root)
        if set(values) != set(expected):
            raise SafetyError("restored compose environment has unknown or missing keys")
        for key, value in expected.items():
            if key in self.GENERATED_ENV_KEYS:
                continue
            if values[key] != value:
                raise SafetyError(
                    f"restored compose environment does not bind the admitted target: {key}"
                )

    @serialized_lifecycle
    def restore(self, backup_dir: Path, expected_manifest_sha256: str) -> dict[str, Any]:
        """Restore only a fully validated cold bundle into a clean destination."""
        self._require_linux()
        contract = self._backup_contract()
        backup_dir = validate_backup_path(
            backup_dir, state_dir=self.state_dir, forbidden_roots=(self.runtime, self.hrh),
        )
        if not self.state_dir.parent.is_dir():
            raise SafetyError("restore state parent directory must already exist")
        # A killed predecessor can have left an extracted state tree or a full
        # private copy of a bundle beside the destination; both carry generated
        # secret material.
        self._reconcile_owned_initialization_orphans()
        # Copy first: every later read is from private storage, so the external
        # directory cannot be swapped between validation and use.
        snapshot = _bundle.materialize_backup_snapshot(
            contract, backup_dir, self.state_dir.parent, snapshot_stem=self.state_dir.name,
        )
        temporary = self.state_dir.parent / f".{self.state_dir.name}.recovering-{secrets.token_hex(8)}"
        published_state = False
        try:
            manifest = _bundle.validate_backup_bundle(
                contract, snapshot, expected_manifest_sha256, self.project, self.state_dir,
            )
            archived_marker = _bundle.validate_archived_marker(
                contract, snapshot / BACKUP_STATE_ARCHIVE,
                project=self.project, state_dir=self.state_dir, manifest=manifest,
            )
            self._assert_restored_admission(archived_marker)
            frame = verify_source_frame(self.runtime, self.hrh, self.shell)
            if frame != manifest["source"]:
                raise SafetyError("current source frame differs from the validated backup source frame")
            self._require_empty_restore_destination()

            temporary.mkdir(mode=0o700)
            self._extract_safe_state_archive(snapshot / BACKUP_STATE_ARCHIVE, temporary)
            restored_marker = validate_marker_value(
                json.loads((temporary / MARKER_NAME).read_text(encoding="utf-8")),
                project=self.project, state_dir=self.state_dir,
            )
            if restored_marker != archived_marker:
                raise SafetyError("extracted marker differs from the validated archived marker")
            restored_marker["lifecycle"] = "recovering"
            write_json_atomic(temporary / MARKER_NAME, restored_marker, mode=0o600)
            if file_sha256(temporary / "compose.env") != manifest["compose_env_sha256"]:
                raise SafetyError("restored compose environment differs from the validated backup")
            self._assert_restored_environment(restored_marker, temporary)
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
                    "not a causal recovery verification", "not a hot restore",
                    "not encrypted", "not production",
                ],
            }
            receipt_dir = self.state_dir / "evidence" / "recovery"
            receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_json_atomic(
                receipt_dir / f"restore-{expected_manifest_sha256}.json", receipt, mode=0o600
            )
            return receipt
        except Exception as exc:
            if published_state:
                # A failed post-publication step must remain non-operational.
                # `destroy` accepts recovering state and reuses the exact
                # resource allowlists for bounded cleanup.
                try:
                    failed_marker = read_marker(self.state_dir, self.project)
                    failed_marker["lifecycle"] = "recovering"
                    self._write_marker(failed_marker)
                    self.compose("stop", *LONG_RUNNING_SERVICES, check=False)
                except Exception:
                    pass
                raise SafetyError(
                    "restore failed after controlled recovery state was published; "
                    "run destroy before retrying"
                ) from exc
            raise
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
            if snapshot.exists():
                shutil.rmtree(snapshot)

    def _assert_destroyed_absent(self) -> None:
        """Prove the exact bounded project namespace is gone after destroy.

        The check is deliberately narrower than a Docker-wide sweep: it covers
        only the fixed Compose-name prefix, the fixed network names, and the
        volume allowlist that `destroy` was authorized to remove.  A teardown
        that cannot establish this condition is a failed teardown, even though
        a later operator may still perform manual cleanup.
        """
        names = self.shell.run("docker", "container", "ls", "--all", "--format", "{{.Names}}")
        prefix = f"{self.project}-"
        remaining = sorted(
            line.strip() for line in names.stdout.splitlines()
            if line.strip().startswith(prefix)
        )
        if remaining:
            raise SafetyError("project containers remain after destroy: " + ", ".join(remaining))
        for key in NETWORK_KEYS:
            name = f"{self.project}_{key}"
            if self.shell.run("docker", "network", "inspect", name, check=False).returncode == 0:
                raise SafetyError(f"project network remains after destroy: {name}")
        for name in volume_names(self.project).values():
            if self.shell.run("docker", "volume", "inspect", name, check=False).returncode == 0:
                raise SafetyError(f"project volume remains after destroy: {name}")

    @serialized_lifecycle
    def finalize_cold_recovery_verification(
        self, expected_manifest_sha256: str, causal_checks: Mapping[str, bool],
    ) -> dict[str, Any]:
        """Publish a verified receipt only after the external causal drill passes.

        `restore` can only witness that the bytes came back and the stack
        started; it deliberately publishes `mechanical_restore_only`.  Whether
        the *behavior* survived -- an already-delivered item is not
        redelivered, an unknown delivery stays erased and ambiguous, isolation
        and policy expiry still fail closed -- is only observable from the
        composed E2E, so that drill supplies the result here.

        This receipt is still not a compliance or production claim.  It says
        one synthetic composed run reproduced the named behaviors on this exact
        candidate.
        """
        self._require_linux()
        _bundle.require_sha256(
            self._backup_contract(), expected_manifest_sha256, name="external manifest hash"
        )
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "finalize-cold-recovery-verification", {"ready"})
        if set(causal_checks) != CAUSAL_RECOVERY_CHECKS or any(
            value is not True for value in causal_checks.values()
        ):
            raise SafetyError("causal recovery verification is incomplete or invalid")
        receipt_dir = self.state_dir / "evidence" / "recovery"
        mechanical_path = receipt_dir / f"restore-{expected_manifest_sha256}.json"
        try:
            mechanical = json.loads(mechanical_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SafetyError("mechanical restore receipt is unavailable") from exc
        if (
            not isinstance(mechanical, dict)
            or mechanical.get("manifest_sha256") != expected_manifest_sha256
            or mechanical.get("verification") != "mechanical_restore_only"
            or mechanical.get("state_id") != marker["state_id"]
            or mechanical.get("project") != self.project
        ):
            raise SafetyError("mechanical restore receipt does not bind this verification")
        receipt = {
            "schema": BACKUP_SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "manifest_sha256": expected_manifest_sha256,
            "source": {
                key: marker[key]
                for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")
            },
            "verification": "causal_e2e_verified",
            "causal_checks": {key: True for key in sorted(CAUSAL_RECOVERY_CHECKS)},
            "verified_at": datetime.now(UTC).isoformat(),
            "nonclaims": [
                "not PHI", "not production", "not a compliance certification",
                "not a representative-host receipt",
            ],
        }
        write_json_atomic(
            receipt_dir / f"verified-{expected_manifest_sha256}.json", receipt, mode=0o600
        )
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

    @serialized_lifecycle
    def reset(self) -> dict[str, Any]:
        self._require_linux()
        self._destroy_resources()
        for name in ("seed", "evidence"):
            shutil.rmtree(self.state_dir / name, ignore_errors=False)
        for name in (MARKER_NAME, "compose.env"):
            (self.state_dir / name).unlink()
        return self.init()

    @serialized_lifecycle
    def destroy(self) -> dict[str, Any]:
        self._require_linux()
        marker = read_marker(self.state_dir, self.project)
        self._destroy_resources()
        result = {"schema": SCHEMA, "project": self.project, "state_id": marker["state_id"], "lifecycle": "destroyed"}
        shutil.rmtree(self.state_dir)
        # Secret-bearing remnants of a killed backup or restore live beside the
        # state directory, not inside it, so removing the target alone leaves
        # them on disk.
        self._reconcile_owned_initialization_orphans()
        # A teardown that cannot establish its own bounded absence is a failed
        # teardown, not a successful one with a caveat.
        self._assert_destroyed_absent()
        return result


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--hrh-root", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--subject-manifest", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "up", "status", "stop", "reset", "destroy"):
        sub.add_parser(name)
    refresh = sub.add_parser("refresh-policy")
    refresh.add_argument("--epoch", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("--backup-dir", type=Path, required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--backup-dir", type=Path, required=True)
    restore.add_argument("--manifest-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        admission = read_subject_admission(args.subject_manifest, runtime=args.runtime_root) if args.subject_manifest else None
        staging = ClinicalStaging(args.runtime_root, args.hrh_root, args.state_dir, args.project, args.port, subject_admission=admission)
        if args.command == "refresh-policy":
            result = staging.refresh_policy(args.epoch)
        elif args.command == "backup":
            result = staging.backup(args.backup_dir)
        elif args.command == "restore":
            result = staging.restore(args.backup_dir, args.manifest_sha256)
        else:
            result = getattr(staging, args.command)()
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
