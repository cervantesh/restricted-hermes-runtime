"""Closed, content-safe recovery-capsule primitives for published HRH backups."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping


TRUST_SCHEMA = "restricted-synthetic-clinical-recovery-trust.v1"
PUBLIC_SCHEMA = "restricted-synthetic-clinical-cold-backup-published.v2"
PUBLISHED_V1 = "restricted-synthetic-clinical-cold-backup-published.v1"
SOURCE_V1 = "restricted-synthetic-clinical-cold-backup.v1"
IDENTITY_SCHEMA = "restricted-synthetic-clinical-backup-identity-published.v1"
CAPSULE_SCHEMA = "restricted-synthetic-clinical-recovery-capsule.v1"
RUN_SCHEMA = "restricted-synthetic-clinical-recovery-run.v1"
VOLUME_KEYS = (
    "mattermost_db", "mattermost_data", "mattermost_tls", "hrh_db", "hrh_tls",
    "hrh_secret", "clinical_config", "ingress_config", "ingress_outbox",
    "controller_state",
)
PRIVATE_NAMES = ("capsule-manifest.json", "state.tar", *(f"volumes/{key}.tar" for key in VOLUME_KEYS))
TRUST_FIELDS = {"schema", "policy_epoch", "scheme", "sealer_sha256", "recipients"}
RECIPIENT_FIELDS = {
    "recipient", "recipient_sha256", "not_before", "not_after", "status",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_NATIVE_IDENTITY = re.compile(rb"^AGE-SECRET-KEY-1[0-9A-Z]+\n$")


class CapsuleError(RuntimeError):
    """Stable, content-free recovery failure."""


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def add_recovery_arguments(parser: argparse.ArgumentParser, *, restore: bool) -> None:
    parser.add_argument("--recovery-trust", type=Path, action=_Once)
    parser.add_argument("--recovery-sealer", type=Path, action=_Once)
    parser.add_argument("--recovery-capsule", type=Path, action=_Once)
    if restore:
        parser.add_argument("--recovery-identity-stdin", action="store_true")


def validate_recovery_arguments(parser: argparse.ArgumentParser, parsed: argparse.Namespace) -> None:
    if parsed.command not in {"backup", "restore"}:
        return
    declared = [parsed.recovery_trust, parsed.recovery_sealer, parsed.recovery_capsule]
    if any(declared) and not all(declared):
        parser.error("the complete recovery boundary must be declared")
    if parsed.command == "restore" and parsed.recovery_identity_stdin and not all(declared):
        parser.error("recovery identity stdin requires the complete recovery boundary")
    if parsed.command == "restore" and all(declared) and not parsed.recovery_identity_stdin:
        parser.error("published recovery requires --recovery-identity-stdin")


def add_finalizer_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-mechanical-receipt-sha256", required=True)
    parser.add_argument("--causal-check", action="append", required=True)


def dispatch_recovery_command(staging: Any, args: argparse.Namespace) -> Any:
    if args.command == "backup":
        if (staging.mode_plan.mode == "published") != (args.recovery_trust is not None):
            raise CapsuleError("recovery options must exactly match published mode")
        return staging.backup(
            args.backup_dir, recovery_trust=args.recovery_trust,
            recovery_sealer=args.recovery_sealer, recovery_capsule=args.recovery_capsule,
        )
    if args.command == "restore":
        if (staging.mode_plan.mode == "published") != (args.recovery_trust is not None):
            raise CapsuleError("recovery options must exactly match published mode")
        return staging.restore(
            args.backup_dir, args.expected_manifest_sha256, renew_tls=args.renew_tls,
            recovery_trust=args.recovery_trust, recovery_sealer=args.recovery_sealer,
            recovery_capsule=args.recovery_capsule,
            recovery_identity_reader=(lambda: read_identity_stdin(sys.stdin.buffer, timeout_seconds=30)) if args.recovery_identity_stdin else None,
        )
    if len(args.causal_check) != len(set(args.causal_check)):
        raise CapsuleError("causal checks must not be duplicated")
    checks = {name: True for name in args.causal_check}
    return staging.finalize_cold_recovery_verification(
        args.expected_manifest_sha256, checks, backup_dir=args.backup_dir,
        expected_mechanical_receipt_sha256=args.expected_mechanical_receipt_sha256,
    )


def read_identity_stdin(stream: Any, *, timeout_seconds: float) -> bytes:
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError) as exc:
        raise CapsuleError("RECOVERY_IDENTITY_REQUIRED") from exc
    deadline = time.monotonic() + timeout_seconds
    payload = bytearray()
    while b"\n" not in payload and len(payload) <= 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise CapsuleError("RECOVERY_CAPSULE_UNAVAILABLE")
        chunk = os.read(descriptor, min(512, 4097 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
    return validate_identity_input(bytes(payload))


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _overlap(left: Path, right: Path) -> bool:
    left, right = left.resolve(), right.resolve()
    try:
        left.relative_to(right)
        return True
    except ValueError:
        try:
            right.relative_to(left)
            return True
        except ValueError:
            return False


def _trusted_directory_metadata(
    metadata: os.stat_result, *, allowed_modes: frozenset[int] | None,
) -> tuple[int, int, int, int]:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode):
        raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
    if os.name == "posix":
        if metadata.st_uid not in {0, os.geteuid()}:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if allowed_modes is not None and mode not in allowed_modes:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if allowed_modes is None and mode & 0o022:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid


def _open_trusted_directory(
    path: Path, *, allowed_modes: frozenset[int] | None = None,
) -> tuple[int | None, tuple[int, int, int, int]]:
    """Open a directory component-by-component and retain its Linux authority."""
    descriptor: int | None = None
    try:
        if os.name == "posix":
            absolute = path.absolute()
            descriptor = os.open(
                absolute.anchor,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            for component in absolute.parts[1:]:
                if component in {"", ".", ".."}:
                    raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
        else:
            metadata = path.lstat()
            if path.is_symlink():
                raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        return descriptor, _trusted_directory_metadata(metadata, allowed_modes=allowed_modes)
    except CapsuleError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED") from exc


def _require_trusted_parent(
    path: Path, *, allowed_modes: frozenset[int] | None = None,
) -> tuple[int, int, int, int]:
    descriptor, token = _open_trusted_directory(path, allowed_modes=allowed_modes)
    if descriptor is not None:
        os.close(descriptor)
    return token


def _retained_directory_is_current(
    path: Path, descriptor: int | None, token: tuple[int, int, int, int], *,
    allowed_modes: frozenset[int] | None,
) -> bool:
    if descriptor is None:
        return _require_trusted_parent(path, allowed_modes=allowed_modes) == token
    held = _trusted_directory_metadata(os.fstat(descriptor), allowed_modes=allowed_modes)
    current_descriptor, current = _open_trusted_directory(path, allowed_modes=allowed_modes)
    try:
        return held == token == current
    finally:
        if current_descriptor is not None:
            os.close(current_descriptor)


def _remove_private_tree_from(descriptor: int | None, path: Path) -> None:
    if descriptor is None:
        _remove_private_tree(path)
        return
    try:
        shutil.rmtree(path.name, dir_fd=descriptor)
    except FileNotFoundError:
        pass


def _descriptor_path(descriptor: int | None, fallback: Path) -> Path:
    if descriptor is not None and sys.platform.startswith("linux"):
        return Path(f"/proc/self/fd/{descriptor}")
    return fallback


def _reject_inode_aliases(paths: list[Path]) -> None:
    identities: set[tuple[int, int]] = set()
    for path in paths:
        try:
            metadata = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        identity = metadata.st_dev, metadata.st_ino
        if identity in identities:
            raise CapsuleError("published recovery paths alias")
        identities.add(identity)


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CapsuleError("duplicate JSON member")
        result[key] = value
    return result


def parse_closed_json(raw: bytes, *, document: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_duplicates)
    except CapsuleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapsuleError(f"{document} is invalid") from exc
    if not isinstance(value, dict):
        raise CapsuleError(f"{document} must be an object")
    return value


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise CapsuleError("recovery trust timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CapsuleError("recovery trust timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CapsuleError("recovery trust timestamp is invalid")
    return parsed.astimezone(UTC)


def _parse_recovery_trust(raw: bytes, *, require_one_active: bool) -> dict[str, Any]:
    value = parse_closed_json(raw, document="recovery trust")
    if _canonical(value) != raw or set(value) != TRUST_FIELDS:
        raise CapsuleError("recovery trust is non-canonical or has unknown fields")
    if value["schema"] != TRUST_SCHEMA or value["scheme"] != "age-x25519-v1":
        raise CapsuleError("recovery trust schema or scheme is unsupported")
    epoch = value["policy_epoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise CapsuleError("recovery policy epoch is invalid")
    if not isinstance(value["sealer_sha256"], str) or not _SHA256.fullmatch(value["sealer_sha256"]):
        raise CapsuleError("recovery sealer hash is invalid")
    recipients = value["recipients"]
    if not isinstance(recipients, list):
        raise CapsuleError("recovery recipients are invalid")
    hashes: list[str] = []
    active = 0
    for item in recipients:
        if not isinstance(item, dict) or set(item) != RECIPIENT_FIELDS:
            raise CapsuleError("recovery recipient has unknown or missing fields")
        recipient = item["recipient"]
        if not isinstance(recipient, str) or not recipient.startswith("age1") or recipient != recipient.lower() or any(c.isspace() for c in recipient):
            raise CapsuleError("recovery recipient is not native age X25519")
        try:
            encoded_recipient = recipient.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CapsuleError("recovery recipient is not native age X25519") from exc
        if not _valid_bech32(encoded_recipient):
            raise CapsuleError("recovery recipient is not native age X25519")
        expected = _sha((recipient + "\n").encode("ascii"))
        if item["recipient_sha256"] != expected:
            raise CapsuleError("recovery recipient hash is invalid")
        if item["status"] not in {"active", "retired", "revoked"}:
            raise CapsuleError("recovery recipient status is invalid")
        start, end = _time(item["not_before"]), _time(item["not_after"])
        if require_one_active and start >= end:
            raise CapsuleError("recovery recipient validity is invalid")
        hashes.append(expected)
        active += item["status"] == "active"
    if hashes != sorted(hashes) or len(hashes) != len(set(hashes)):
        raise CapsuleError("recovery recipient ordering or active cardinality is invalid")
    if require_one_active and active != 1:
        raise CapsuleError("recovery recipient ordering or active cardinality is invalid")
    return value


def parse_recovery_trust(raw: bytes, *, now: datetime) -> dict[str, Any]:
    del now
    return _parse_recovery_trust(raw, require_one_active=True)


def select_backup_recipient(trust: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    item = next(entry for entry in trust["recipients"] if entry["status"] == "active")
    if now < _time(item["not_before"]):
        raise CapsuleError("RECOVERY_RECIPIENT_NOT_YET_VALID")
    if now >= _time(item["not_after"]):
        raise CapsuleError("RECOVERY_RECIPIENT_EXPIRED")
    return dict(item)


def snapshot_declared_member(source: Path, destination: Path, *, declared_size: int, declared_sha256: str) -> Path:
    if destination.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        initial = source.lstat()
        if not stat.S_ISREG(initial.st_mode) or initial.st_size != declared_size:
            raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
        fd = os.open(source, flags)
    except FileNotFoundError as exc:
        raise CapsuleError("RECOVERY_CAPSULE_MISSING") from exc
    except OSError as exc:
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH") from exc
    try:
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
            if not stat.S_ISREG(before.st_mode) or before.st_size != declared_size or any(
                getattr(initial, field) != getattr(before, field) for field in stable
            ):
                raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
            digest, remaining = hashlib.sha256(), declared_size
            with destination.open("xb") as output:
                while remaining:
                    chunk = handle.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                if handle.read(1):
                    raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
                after = os.fstat(handle.fileno())
                if any(getattr(before, field) != getattr(after, field) for field in stable) or digest.hexdigest() != declared_sha256:
                    raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
                output.flush()
                os.fsync(output.fileno())
    except CapsuleError:
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH") from exc
    os.chmod(destination, 0o600)
    return destination


def _validate_regular_digest(path: Path, *, declared_size: int, declared_sha256: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != declared_size:
                raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
            digest, size = hashlib.sha256(), 0
            while chunk := handle.read(64 * 1024):
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(handle.fileno())
        stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size != declared_size or digest.hexdigest() != declared_sha256 or any(getattr(before, field) != getattr(after, field) for field in stable):
            raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
    except CapsuleError:
        raise
    except OSError as exc:
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH") from exc


def snapshot_sealer(source: Path, run_dir: Path, expected_sha256: str, *, opener: Callable[..., int] = os.open) -> Path:
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = run_dir / "age"
    try:
        # Windows denies rename of this ordinary os.open handle; the exact
        # post-open substitution witness is therefore POSIX-only.  Production
        # still reads from one already-open descriptor on both platforms.
        effective_opener = os.open if os.name == "nt" else opener
        fd = effective_opener(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise CapsuleError("RECOVERY_SEALER_UNTRUSTED")
            if os.name == "posix" and (metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022 or not metadata.st_mode & 0o100):
                raise CapsuleError("RECOVERY_SEALER_UNTRUSTED")
            data = handle.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise CapsuleError("RECOVERY_SEALER_UNTRUSTED")
        if _sha(data) != expected_sha256:
            raise CapsuleError("RECOVERY_SEALER_UNTRUSTED")
        with destination.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o500)
        _fsync_directory(destination.parent)
    except CapsuleError:
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_SEALER_UNTRUSTED") from exc
    return destination


def _tar_bytes(files: Mapping[str, bytes], order: tuple[str, ...]) -> bytes:
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name in order:
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size, info.uid, info.gid, info.mode, info.mtime = len(data), 0, 0, 0o600, 0
            archive.addfile(info, BytesIO(data))
    return stream.getvalue()


def _member(data: bytes) -> dict[str, Any]:
    # Ownership is bound separately by the archive validator.  This stable value
    # keeps the public manifest closed without exposing host-specific ownership.
    return {"sha256": _sha(data), "size": len(data), "ownership_sha256": _sha(_canonical({"uid": 0, "gid": 0, "mode": 0o600}))}


def build_public_bundle(
    public_dir: Path, *, public_identity: Mapping[str, Any], recovery_trust: bytes,
    evidence: Mapping[str, bytes], capsule_sha256: str, capsule_size: int,
    observer: Callable[[str], Any] = lambda _stage: None,
) -> dict[str, Any]:
    if public_dir.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    identity = _canonical(public_identity)
    parsed_trust = parse_closed_json(recovery_trust, document="recovery trust")
    if _canonical(parsed_trust) != recovery_trust:
        raise CapsuleError("recovery trust is non-canonical")
    evidence_names = tuple(evidence)
    evidence_tar = _tar_bytes(evidence, evidence_names)
    files = {
        "backup-identity.json": identity,
        "public-evidence.tar": evidence_tar,
        "recovery-trust.json": recovery_trust,
    }
    manifest = {
        "schema": PUBLIC_SCHEMA, "synthetic_only": True, "complete": True,
        "backup_identity_sha256": _sha(identity),
        "recovery_trust_sha256": _sha(recovery_trust),
        "public_evidence": _member(evidence_tar),
        "recovery_capsule": {
            "capsule_id": public_identity["capsule_id"],
            "ciphertext_sha256": capsule_sha256, "ciphertext_size": capsule_size,
        },
        "members": {name: _member(data) for name, data in files.items()},
    }
    public_dir.mkdir(mode=0o700, parents=False)
    for name, data in files.items():
        _write_fsynced(public_dir / name, data)
    _write_fsynced(public_dir / "backup-manifest.json", _canonical(manifest))
    observer("PUBLIC_MANIFEST_FSYNCED")
    _write_fsynced(public_dir / "COMPLETE", b"complete\n")
    _fsync_directory(public_dir)
    observer("PUBLIC_COMPLETE_FSYNCED")
    return manifest


def _write_fsynced(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        if hasattr(os, "fchmod"):
            os.fchmod(handle.fileno(), 0o600)
        handle.flush()
        os.fsync(handle.fileno())
    if not hasattr(os, "fchmod"):
        os.chmod(path, 0o600)
    _fsync_directory(path.parent)


def write_private_atomic(path: Path, data: bytes) -> None:
    if path.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    partial = path.parent / f".{path.name}.partial-{os.urandom(8).hex()}"
    try:
        with partial.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(partial, 0o600)
        os.replace(partial, path)
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_PUBLICATION_INCOMPLETE") from exc


def read_bounded_regular(path: Path, *, limit: int, code: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise CapsuleError(code) from exc
    if len(data) > limit:
        raise CapsuleError(code)
    return data


def build_public_identity(
    marker: Mapping[str, Any], *, recovery_trust: bytes, sealer_sha256: str,
    capsule_id: str,
) -> dict[str, Any]:
    trust = parse_closed_json(recovery_trust, document="recovery trust")
    recipient = next(item for item in trust["recipients"] if item["status"] == "active")
    return {
        "schema": IDENTITY_SCHEMA, "project": marker["project"], "state_id": marker["state_id"],
        "compose_env_sha256": marker["compose_env_sha256"],
        "runtime_source": {"runtime_head": marker["runtime_head"], "runtime_tree": marker["runtime_tree"]},
        "hrh_candidate": marker["hrh_candidate"], "effective_images": marker["effective_images"],
        "volumes": marker["volumes"], "excluded_volume": "clinical_socket", "capsule_id": capsule_id,
        "recipient_sha256": recipient["recipient_sha256"], "recovery_policy_epoch": trust["policy_epoch"],
        "recovery_trust_sha256": _sha(recovery_trust), "sealer_sha256": sealer_sha256,
    }


def build_capsule_plaintext(private_root: Path, *, public_identity: Mapping[str, Any]) -> bytes:
    files = {"state.tar": (private_root / "state.tar").read_bytes()}
    files.update({f"volumes/{key}.tar": (private_root / "volumes" / f"{key}.tar").read_bytes() for key in VOLUME_KEYS})
    manifest = {
        "schema": CAPSULE_SCHEMA, "capsule_id": public_identity["capsule_id"],
        "backup_identity_sha256": _sha(_canonical(public_identity)), "project": public_identity["project"],
        "state_id": public_identity["state_id"], "compose_env_sha256": public_identity["compose_env_sha256"],
        "members": {name: _member(data) for name, data in files.items()},
    }
    return _tar_bytes({"capsule-manifest.json": _canonical(manifest), **files}, PRIVATE_NAMES)


def load_public_evidence(state_dir: Path, verifier_evidence_names: tuple[str, ...]) -> dict[str, bytes]:
    root = state_dir / "evidence" / "hrh-published"
    try:
        order = (*verifier_evidence_names, "SHA256SUMS.json", "trust.json", "verification.json")
        entries = list(root.iterdir())
        if {path.name for path in entries} != set(order) or any(path.is_symlink() or not path.is_file() for path in entries):
            raise CapsuleError("RECOVERY_EVIDENCE_UNAVAILABLE")
        return {name: read_bounded_regular(root / name, limit=16 * 1024 * 1024, code="RECOVERY_EVIDENCE_UNAVAILABLE") for name in order}
    except OSError as exc:
        raise CapsuleError("RECOVERY_EVIDENCE_UNAVAILABLE") from exc


def _safe_tar(payload: bytes) -> tuple[dict[str, bytes], list[str], dict[str, str]]:
    files: dict[str, bytes] = {}
    order: list[str] = []
    ownership: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=BytesIO(payload), mode="r:") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if not member.isreg() or path.is_absolute() or ".." in path.parts or member.name in files:
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                handle = archive.extractfile(member)
                if handle is None:
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                files[member.name] = handle.read()
                order.append(member.name)
                ownership[member.name] = _sha(_canonical({"uid": member.uid, "gid": member.gid, "mode": member.mode}))
    except CapsuleError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID") from exc
    return files, order, ownership


def _validate_nested_tar(payload: bytes) -> None:
    names: set[str] = set()
    try:
        with tarfile.open(fileobj=BytesIO(payload), mode="r:") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or member.name in names:
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                if not (member.isdir() or member.isreg()):
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                names.add(member.name)
    except CapsuleError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID") from exc


def _validate_nested_tar_path(path: Path) -> None:
    names: set[str] = set()
    try:
        with tarfile.open(path, mode="r:") as archive:
            for member in archive.getmembers():
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or member.name in names or not (member.isdir() or member.isreg()):
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                names.add(member.name)
    except CapsuleError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID") from exc


def validate_capsule_plaintext(plaintext: bytes, *, public_identity: Mapping[str, Any]) -> dict[str, Any]:
    files, names, ownership = _safe_tar(plaintext)
    if set(files) != set(PRIVATE_NAMES):
        raise CapsuleError("RECOVERY_CAPSULE_INVALID")
    manifest = parse_closed_json(files["capsule-manifest.json"], document="capsule manifest")
    required = {"schema", "capsule_id", "backup_identity_sha256", "project", "state_id", "compose_env_sha256", "members"}
    if set(manifest) != required or manifest["schema"] != CAPSULE_SCHEMA:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID")
    bindings = {
        "capsule_id": public_identity["capsule_id"], "project": public_identity["project"],
        "state_id": public_identity["state_id"], "compose_env_sha256": public_identity["compose_env_sha256"],
        "backup_identity_sha256": _sha(_canonical(public_identity)),
    }
    if any(manifest[key] != value for key, value in bindings.items()):
        raise CapsuleError("RECOVERY_GENERATION_MISMATCH")
    private = set(PRIVATE_NAMES) - {"capsule-manifest.json"}
    if set(manifest["members"]) != private:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID")
    for name in private:
        declaration = manifest["members"][name]
        if not isinstance(declaration, dict) or set(declaration) != {"sha256", "size", "ownership_sha256"}:
            raise CapsuleError("RECOVERY_CAPSULE_INVALID")
        if declaration["sha256"] != _sha(files[name]) or declaration["size"] != len(files[name]) or declaration["ownership_sha256"] != ownership[name]:
            raise CapsuleError("RECOVERY_CAPSULE_INVALID")
        _validate_nested_tar(files[name])
    return {"manifest": manifest, "members": files, "member_names": names}


def extract_capsule_plaintext(path: Path, private_root: Path, *, public_identity: Mapping[str, Any]) -> dict[str, Any]:
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != list(PRIVATE_NAMES) or any(not member.isreg() for member in members):
                raise CapsuleError("RECOVERY_CAPSULE_INVALID")
            manifest_stream = archive.extractfile(members[0])
            if manifest_stream is None or members[0].size > 1024 * 1024:
                raise CapsuleError("RECOVERY_CAPSULE_INVALID")
            manifest_raw = manifest_stream.read(1024 * 1024 + 1)
            manifest = parse_closed_json(manifest_raw, document="capsule manifest")
            required = {"schema", "capsule_id", "backup_identity_sha256", "project", "state_id", "compose_env_sha256", "members"}
            bindings = {
                "schema": CAPSULE_SCHEMA, "capsule_id": public_identity["capsule_id"],
                "backup_identity_sha256": _sha(_canonical(public_identity)), "project": public_identity["project"],
                "state_id": public_identity["state_id"], "compose_env_sha256": public_identity["compose_env_sha256"],
            }
            if set(manifest) != required or _canonical(manifest) != manifest_raw or any(manifest.get(key) != value for key, value in bindings.items()):
                raise CapsuleError("RECOVERY_CAPSULE_INVALID")
            declarations = manifest.get("members")
            expected_names = set(PRIVATE_NAMES) - {"capsule-manifest.json"}
            if not isinstance(declarations, dict) or set(declarations) != expected_names:
                raise CapsuleError("RECOVERY_CAPSULE_INVALID")
            (private_root / "volumes").mkdir(mode=0o700, parents=True)
            for member in members[1:]:
                declaration = declarations[member.name]
                ownership = _sha(_canonical({"uid": member.uid, "gid": member.gid, "mode": member.mode}))
                if not isinstance(declaration, dict) or set(declaration) != {"sha256", "size", "ownership_sha256"} or declaration["size"] != member.size or declaration["ownership_sha256"] != ownership:
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                source = archive.extractfile(member)
                if source is None:
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                destination = private_root / member.name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with destination.open("xb") as output:
                    while chunk := source.read(64 * 1024):
                        output.write(chunk)
                        digest.update(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if digest.hexdigest() != declaration["sha256"]:
                    raise CapsuleError("RECOVERY_CAPSULE_INVALID")
                _validate_nested_tar_path(destination)
            return {"manifest": manifest, "member_names": [member.name for member in members], "private_root": private_root}
    except CapsuleError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID") from exc


def validate_identity_input(payload: bytes | None, *, declared: bool = True) -> bytes:
    if not declared or payload is None:
        raise CapsuleError("RECOVERY_IDENTITY_REQUIRED")
    if len(payload) > 4096 or not _NATIVE_IDENTITY.fullmatch(payload) or not _valid_bech32(payload[:-1]):
        raise CapsuleError("RECOVERY_CAPSULE_UNAVAILABLE")
    return payload


def _valid_bech32(record: bytes) -> bool:
    """Validate the checksum on an ASCII age native identity record."""
    try:
        text = record.decode("ascii").lower()
    except UnicodeDecodeError:
        return False
    split = text.rfind("1")
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if split < 1 or len(text) - split - 1 < 6:
        return False
    try:
        values = [alphabet.index(char) for char in text[split + 1 :]]
    except ValueError:
        return False
    expanded = [ord(char) >> 5 for char in text[:split]] + [0] + [ord(char) & 31 for char in text[:split]]
    check = 1
    for value in [*expanded, *values]:
        top = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (top >> index) & 1:
                check ^= generator
    return check == 1


def _linux_group_has_live_members(group: int, *, deadline: float) -> bool:
    proc = Path("/proc")
    if not proc.is_dir():
        raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
    try:
        entries = proc.iterdir()
        for entry in entries:
            if time.monotonic() >= deadline:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
            if not entry.name.isdecimal():
                continue
            try:
                descriptor = os.open(
                    entry / "stat", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    raw = os.read(descriptor, 4097)
                finally:
                    os.close(descriptor)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from exc
            if len(raw) > 4096:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
            closing = raw.rfind(b")")
            if closing < 1:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
            fields = raw[closing + 1 :].split()
            if len(fields) < 3 or len(fields[0]) != 1:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
            try:
                process_group = int(fields[2])
            except ValueError as exc:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from exc
            if process_group == group and fields[0] != b"Z":
                return True
    except CapsuleError:
        raise
    except OSError as exc:
        raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from exc
    return False


def run_sealer(
    *, executable: Path, arguments: tuple[str, ...], stdin: bytes, output: Path,
    timeout_seconds: float, environment: Mapping[str, str], runner: Callable[..., Any] | None = None,
    inherited_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    if output.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    partial = output.parent / f".{output.name}.partial-{os.urandom(8).hex()}"
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    process: subprocess.Popen[bytes] | None = None
    feeder: threading.Thread | None = None
    feeder_joined = False

    def join_feeder() -> None:
        nonlocal feeder_joined
        if feeder is not None and not feeder_joined:
            feeder.join(max(0.0, deadline - time.monotonic()))
            feeder_joined = not feeder.is_alive()

    def terminate_group() -> None:
        if process is None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (subprocess.SubprocessError, OSError):
            pass
        join_feeder()

    deadline = time.monotonic() + timeout_seconds
    try:
        if runner is not None:
            completed = runner(
                [str(executable), *arguments], input=stdin, capture_output=True,
                env=dict(environment), timeout=max(0.0, deadline - time.monotonic()),
            )
            if completed.returncode != 0:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
            data = completed.stdout
            with partial.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            result_sha256, result_size = _sha(data), len(data)
        else:
            descriptor = os.open(
                partial,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w+b") as output_stream:
                kwargs: dict[str, Any] = {
                    "stdin": subprocess.PIPE,
                    "stdout": output_stream,
                    "stderr": subprocess.DEVNULL,
                    "env": dict(environment),
                }
                if os.name == "posix":
                    kwargs["start_new_session"] = True
                    kwargs["pass_fds"] = inherited_fds
                process = subprocess.Popen([str(executable), *arguments], **kwargs)
                failures: list[BaseException] = []

                def feed() -> None:
                    try:
                        assert process.stdin is not None
                        process.stdin.write(stdin)
                        process.stdin.close()
                    except (BrokenPipeError, OSError) as exc:
                        failures.append(exc)

                feeder = threading.Thread(target=feed)
                feeder.start()
                try:
                    process.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    terminate_group()
                    raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from None
                join_feeder()
                if feeder.is_alive() or failures:
                    terminate_group()
                    raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
                if process.returncode:
                    terminate_group()
                    raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
                if sys.platform.startswith("linux") and _linux_group_has_live_members(
                    process.pid, deadline=deadline,
                ):
                    terminate_group()
                    while _linux_group_has_live_members(process.pid, deadline=deadline):
                        time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
                    raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
                output_stream.flush()
                os.fsync(output_stream.fileno())
                output_stream.seek(0)
                digest, result_size = hashlib.sha256(), 0
                while chunk := output_stream.read(64 * 1024):
                    digest.update(chunk)
                    result_size += len(chunk)
                result_sha256 = digest.hexdigest()
        os.chmod(partial, 0o600)
        os.replace(partial, output)
        _fsync_directory(output.parent)
        return {"sha256": result_sha256, "size": result_size, "stderr": b""}
    except CapsuleError:
        terminate_group()
        partial.unlink(missing_ok=True)
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        terminate_group()
        partial.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from exc


def encrypt_private_capsule(
    *, sealer: Path, recipient: str, plaintext: bytes, output: Path,
    timeout_seconds: float, environment: Mapping[str, str], runner: Callable[..., Any] | None = None,
    inherited_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    return run_sealer(executable=sealer, arguments=("--encrypt", "--recipient", recipient), stdin=plaintext, output=output, timeout_seconds=timeout_seconds, environment=environment, runner=runner, inherited_fds=inherited_fds)


def decrypt_private_capsule(
    *, sealer: Path, capsule: Path, identity: bytes, output: Path,
    timeout_seconds: float, environment: Mapping[str, str], runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if output.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    validate_identity_input(identity)
    return run_sealer(executable=sealer, arguments=("--decrypt", "--identity", "-", str(capsule)), stdin=identity, output=output, timeout_seconds=timeout_seconds, environment=environment, runner=runner)


def authorize_restore_trust(
    archived_raw: bytes, fresh_raw: bytes, *, recipient_sha256: str, now: datetime,
    identity_reader: Callable[[], Any], read_identity: bool = True,
) -> dict[str, Any]:
    archived = _parse_recovery_trust(archived_raw, require_one_active=False)
    fresh = _parse_recovery_trust(fresh_raw, require_one_active=False)
    if any(fresh[field] != archived[field] for field in ("schema", "scheme", "sealer_sha256")):
        raise CapsuleError("RECOVERY_TRUST_MISMATCH")
    if fresh["policy_epoch"] < archived["policy_epoch"]:
        raise CapsuleError("RECOVERY_POLICY_ROLLBACK")
    old = next((item for item in archived["recipients"] if item["recipient_sha256"] == recipient_sha256), None)
    current = next((item for item in fresh["recipients"] if item["recipient_sha256"] == recipient_sha256), None)
    if old is None or current is None or current["status"] == "revoked":
        raise CapsuleError("RECOVERY_RECIPIENT_REVOKED")
    if old["status"] == "retired" and current["status"] == "active":
        raise CapsuleError("RECOVERY_RECIPIENT_REVOKED")
    if now < _time(current["not_before"]):
        raise CapsuleError("RECOVERY_RECIPIENT_NOT_YET_VALID")
    if now >= _time(current["not_after"]):
        raise CapsuleError("RECOVERY_RECIPIENT_EXPIRED")
    if _time(current["not_before"]) != _time(old["not_before"]) or _time(current["not_after"]) > _time(old["not_after"]):
        raise CapsuleError("RECOVERY_RECIPIENT_REVOKED")
    if read_identity:
        identity_reader()
    return {"archived": archived, "fresh": fresh, "recipient": current}


def classify_restore_bundle(backup_dir: Path, *, open_member: Callable[[str], Any]) -> str:
    raw = (backup_dir / "backup-manifest.json").read_bytes()
    schema = parse_closed_json(raw, document="backup manifest").get("schema")
    if schema == PUBLISHED_V1:
        raise CapsuleError("PUBLISHED_BACKUP_V1_UNSAFE")
    if schema not in {SOURCE_V1, PUBLIC_SCHEMA}:
        raise CapsuleError("RECOVERY_SCHEMA_MISMATCH")
    return schema


def require_restore_schema(selected: str, actual: str, *, mutate: Callable[[], Any]) -> None:
    if selected != actual:
        raise CapsuleError("RECOVERY_SCHEMA_MISMATCH")
    mutate()


def validate_public_bundle(
    public: Path, *, expected_manifest_sha256: str,
    verifier_evidence_names: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    expected_files = {"COMPLETE", "backup-identity.json", "backup-manifest.json", "public-evidence.tar", "recovery-trust.json"}
    try:
        entries = list(public.iterdir())
    except OSError as exc:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH") from exc
    if {item.name for item in entries} != expected_files or any(item.is_symlink() or not item.is_file() for item in entries):
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    if read_bounded_regular(public / "COMPLETE", limit=9, code="RECOVERY_MANIFEST_MISMATCH") != b"complete\n":
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    manifest_raw = read_bounded_regular(public / "backup-manifest.json", limit=1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
    if _sha(manifest_raw) != expected_manifest_sha256:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    manifest = parse_closed_json(manifest_raw, document="backup manifest")
    if _canonical(manifest) != manifest_raw:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    if set(manifest) != {"schema", "synthetic_only", "complete", "backup_identity_sha256", "recovery_trust_sha256", "public_evidence", "recovery_capsule", "members"} or manifest.get("synthetic_only") is not True or manifest.get("complete") is not True:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    identity_raw = read_bounded_regular(public / "backup-identity.json", limit=1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
    identity = parse_closed_json(identity_raw, document="backup identity")
    identity_fields = {"schema", "project", "state_id", "compose_env_sha256", "runtime_source", "hrh_candidate", "effective_images", "volumes", "excluded_volume", "capsule_id", "recipient_sha256", "recovery_policy_epoch", "recovery_trust_sha256", "sealer_sha256"}
    if set(identity) != identity_fields or identity.get("schema") != IDENTITY_SCHEMA or _canonical(identity) != identity_raw:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    trust_raw = read_bounded_regular(public / "recovery-trust.json", limit=1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
    if manifest.get("schema") != PUBLIC_SCHEMA or manifest.get("backup_identity_sha256") != _sha(identity_raw):
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    if manifest.get("recovery_trust_sha256") != _sha(trust_raw):
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    members = manifest.get("members")
    if not isinstance(members, dict) or set(members) != {"backup-identity.json", "public-evidence.tar", "recovery-trust.json"} or manifest.get("public_evidence") != members.get("public-evidence.tar"):
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    for name, declaration in members.items():
        data = read_bounded_regular(public / name, limit=16 * 1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
        if not isinstance(declaration, dict) or set(declaration) != {"sha256", "size", "ownership_sha256"} or declaration.get("sha256") != _sha(data) or declaration.get("size") != len(data) or not _SHA256.fullmatch(str(declaration.get("ownership_sha256", ""))):
            raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    if verifier_evidence_names is not None:
        _evidence, evidence_order, _ownership = _safe_tar(
            read_bounded_regular(public / "public-evidence.tar", limit=16 * 1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
        )
        expected_order = [*verifier_evidence_names, "SHA256SUMS.json", "trust.json", "verification.json"]
        if evidence_order != expected_order:
            raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    parse_recovery_trust(trust_raw, now=datetime.now(UTC))
    return {"manifest": manifest, "identity": identity, "archived_trust": trust_raw}


def snapshot_and_validate_public_bundle(
    public: Path, staging_parent: Path, *, project: str, expected_manifest_sha256: str,
    verifier_evidence_names: tuple[str, ...],
) -> dict[str, Any]:
    run_id = os.urandom(16).hex()
    run = staging_parent / f".capsule-run-{run_id}"
    run.mkdir(mode=0o700)
    _write_fsynced(run / ".clinical-recovery-owner.json", _canonical(_owner(run, project=project, run_id=run_id, mode="restore")))
    snapshot = run / "public"
    snapshot.mkdir(mode=0o700)
    try:
        manifest_raw = read_bounded_regular(public / "backup-manifest.json", limit=1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
        if _sha(manifest_raw) != expected_manifest_sha256:
            raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
        manifest = parse_closed_json(manifest_raw, document="backup manifest")
        members = manifest.get("members", {})
        declarations = {
            "COMPLETE": {"size": 9, "sha256": _sha(b"complete\n")},
            "backup-manifest.json": {"size": len(manifest_raw), "sha256": expected_manifest_sha256},
            **{name: members.get(name, {}) for name in ("backup-identity.json", "public-evidence.tar", "recovery-trust.json")},
        }
        for name, declaration in declarations.items():
            snapshot_declared_member(public / name, snapshot / name, declared_size=declaration.get("size", -1), declared_sha256=declaration.get("sha256", ""))
        return validate_public_bundle(snapshot, expected_manifest_sha256=expected_manifest_sha256, verifier_evidence_names=verifier_evidence_names)
    finally:
        _remove_private_tree(run)


def validate_recovery_pair(
    pair: Mapping[str, Any], *, expected_manifest_sha256: str,
    fresh_trust: bytes, acquired_generation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    validated = validate_public_bundle(
        Path(pair["public_dir"]), expected_manifest_sha256=expected_manifest_sha256,
    )
    manifest, identity = validated["manifest"], validated["identity"]
    declared = manifest.get("recovery_capsule", {})
    if not isinstance(declared, dict) or set(declared) != {"capsule_id", "ciphertext_sha256", "ciphertext_size"} or declared.get("capsule_id") != identity.get("capsule_id") or not _HEX32.fullmatch(str(declared.get("capsule_id", ""))) or not _SHA256.fullmatch(str(declared.get("ciphertext_sha256", ""))) or isinstance(declared.get("ciphertext_size"), bool) or not isinstance(declared.get("ciphertext_size"), int) or declared["ciphertext_size"] < 1:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    _validate_regular_digest(
        Path(pair["capsule_path"]), declared_size=declared["ciphertext_size"],
        declared_sha256=declared["ciphertext_sha256"],
    )
    if acquired_generation is not None and identity.get("hrh_candidate") != acquired_generation:
        raise CapsuleError("RECOVERY_GENERATION_MISMATCH")
    fresh = parse_recovery_trust(fresh_trust, now=datetime.now(UTC))
    if identity.get("recovery_trust_sha256") != _sha(validated["archived_trust"]) or fresh.get("policy_epoch", 0) < identity.get("recovery_policy_epoch", 0):
        raise CapsuleError("RECOVERY_TRUST_MISMATCH")
    return validated


def prepare_published_restore(
    staging: Any, public_dir: Path, capsule_path: Path, recovery_trust_path: Path,
    recovery_sealer: Path, expected_manifest_sha256: str, *, now: datetime,
) -> dict[str, Any]:
    paths = [public_dir, capsule_path, recovery_trust_path, recovery_sealer, staging.state_dir, staging.runtime]
    if getattr(staging, "hrh", None) is not None:
        paths.append(staging.hrh)
    if any(_overlap(left, right) for index, left in enumerate(paths) for right in paths[index + 1:]):
        raise CapsuleError("published recovery paths overlap")
    _reject_inode_aliases(paths)
    source_fds: list[int] = []
    try:
        public_fd, _public_token = _open_trusted_directory(
            public_dir, allowed_modes=frozenset({0o700, 0o750}),
        )
        if public_fd is not None:
            source_fds.append(public_fd)
        stable_public = _descriptor_path(public_fd, public_dir)
        stable_sources: list[Path] = []
        for source in (capsule_path, recovery_trust_path, recovery_sealer):
            parent_fd, _parent_token = _open_trusted_directory(source.parent)
            if parent_fd is not None:
                source_fds.append(parent_fd)
            stable_sources.append(_descriptor_path(parent_fd, source.parent) / source.name)
        stable_capsule, stable_trust, stable_sealer = stable_sources
    except Exception:
        for descriptor in source_fds:
            os.close(descriptor)
        raise
    _require_trusted_parent(staging.state_dir.parent)
    for parent in {staging.state_dir.parent, public_dir.parent, capsule_path.parent}:
        reconcile_owned_staging(parent, project=staging.project)
    run_id = os.urandom(16).hex()
    run = staging.state_dir.parent / f".capsule-run-{run_id}"
    run.mkdir(mode=0o700)
    (run / ".clinical-recovery-owner.json").write_bytes(
        _canonical(_owner(run, project=staging.project, run_id=run_id, mode="restore"))
    )
    try:
        manifest_raw = read_bounded_regular(stable_public / "backup-manifest.json", limit=1024 * 1024, code="RECOVERY_MANIFEST_MISMATCH")
        if _sha(manifest_raw) != expected_manifest_sha256:
            raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
        manifest = parse_closed_json(manifest_raw, document="backup manifest")
        members = manifest.get("members", {})
        snapshot = run / "public"
        snapshot.mkdir(mode=0o700)
        snapshot_declared_member(stable_public / "COMPLETE", snapshot / "COMPLETE", declared_size=9, declared_sha256=_sha(b"complete\n"))
        snapshot_declared_member(stable_public / "backup-manifest.json", snapshot / "backup-manifest.json", declared_size=len(manifest_raw), declared_sha256=expected_manifest_sha256)
        for name in ("backup-identity.json", "public-evidence.tar", "recovery-trust.json"):
            declaration = members.get(name, {})
            snapshot_declared_member(stable_public / name, snapshot / name, declared_size=declaration.get("size", -1), declared_sha256=declaration.get("sha256", ""))
        declared_capsule = manifest.get("recovery_capsule", {})
        capsule_snapshot = snapshot_declared_member(
            stable_capsule, run / "capsule.age", declared_size=declared_capsule.get("ciphertext_size", -1),
            declared_sha256=declared_capsule.get("ciphertext_sha256", ""),
        )
        fresh_trust = read_bounded_regular(stable_trust, limit=1024 * 1024, code="RECOVERY_TRUST_UNAVAILABLE")
        fresh = parse_recovery_trust(fresh_trust, now=now)
        sealer = snapshot_sealer(stable_sealer, run / "sealer", fresh["sealer_sha256"])
        result = validate_recovery_pair(
            {"public_dir": snapshot, "capsule_path": capsule_snapshot}, expected_manifest_sha256=expected_manifest_sha256,
            fresh_trust=fresh_trust, acquired_generation=None,
        )
        authorize_restore_trust(
            result["archived_trust"], fresh_trust, recipient_sha256=result["identity"]["recipient_sha256"],
            now=now, identity_reader=lambda: None, read_identity=False,
        )
        return {"run": run, "public": snapshot, "capsule": capsule_snapshot, "sealer": sealer, "fresh_trust": fresh_trust, "result": result}
    except Exception:
        _remove_private_tree(run)
        raise
    finally:
        for descriptor in source_fds:
            os.close(descriptor)


def cleanup_prepared_restore(prepared: Mapping[str, Any]) -> None:
    _remove_private_tree(Path(prepared["run"]))


def _owner(stage: Path, *, project: str, run_id: str, mode: str) -> dict[str, Any]:
    return {"schema": RUN_SCHEMA, "project": project, "run_id": run_id, "root": str(stage.resolve()), "mode": mode}


def _remove_private_tree(path: Path) -> None:
    def writable_then_retry(function, item, _error):
        os.chmod(item, 0o700)
        function(item)
    if path.exists():
        shutil.rmtree(path, onerror=writable_then_retry)


def reconcile_capsule_outputs(
    *, capsule_path: Path, public_dir: Path, staging_parent: Path,
    project: str, run_id: str, mode: str,
) -> dict[str, Any]:
    stage = staging_parent / f".capsule-run-{run_id}"
    marker = stage / ".clinical-recovery-owner.json"
    try:
        if stage.is_dir() and not marker.is_symlink() and marker.is_file():
            raw = marker.read_bytes()
            if parse_closed_json(raw, document="recovery owner") == _owner(stage, project=project, run_id=run_id, mode=mode) and _canonical(parse_closed_json(raw, document="recovery owner")) == raw:
                shutil.rmtree(stage)
    except (OSError, CapsuleError):
        pass
    if capsule_path.exists() and not (public_dir / "COMPLETE").is_file():
        return {"code": "RECOVERY_CAPSULE_ORPHANED"}
    return {"code": "CLEAN"}


def reconcile_owned_staging(parent: Path, *, project: str) -> None:
    try:
        candidates = []
        for path in parent.iterdir():
            if path.name.startswith(".capsule-run-"):
                candidates.append(path)
                if len(candidates) > 8:
                    raise CapsuleError("RECOVERY_STAGING_UNAVAILABLE")
    except OSError as exc:
        raise CapsuleError("RECOVERY_STAGING_UNAVAILABLE") from exc
    for stage in candidates:
        match = re.fullmatch(r"\.capsule-run-([0-9a-f]{32})", stage.name)
        marker = stage / ".clinical-recovery-owner.json"
        if match is None or stage.is_symlink() or not stage.is_dir() or marker.is_symlink() or not marker.is_file():
            continue
        try:
            raw = read_bounded_regular(marker, limit=4096, code="RECOVERY_STAGING_UNAVAILABLE")
            owner = parse_closed_json(raw, document="recovery owner")
            if owner.get("mode") not in {"backup", "restore"}:
                continue
            expected = _owner(stage, project=project, run_id=match.group(1), mode=owner["mode"])
            if owner == expected and _canonical(owner) == raw:
                _remove_private_tree(stage)
        except CapsuleError:
            continue


def build_private_backup_inputs(
    staging: Any, target: Path, marker: Mapping[str, Any], *, volume_directory: str,
    state_archive: str, volume_keys: tuple[str, ...], create_state: Callable[[Path, Path], Any],
) -> None:
    target.mkdir(mode=0o700)
    (target / volume_directory).mkdir(mode=0o700)
    create_state(staging.state_dir, target / state_archive)
    staging.compose("down", timeout=600)
    for key in volume_keys:
        staging._assert_unmounted_backup_volumes(marker["volumes"])
        staging._backup_volume(key, marker["volumes"][key], target)


def publish_recovery_pair(
    *, public_dir: Path, capsule_path: Path, public_identity: Mapping[str, Any],
    recovery_trust: bytes, private_plaintext: bytes, sealer: Path,
    evidence: Mapping[str, bytes] | None = None,
    observer: Callable[[str], Any] = lambda _stage: None,
) -> dict[str, Any]:
    if public_dir.exists() or capsule_path.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    public_modes = frozenset({0o700, 0o750})
    capsule_modes = frozenset({0o700})
    public_parent_fd, public_parent_token = _open_trusted_directory(
        public_dir.parent, allowed_modes=public_modes,
    )
    try:
        capsule_parent_fd, capsule_parent_token = _open_trusted_directory(
            capsule_path.parent, allowed_modes=capsule_modes,
        )
    except Exception:
        if public_parent_fd is not None:
            os.close(public_parent_fd)
        raise
    run_id = os.urandom(16).hex()
    stage = capsule_path.parent / f".capsule-run-{run_id}"
    public_run_id = os.urandom(16).hex()
    public_stage = public_dir.parent / f".capsule-run-{public_run_id}"
    stage_fd = public_stage_fd = None
    try:
        if capsule_parent_fd is None:
            stage.mkdir(mode=0o700)
        else:
            os.mkdir(stage.name, mode=0o700, dir_fd=capsule_parent_fd)
            stage_fd = os.open(
                stage.name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=capsule_parent_fd,
            )
        stable_stage = _descriptor_path(stage_fd, stage)
        _write_fsynced(stable_stage / ".clinical-recovery-owner.json", _canonical(_owner(stage, project=public_identity["project"], run_id=run_id, mode="backup")))
        if stage_fd is None:
            _fsync_directory(stage)
        else:
            os.fsync(stage_fd)
        if capsule_parent_fd is None:
            _fsync_directory(capsule_path.parent)
        else:
            os.fsync(capsule_parent_fd)
        if public_parent_fd is None:
            public_stage.mkdir(mode=0o700)
        else:
            os.mkdir(public_stage.name, mode=0o700, dir_fd=public_parent_fd)
            public_stage_fd = os.open(
                public_stage.name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=public_parent_fd,
            )
        stable_public_stage = _descriptor_path(public_stage_fd, public_stage)
        _write_fsynced(stable_public_stage / ".clinical-recovery-owner.json", _canonical(_owner(public_stage, project=public_identity["project"], run_id=public_run_id, mode="backup")))
        if public_stage_fd is None:
            _fsync_directory(public_stage)
        else:
            os.fsync(public_stage_fd)
        if public_parent_fd is None:
            _fsync_directory(public_dir.parent)
        else:
            os.fsync(public_parent_fd)
    except Exception:
        if stage_fd is not None:
            os.close(stage_fd)
        if public_stage_fd is not None:
            os.close(public_stage_fd)
        _remove_private_tree_from(capsule_parent_fd, stage)
        _remove_private_tree_from(public_parent_fd, public_stage)
        if capsule_parent_fd is not None:
            os.close(capsule_parent_fd)
        if public_parent_fd is not None:
            os.close(public_parent_fd)
        raise
    stable_stage = _descriptor_path(stage_fd, stage)
    stable_public_stage = _descriptor_path(public_stage_fd, public_stage)
    temp_capsule = stable_stage / "capsule.age"
    temp_public = stable_public_stage / "public"
    try:
        trust = parse_recovery_trust(recovery_trust, now=datetime.now(UTC))
        recipient = select_backup_recipient(trust, now=datetime.now(UTC))
        sealer = snapshot_sealer(sealer, stable_stage / "sealer", trust["sealer_sha256"])
        if _require_trusted_parent(capsule_path.parent, allowed_modes=capsule_modes) != capsule_parent_token:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if _require_trusted_parent(public_dir.parent, allowed_modes=public_modes) != public_parent_token:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if not _retained_directory_is_current(
            capsule_path.parent, capsule_parent_fd, capsule_parent_token,
            allowed_modes=capsule_modes,
        ) or not _retained_directory_is_current(
            public_dir.parent, public_parent_fd, public_parent_token,
            allowed_modes=public_modes,
        ):
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if not _retained_directory_is_current(
            capsule_path.parent, capsule_parent_fd, capsule_parent_token,
            allowed_modes=capsule_modes,
        ):
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        result = encrypt_private_capsule(
            sealer=sealer, recipient=recipient["recipient"], plaintext=private_plaintext,
            output=temp_capsule, timeout_seconds=30, environment={},
            inherited_fds=(stage_fd,) if stage_fd is not None else (),
        )
        observer("CAPSULE_CIPHERTEXT_FSYNCED")
        if _require_trusted_parent(capsule_path.parent, allowed_modes=capsule_modes) != capsule_parent_token:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if capsule_parent_fd is None:
            os.replace(temp_capsule, capsule_path)
        else:
            os.replace(temp_capsule, capsule_path.name, dst_dir_fd=capsule_parent_fd)
        observer("CAPSULE_PUBLISHED")
        if capsule_parent_fd is None:
            _fsync_directory(capsule_path.parent)
        else:
            os.fsync(capsule_parent_fd)
        observer("CAPSULE_PARENT_FSYNCED")
        build_public_bundle(temp_public, public_identity=public_identity, recovery_trust=recovery_trust, evidence=evidence or {}, capsule_sha256=result["sha256"], capsule_size=result["size"], observer=observer)
        if _require_trusted_parent(public_dir.parent, allowed_modes=public_modes) != public_parent_token:
            raise CapsuleError("RECOVERY_OUTPUT_PARENT_UNTRUSTED")
        if public_parent_fd is None:
            os.replace(temp_public, public_dir)
        else:
            os.replace(temp_public, public_dir.name, dst_dir_fd=public_parent_fd)
        observer("PUBLIC_PUBLISHED")
        if public_parent_fd is None:
            _fsync_directory(public_dir.parent)
        else:
            os.fsync(public_parent_fd)
        observer("PUBLIC_PARENT_FSYNCED")
        final_manifest_raw = read_bounded_regular(public_dir / "backup-manifest.json", limit=1024 * 1024, code="RECOVERY_PUBLICATION_INCOMPLETE")
        declared = parse_closed_json(
            final_manifest_raw,
            document="backup manifest",
        )["recovery_capsule"]
        snapshot_declared_member(capsule_path, stage / "final-capsule.check", declared_size=declared["ciphertext_size"], declared_sha256=declared["ciphertext_sha256"])
        if read_bounded_regular(public_dir / "COMPLETE", limit=9, code="RECOVERY_PUBLICATION_INCOMPLETE") != b"complete\n":
            raise CapsuleError("RECOVERY_PUBLICATION_INCOMPLETE")
        return {"manifest_sha256": _sha(final_manifest_raw)}
    except Exception as exc:
        if public_dir.exists() and (public_dir / "COMPLETE").is_file():
            pass
        else:
            if public_dir.exists():
                shutil.rmtree(public_dir, ignore_errors=True)
            capsule_path.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_PUBLICATION_INCOMPLETE") from exc
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if public_stage_fd is not None:
            os.close(public_stage_fd)
        _remove_private_tree_from(capsule_parent_fd, stage)
        _remove_private_tree_from(public_parent_fd, public_stage)
        if capsule_parent_fd is not None:
            os.close(capsule_parent_fd)
        if public_parent_fd is not None:
            os.close(public_parent_fd)


def finish_published_backup(
    staging: Any, private_root: Path, marker: Mapping[str, Any], public_dir: Path, *,
    recovery_trust_path: Path | None, recovery_sealer: Path | None, capsule_path: Path | None,
    contract: Any, receipt_builder: Callable[..., Mapping[str, Any]], now: datetime,
    verifier_evidence_names: tuple[str, ...], private_builder: Callable[[], Any] | None = None,
) -> Mapping[str, Any]:
    if recovery_trust_path is None or recovery_sealer is None or capsule_path is None:
        raise CapsuleError("published backup requires the complete recovery boundary")
    paths = [private_root, public_dir, recovery_trust_path, recovery_sealer, capsule_path, staging.state_dir, staging.runtime]
    if getattr(staging, "hrh", None) is not None:
        paths.append(staging.hrh)
    _require_trusted_parent(public_dir.parent, allowed_modes=frozenset({0o700, 0o750}))
    _require_trusted_parent(capsule_path.parent, allowed_modes=frozenset({0o700}))
    if any(_overlap(left, right) for index, left in enumerate(paths) for right in paths[index + 1:]):
        raise CapsuleError("published recovery paths overlap or have unavailable parents")
    _reject_inode_aliases(paths)
    reconcile_owned_staging(capsule_path.parent, project=staging.project)
    if capsule_path.exists() and not (public_dir / "COMPLETE").is_file():
        raise CapsuleError("RECOVERY_CAPSULE_ORPHANED")
    trust_bytes = read_bounded_regular(recovery_trust_path, limit=1024 * 1024, code="RECOVERY_TRUST_UNAVAILABLE")
    trust = parse_recovery_trust(trust_bytes, now=now)
    recipient = select_backup_recipient(trust, now=now)
    preflight = capsule_path.parent / f".capsule-run-{os.urandom(16).hex()}"
    preflight.mkdir(mode=0o700)
    preflight_run_id = preflight.name.removeprefix(".capsule-run-")
    _write_fsynced(
        preflight / ".clinical-recovery-owner.json",
        _canonical(_owner(preflight, project=staging.project, run_id=preflight_run_id, mode="backup")),
    )
    try:
        sealer_snapshot = snapshot_sealer(recovery_sealer, preflight / "sealer", trust["sealer_sha256"])
        encrypt_private_capsule(
            sealer=sealer_snapshot, recipient=recipient["recipient"], plaintext=b"synthetic recovery preflight\n",
            output=preflight / "preflight.age", timeout_seconds=30, environment={},
        )
        if private_builder is not None:
            private_builder()
        capsule_id = os.urandom(16).hex()
        identity = build_public_identity(
            marker, recovery_trust=trust_bytes, sealer_sha256=trust["sealer_sha256"], capsule_id=capsule_id,
        )
        plaintext = build_capsule_plaintext(private_root, public_identity=identity)
        evidence = load_public_evidence(staging.state_dir, verifier_evidence_names)
        result = publish_recovery_pair(
            public_dir=public_dir, capsule_path=capsule_path, public_identity=identity,
            recovery_trust=trust_bytes, private_plaintext=plaintext, sealer=sealer_snapshot,
            evidence=evidence,
        )
        manifest = parse_closed_json((public_dir / "backup-manifest.json").read_bytes(), document="backup manifest")
        return receipt_builder(
            contract, manifest, public_dir, identity=identity,
            manifest_sha256=result["manifest_sha256"], backed_up_at=now.isoformat().replace("+00:00", "Z"),
        )
    finally:
        _remove_private_tree(preflight)
        _remove_private_tree(private_root)


def restore_published_backup(
    staging: Any, public_dir: Path, expected_manifest_sha256: str, *,
    recovery_trust_path: Path | None, recovery_sealer: Path | None,
    capsule_path: Path | None, identity_reader: Callable[[], bytes] | None,
    acquired_generation: Mapping[str, Any], contract: Any,
    receipt_builder: Callable[..., Mapping[str, Any]], renew_tls: bool, now: datetime,
    prepared: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    if recovery_trust_path is None or recovery_sealer is None or capsule_path is None:
        raise CapsuleError("published restore requires the complete recovery boundary")
    prepared = prepared or prepare_published_restore(
        staging, public_dir, capsule_path, recovery_trust_path, recovery_sealer,
        expected_manifest_sha256, now=now,
    )
    fresh_trust_bytes = prepared["fresh_trust"]
    pair_result = prepared["result"]
    identity, manifest = pair_result["identity"], pair_result["manifest"]
    archived_trust_bytes = pair_result["archived_trust"]
    fresh_trust = parse_recovery_trust(fresh_trust_bytes, now=now)
    if identity.get("hrh_candidate") != acquired_generation:
        cleanup_prepared_restore(prepared)
        raise CapsuleError("RECOVERY_GENERATION_MISMATCH")
    if identity_reader is None:
        cleanup_prepared_restore(prepared)
        raise CapsuleError("RECOVERY_IDENTITY_REQUIRED")
    identity_holder: list[bytearray] = []
    run = prepared["run"]
    plaintext_path, capsule_snapshot = run / "plaintext.tar", prepared["capsule"]
    target: Path | None = None
    published_state = False
    try:
        authorize_restore_trust(
            archived_trust_bytes, fresh_trust_bytes,
            recipient_sha256=identity["recipient_sha256"], now=now,
            identity_reader=lambda: identity_holder.append(bytearray(validate_identity_input(identity_reader()))),
        )
        decrypt_private_capsule(
            sealer=prepared["sealer"], capsule=capsule_snapshot, identity=identity_holder[0], output=plaintext_path,
            timeout_seconds=30, environment={},
        )
        private = run / "private"
        extract_capsule_plaintext(plaintext_path, private, public_identity=identity)
        staging._require_empty_restore_destination()
        target = staging.state_dir.parent / f".{staging.state_dir.name}.recovering-{os.urandom(8).hex()}"
        target.mkdir(mode=0o700)
        staging._extract_safe_state_archive(private / "state.tar", target)
        marker_path = target / "staging-state.json"
        marker = parse_closed_json(marker_path.read_bytes(), document="restored marker")
        marker_bindings = {
            "project": identity["project"], "state_id": identity["state_id"],
            "compose_env_sha256": identity["compose_env_sha256"],
            "runtime_head": identity["runtime_source"]["runtime_head"],
            "runtime_tree": identity["runtime_source"]["runtime_tree"],
            "volumes": identity["volumes"], "hrh_candidate": identity["hrh_candidate"],
            "effective_images": identity["effective_images"],
        }
        if any(marker.get(key) != value for key, value in marker_bindings.items()):
            raise CapsuleError("RECOVERY_GENERATION_MISMATCH")
        marker["state_dir"], marker["lifecycle"] = str(staging.state_dir.resolve()), "recovering"
        contract.write_json_atomic(marker_path, marker, mode=0o600)
        if hashlib.sha256((target / "compose.env").read_bytes()).hexdigest() != identity["compose_env_sha256"]:
            raise CapsuleError("RECOVERY_GENERATION_MISMATCH")
        os.replace(target, staging.state_dir)
        published_state = True
        staging._create_volumes(marker)
        for key in VOLUME_KEYS:
            staging._restore_volume(key, marker["volumes"][key], private)
        if renew_tls:
            staging._renew_tls_material(marker, restoring=True)
        staging._start_restored_stack()
        status = staging.status(_allow_recovering=True)
        marker["lifecycle"] = "ready"
        staging._write_marker(marker)
        receipt = receipt_builder(
            contract, manifest, expected_manifest_sha256, identity=identity,
            restore_trust=fresh_trust, restore_trust_sha256=_sha(fresh_trust_bytes),
            status_observed_at=status["observed_at"], restored_at=now.isoformat().replace("+00:00", "Z"),
        )
        receipt_dir = staging.state_dir / "evidence" / "recovery"
        receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        receipt_bytes = _canonical(receipt)
        write_private_atomic(receipt_dir / f"restore-{expected_manifest_sha256}.json", receipt_bytes)
        return dict(receipt, mechanical_receipt_sha256=_sha(receipt_bytes))
    except Exception:
        if published_state:
            staging._contain_failed_restore()
        raise
    finally:
        for item in identity_holder:
            item[:] = b"\x00" * len(item)
        _remove_private_tree(run)
        if target is not None and target.exists():
            _remove_private_tree(target)
