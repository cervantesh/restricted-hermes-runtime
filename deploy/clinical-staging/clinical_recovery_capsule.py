"""Closed, content-safe recovery-capsule primitives for published HRH backups."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
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


def add_finalizer_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-mechanical-receipt-sha256", required=True)
    parser.add_argument("--causal-check", action="append", required=True)


def dispatch_recovery_command(staging: Any, args: argparse.Namespace) -> Any:
    if args.command == "backup":
        return staging.backup(
            args.backup_dir, recovery_trust=args.recovery_trust,
            recovery_sealer=args.recovery_sealer, recovery_capsule=args.recovery_capsule,
        )
    if args.command == "restore":
        return staging.restore(
            args.backup_dir, args.expected_manifest_sha256, renew_tls=args.renew_tls,
            recovery_trust=args.recovery_trust, recovery_sealer=args.recovery_sealer,
            recovery_capsule=args.recovery_capsule,
            recovery_identity_reader=(lambda: sys.stdin.buffer.read(4097)) if args.recovery_identity_stdin else None,
        )
    checks = {name: True for name in args.causal_check}
    return staging.finalize_cold_recovery_verification(
        args.expected_manifest_sha256, checks, backup_dir=args.backup_dir,
        expected_mechanical_receipt_sha256=args.expected_mechanical_receipt_sha256,
    )


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(source, flags)
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(declared_size + 1)
    except OSError as exc:
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH") from exc
    if len(data) != declared_size or _sha(data) != declared_sha256:
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with destination.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o600)
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH") from exc
    return destination


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
            data = handle.read()
        if _sha(data) != expected_sha256:
            raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
        with destination.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o500)
    except CapsuleError:
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from exc
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
        (public_dir / name).write_bytes(data)
    (public_dir / "backup-manifest.json").write_bytes(_canonical(manifest))
    (public_dir / "COMPLETE").write_bytes(b"complete\n")
    return manifest


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


def load_public_evidence(state_dir: Path) -> dict[str, bytes]:
    root = state_dir / "evidence" / "hrh-published"
    try:
        names = {path.name for path in root.iterdir() if path.is_file() and path.name not in {"trust.json", "verification.json"}}
        order = (*sorted(names - {"SHA256SUMS.json"}), "SHA256SUMS.json", "trust.json", "verification.json")
        return {name: read_bounded_regular(root / name, limit=16 * 1024 * 1024, code="RECOVERY_EVIDENCE_UNAVAILABLE") for name in order}
    except OSError as exc:
        raise CapsuleError("RECOVERY_EVIDENCE_UNAVAILABLE") from exc


def _safe_tar(payload: bytes) -> tuple[dict[str, bytes], list[str]]:
    files: dict[str, bytes] = {}
    order: list[str] = []
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
    except CapsuleError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise CapsuleError("RECOVERY_CAPSULE_INVALID") from exc
    return files, order


def validate_capsule_plaintext(plaintext: bytes, *, public_identity: Mapping[str, Any]) -> dict[str, Any]:
    files, names = _safe_tar(plaintext)
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
        if declaration["sha256"] != _sha(files[name]) or declaration["size"] != len(files[name]):
            raise CapsuleError("RECOVERY_CAPSULE_INVALID")
    return {"manifest": manifest, "members": files, "member_names": names}


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


def run_sealer(
    *, executable: Path, arguments: tuple[str, ...], stdin: bytes, output: Path,
    timeout_seconds: float, environment: Mapping[str, str], runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if output.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    partial = output.parent / f".{output.name}.partial-{os.urandom(8).hex()}"
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        if runner is not None:
            completed = runner([str(executable), *arguments], input=stdin, capture_output=True, env=dict(environment), timeout=timeout_seconds)
            if completed.returncode != 0:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
            data = completed.stdout
        else:
            kwargs: dict[str, Any] = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": dict(environment)}
            if os.name == "posix":
                kwargs["start_new_session"] = True
            process = subprocess.Popen([str(executable), *arguments], **kwargs)
            try:
                data, _diagnostic = process.communicate(stdin, timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.communicate()
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from None
            if process.returncode:
                raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE")
        with partial.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(partial, 0o600)
        os.replace(partial, output)
        return {"sha256": _sha(data), "size": len(data), "stderr": b""}
    except CapsuleError:
        partial.unlink(missing_ok=True)
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        partial.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_SEALER_UNAVAILABLE") from exc


def encrypt_private_capsule(
    *, sealer: Path, recipient: str, plaintext: bytes, output: Path,
    timeout_seconds: float, environment: Mapping[str, str], runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    return run_sealer(executable=sealer, arguments=("--encrypt", "--recipient", recipient), stdin=plaintext, output=output, timeout_seconds=timeout_seconds, environment=environment, runner=runner)


def decrypt_private_capsule(
    *, sealer: Path, capsule: Path, identity: bytes, output: Path,
    timeout_seconds: float, environment: Mapping[str, str], runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    if output.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    validate_identity_input(identity)
    return run_sealer(executable=sealer, arguments=("--decrypt", "--identity", "-", str(capsule)), stdin=identity, output=output, timeout_seconds=timeout_seconds, environment=environment, runner=runner)


def authorize_restore_trust(
    archived_raw: bytes, fresh_raw: bytes, *, recipient_sha256: str, now: datetime,
    identity_reader: Callable[[], Any],
) -> dict[str, Any]:
    archived = _parse_recovery_trust(archived_raw, require_one_active=False)
    fresh = _parse_recovery_trust(fresh_raw, require_one_active=False)
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


def validate_recovery_pair(
    pair: Mapping[str, Any], *, expected_manifest_sha256: str,
    fresh_trust: bytes, acquired_generation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    public = Path(pair["public_dir"])
    expected_files = {"COMPLETE", "backup-identity.json", "backup-manifest.json", "public-evidence.tar", "recovery-trust.json"}
    try:
        entries = list(public.iterdir())
    except OSError as exc:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH") from exc
    if {item.name for item in entries} != expected_files or any(item.is_symlink() or not item.is_file() for item in entries):
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    if (public / "COMPLETE").read_bytes() != b"complete\n":
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
    parse_recovery_trust(trust_raw, now=datetime.now(UTC))
    declared = manifest.get("recovery_capsule", {})
    if not isinstance(declared, dict) or set(declared) != {"capsule_id", "ciphertext_sha256", "ciphertext_size"} or declared.get("capsule_id") != identity.get("capsule_id") or not _HEX32.fullmatch(str(declared.get("capsule_id", ""))) or not _SHA256.fullmatch(str(declared.get("ciphertext_sha256", ""))) or isinstance(declared.get("ciphertext_size"), bool) or not isinstance(declared.get("ciphertext_size"), int) or declared["ciphertext_size"] < 1:
        raise CapsuleError("RECOVERY_MANIFEST_MISMATCH")
    capsule = read_bounded_regular(Path(pair["capsule_path"]), limit=declared["ciphertext_size"], code="RECOVERY_CAPSULE_MISMATCH")
    if declared.get("ciphertext_sha256") != _sha(capsule) or declared.get("ciphertext_size") != len(capsule):
        raise CapsuleError("RECOVERY_CAPSULE_MISMATCH")
    if acquired_generation is not None and identity.get("hrh_candidate") != acquired_generation:
        raise CapsuleError("RECOVERY_GENERATION_MISMATCH")
    fresh = parse_recovery_trust(fresh_trust, now=datetime.now(UTC))
    if identity.get("recovery_trust_sha256") != _sha(trust_raw) or fresh.get("policy_epoch", 0) < identity.get("recovery_policy_epoch", 0):
        raise CapsuleError("RECOVERY_TRUST_MISMATCH")
    return {"manifest": manifest, "identity": identity, "capsule": capsule}


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


def publish_recovery_pair(
    *, public_dir: Path, capsule_path: Path, public_identity: Mapping[str, Any],
    recovery_trust: bytes, private_plaintext: bytes, sealer: Path,
    evidence: Mapping[str, bytes] | None = None,
    observer: Callable[[str], Any] = lambda _stage: None,
) -> dict[str, Any]:
    if public_dir.exists() or capsule_path.exists():
        raise CapsuleError("RECOVERY_OUTPUT_EXISTS")
    run_id = os.urandom(16).hex()
    stage = public_dir.parent / f".capsule-run-{run_id}"
    stage.mkdir(mode=0o700)
    (stage / ".clinical-recovery-owner.json").write_bytes(_canonical(_owner(stage, project=public_identity["project"], run_id=run_id, mode="backup")))
    temp_capsule = stage / "capsule.age"
    temp_public = stage / "public"
    try:
        trust = parse_recovery_trust(recovery_trust, now=datetime.now(UTC))
        recipient = select_backup_recipient(trust, now=datetime.now(UTC))
        sealer = snapshot_sealer(sealer, stage / "sealer", trust["sealer_sha256"])
        result = encrypt_private_capsule(sealer=sealer, recipient=recipient["recipient"], plaintext=private_plaintext, output=temp_capsule, timeout_seconds=30, environment={})
        observer("CAPSULE_CIPHERTEXT_FSYNCED")
        capsule_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.replace(temp_capsule, capsule_path)
        observer("CAPSULE_PUBLISHED")
        observer("CAPSULE_PARENT_FSYNCED")
        build_public_bundle(temp_public, public_identity=public_identity, recovery_trust=recovery_trust, evidence=evidence or {}, capsule_sha256=result["sha256"], capsule_size=result["size"])
        observer("PUBLIC_MANIFEST_FSYNCED")
        observer("PUBLIC_COMPLETE_FSYNCED")
        os.replace(temp_public, public_dir)
        observer("PUBLIC_PUBLISHED")
        observer("PUBLIC_PARENT_FSYNCED")
        return {"manifest_sha256": _sha((public_dir / "backup-manifest.json").read_bytes())}
    except Exception as exc:
        if public_dir.exists() and (public_dir / "COMPLETE").is_file():
            pass
        else:
            if public_dir.exists():
                shutil.rmtree(public_dir, ignore_errors=True)
            capsule_path.unlink(missing_ok=True)
        raise CapsuleError("RECOVERY_PUBLICATION_INCOMPLETE") from exc
    finally:
        _remove_private_tree(stage)


def finish_published_backup(
    staging: Any, private_root: Path, marker: Mapping[str, Any], public_dir: Path, *,
    recovery_trust_path: Path | None, recovery_sealer: Path | None, capsule_path: Path | None,
    contract: Any, receipt_builder: Callable[..., Mapping[str, Any]], now: datetime,
) -> Mapping[str, Any]:
    if recovery_trust_path is None or recovery_sealer is None or capsule_path is None:
        raise CapsuleError("published backup requires the complete recovery boundary")
    trust_bytes = read_bounded_regular(recovery_trust_path, limit=1024 * 1024, code="RECOVERY_TRUST_UNAVAILABLE")
    trust = parse_recovery_trust(trust_bytes, now=now)
    select_backup_recipient(trust, now=now)
    capsule_id = os.urandom(16).hex()
    identity = build_public_identity(
        marker, recovery_trust=trust_bytes, sealer_sha256=trust["sealer_sha256"], capsule_id=capsule_id,
    )
    plaintext = build_capsule_plaintext(private_root, public_identity=identity)
    evidence = load_public_evidence(staging.state_dir)
    try:
        result = publish_recovery_pair(
            public_dir=public_dir, capsule_path=capsule_path, public_identity=identity,
            recovery_trust=trust_bytes, private_plaintext=plaintext, sealer=recovery_sealer,
            evidence=evidence,
        )
        manifest = parse_closed_json((public_dir / "backup-manifest.json").read_bytes(), document="backup manifest")
        return receipt_builder(
            contract, manifest, public_dir, identity=identity,
            manifest_sha256=result["manifest_sha256"], backed_up_at=now.isoformat().replace("+00:00", "Z"),
        )
    finally:
        _remove_private_tree(private_root)


def restore_published_backup(
    staging: Any, public_dir: Path, expected_manifest_sha256: str, *,
    recovery_trust_path: Path | None, recovery_sealer: Path | None,
    capsule_path: Path | None, identity_reader: Callable[[], bytes] | None,
    acquired_generation: Mapping[str, Any], contract: Any,
    receipt_builder: Callable[..., Mapping[str, Any]], renew_tls: bool, now: datetime,
) -> Mapping[str, Any]:
    if recovery_trust_path is None or recovery_sealer is None or capsule_path is None:
        raise CapsuleError("published restore requires the complete recovery boundary")
    fresh_trust_bytes = read_bounded_regular(recovery_trust_path, limit=1024 * 1024, code="RECOVERY_TRUST_UNAVAILABLE")
    pair_result = validate_recovery_pair(
        {"public_dir": public_dir, "capsule_path": capsule_path},
        expected_manifest_sha256=expected_manifest_sha256,
        fresh_trust=fresh_trust_bytes, acquired_generation=acquired_generation,
    )
    identity, manifest = pair_result["identity"], pair_result["manifest"]
    archived_trust_bytes = (public_dir / "recovery-trust.json").read_bytes()
    fresh_trust = parse_recovery_trust(fresh_trust_bytes, now=now)
    if identity_reader is None:
        raise CapsuleError("RECOVERY_IDENTITY_REQUIRED")
    identity_holder: list[bytes] = []
    authorize_restore_trust(
        archived_trust_bytes, fresh_trust_bytes, recipient_sha256=identity["recipient_sha256"], now=now,
        identity_reader=lambda: identity_holder.append(validate_identity_input(identity_reader())),
    )
    run = staging.state_dir.parent / f".capsule-run-{os.urandom(16).hex()}"
    run.mkdir(mode=0o700)
    plaintext_path, capsule_snapshot = run / "plaintext.tar", run / "capsule.age"
    try:
        snapshot_declared_member(
            capsule_path, capsule_snapshot,
            declared_size=manifest["recovery_capsule"]["ciphertext_size"],
            declared_sha256=manifest["recovery_capsule"]["ciphertext_sha256"],
        )
        sealer = snapshot_sealer(recovery_sealer, run / "sealer", fresh_trust["sealer_sha256"])
        decrypt_private_capsule(
            sealer=sealer, capsule=capsule_snapshot, identity=identity_holder[0], output=plaintext_path,
            timeout_seconds=30, environment={},
        )
        decoded = validate_capsule_plaintext(plaintext_path.read_bytes(), public_identity=identity)
        private = run / "private"
        (private / "volumes").mkdir(mode=0o700, parents=True)
        for name, data in decoded["members"].items():
            if name == "capsule-manifest.json":
                continue
            destination = private / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(data)
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
    finally:
        for item in identity_holder:
            del item
        _remove_private_tree(run)
