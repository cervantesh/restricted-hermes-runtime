"""Focused controls for the isolated cold-recovery dependencies.

These two modules are introduced without touching the staging lifecycle, so the
tests here bind them to the *current* staging contract rather than to a
hand-written double: the reference `BackupContract` is assembled from the live
`clinical_staging` constants and helpers.  If the current marker or volume
contract drifts, these tests fail instead of silently validating an older
shape.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import secrets
import stat
import sys
import tarfile
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING_DIR = ROOT / "deploy" / "clinical-staging"

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="the operator recovery boundary is POSIX-only"
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` resolves string annotations through `sys.modules`, so a
    # file-loaded module must be registered before it is executed.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def staging():
    return _load("cold_recovery_staging", STAGING_DIR / "clinical_staging.py")


@pytest.fixture(scope="module")
def codec():
    return _load("cold_recovery_codec", STAGING_DIR / "clinical_backup_bundle.py")


@pytest.fixture(scope="module")
def operator_lock():
    return _load(
        "cold_recovery_operator_lock", STAGING_DIR / "clinical_operator_lock.py"
    )


# --------------------------------------------------------------------------
# Reference contract: exactly what the integration slice will have to supply.
# --------------------------------------------------------------------------

EXCLUDED_RECOVERY_VOLUME = "clinical_socket"
BACKUP_SCHEMA = "restricted-synthetic-clinical-cold-backup.v1"
BACKUP_MANIFEST_NAME = "backup-manifest.json"
BACKUP_COMPLETE_NAME = "COMPLETE"
BACKUP_STATE_ARCHIVE = "state.tar"
BACKUP_VOLUME_DIR = "volumes"


def _fsync_file(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _marker_invariant(staging) -> Callable[[Mapping[str, Any]], None]:
    """Apply the current admission rules to a marker held in memory.

    This mirrors the tail of `clinical_staging.read_marker`.  The integration
    slice will pass the staging module's own callable; keeping the rules here
    identical is what makes the seam a control rather than a placeholder.
    """

    def validate(marker: Mapping[str, Any]) -> None:
        if marker["image_mode"] not in {"exact-source", "subject-admitted"}:
            raise staging.SafetyError("staging marker image mode is invalid")
        if not isinstance(marker["subject_admission"], dict):
            raise staging.SafetyError("staging marker subject admission is invalid")
        if marker["image_mode"] == "exact-source" and marker["subject_admission"]:
            raise staging.SafetyError(
                "exact-source marker cannot retain subject admission"
            )
        if marker["image_mode"] == "subject-admitted":
            staging._validate_subject_admission(
                marker["subject_admission"],
                require_executed=marker["lifecycle"] != "initializing",
            )

    return validate


def reference_contract(staging, codec, *, project: str, state_dir: Path):
    backed_up = tuple(
        key for key in staging.VOLUME_KEYS if key != EXCLUDED_RECOVERY_VOLUME
    )
    marker_keys = frozenset(
        staging.new_marker(
            project=project,
            state_dir=state_dir,
            state_id="0" * 32,
            env_sha256="0" * 64,
            runtime_head="0" * 40,
            runtime_tree="0" * 40,
            hrh_head=staging.REQUIRED_HRH_SHA,
            hrh_tree=staging.REQUIRED_HRH_TREE,
        )
    )
    return codec.BackupContract(
        error_type=staging.SafetyError,
        schema=staging.SCHEMA,
        marker_name=staging.MARKER_NAME,
        backup_schema=BACKUP_SCHEMA,
        manifest_name=BACKUP_MANIFEST_NAME,
        complete_name=BACKUP_COMPLETE_NAME,
        state_archive_name=BACKUP_STATE_ARCHIVE,
        volume_directory=BACKUP_VOLUME_DIR,
        volume_keys=staging.VOLUME_KEYS,
        backup_volume_keys=backed_up,
        excluded_volume=EXCLUDED_RECOVERY_VOLUME,
        required_hrh_head=staging.REQUIRED_HRH_SHA,
        required_hrh_tree=staging.REQUIRED_HRH_TREE,
        marker_keys=marker_keys,
        volume_names=staging.volume_names,
        validate_project=staging.validate_project,
        validate_marker=_marker_invariant(staging),
        fsync_file=_fsync_file,
        fsync_directory=staging.fsync_directory,
    )


def _subject_admission() -> dict[str, Any]:
    subjects = {
        "ingress": "ghcr.io/cervantesh/restricted-mattermost-ingress@sha256:"
        + "1" * 64,
        "clinical-adapter": "ghcr.io/cervantesh/restricted-clinical-adapter@sha256:"
        + "2" * 64,
    }
    return {
        "manifest_sha256": "3" * 64,
        "subjects": dict(subjects),
        "executed_repo_digests": dict(subjects),
    }


PROJECT = "clinicalstagingrecovery"
SECRET_CANARY = "canary-cbb4f1f4d8a24f0e"


def _write_tar(path: Path, entries: Mapping[str, bytes]) -> None:
    with tarfile.open(path, "x") as archive:
        for name, payload in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o600
            member.mtime = 0
            import io

            archive.addfile(member, io.BytesIO(payload))


class Bundle:
    def __init__(self, state_dir: Path, backup_dir: Path, manifest_sha256: str):
        self.state_dir = state_dir
        self.backup_dir = backup_dir
        self.manifest_sha256 = manifest_sha256


def make_bundle(
    staging,
    codec,
    tmp_path: Path,
    *,
    mutate_marker: Callable[[dict[str, Any]], None] | None = None,
    hrh_head: str | None = None,
) -> tuple[Bundle, Any]:
    """Produce a complete, valid bundle unless a mutator deliberately breaks it."""
    state_dir = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    state_dir.mkdir(mode=0o700)
    backup_dir = tmp_path / "cold-backup"
    backup_dir.mkdir(mode=0o700)
    (backup_dir / BACKUP_VOLUME_DIR).mkdir(mode=0o700)

    contract = reference_contract(staging, codec, project=PROJECT, state_dir=state_dir)
    marker = staging.new_marker(
        project=PROJECT,
        state_dir=state_dir,
        state_id=secrets.token_hex(16),
        env_sha256="a" * 64,
        runtime_head="b" * 40,
        runtime_tree="c" * 40,
        hrh_head=hrh_head or staging.REQUIRED_HRH_SHA,
        hrh_tree=staging.REQUIRED_HRH_TREE,
        lifecycle="stopped",
        expected_images={"ingress": "ghcr.io/cervantesh/restricted-mattermost-ingress"},
        image_mode="subject-admitted",
        subject_admission=_subject_admission(),
    )
    if mutate_marker is not None:
        mutate_marker(marker)
    # A real state directory carries generated secret material.  Writing a
    # canary here lets the manifest be checked for disclosure.
    (state_dir / "compose.env").write_text(
        f"CLINICAL_ADMIN_PASSWORD={SECRET_CANARY}\n", encoding="utf-8"
    )
    os.chmod(state_dir / "compose.env", 0o600)
    staging.write_json_atomic(state_dir / staging.MARKER_NAME, marker, mode=0o600)

    for key in contract.backup_volume_keys:
        _write_tar(
            backup_dir / BACKUP_VOLUME_DIR / f"{key}.tar",
            {f"{key}/data": f"{key}-payload".encode("utf-8")},
        )
    codec.create_state_archive(contract, state_dir, backup_dir / BACKUP_STATE_ARCHIVE)
    manifest = codec.build_backup_manifest(contract, marker, state_dir, backup_dir)
    codec.write_backup_manifest(contract, backup_dir, manifest)
    codec.write_backup_completion(contract, backup_dir)
    manifest_sha256 = staging.file_sha256(backup_dir / BACKUP_MANIFEST_NAME)
    return Bundle(state_dir, backup_dir, manifest_sha256), contract


def validate(codec, bundle: Bundle, contract):
    return codec.validate_backup_bundle(
        contract,
        bundle.backup_dir,
        bundle.manifest_sha256,
        PROJECT,
        bundle.state_dir,
    )


# --------------------------------------------------------------------------
# The codec must not weaken the current subject-admission contract.
# --------------------------------------------------------------------------


def test_codec_marker_key_set_is_the_current_staging_marker(staging, codec, tmp_path):
    state_dir = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    state_dir.mkdir(mode=0o700)
    contract = reference_contract(staging, codec, project=PROJECT, state_dir=state_dir)
    assert "subject_admission" in contract.marker_keys
    assert "image_mode" in contract.marker_keys
    assert contract.excluded_volume in staging.VOLUME_KEYS
    assert contract.excluded_volume not in contract.backup_volume_keys
    assert set(contract.backup_volume_keys) | {contract.excluded_volume} == set(
        staging.VOLUME_KEYS
    )


@posix_only
def test_complete_bundle_validates_against_the_current_contract(
    staging, codec, tmp_path
):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    manifest = validate(codec, bundle, contract)
    assert manifest["schema"] == BACKUP_SCHEMA
    assert manifest["source"]["hrh_head"] == staging.REQUIRED_HRH_SHA
    assert manifest["excluded_volume"] == EXCLUDED_RECOVERY_VOLUME


@posix_only
def test_archived_marker_without_subject_admission_is_rejected(
    staging, codec, tmp_path
):
    def drop(marker: dict[str, Any]) -> None:
        marker.pop("subject_admission")

    bundle, contract = make_bundle(staging, codec, tmp_path, mutate_marker=drop)
    with pytest.raises(staging.SafetyError, match="unknown or missing fields"):
        validate(codec, bundle, contract)


@posix_only
def test_archived_marker_without_image_mode_is_rejected(staging, codec, tmp_path):
    def drop(marker: dict[str, Any]) -> None:
        marker.pop("image_mode")

    bundle, contract = make_bundle(staging, codec, tmp_path, mutate_marker=drop)
    with pytest.raises(staging.SafetyError, match="unknown or missing fields"):
        validate(codec, bundle, contract)


@posix_only
def test_archived_marker_with_an_unadmitted_subject_is_rejected(
    staging, codec, tmp_path
):
    def forge(marker: dict[str, Any]) -> None:
        marker["subject_admission"]["subjects"]["ingress"] = (
            "docker.io/library/mattermost@sha256:" + "4" * 64
        )
        marker["subject_admission"]["executed_repo_digests"]["ingress"] = marker[
            "subject_admission"
        ]["subjects"]["ingress"]

    bundle, contract = make_bundle(staging, codec, tmp_path, mutate_marker=forge)
    with pytest.raises(staging.SafetyError, match="subject admission image is invalid"):
        validate(codec, bundle, contract)


@posix_only
def test_archived_marker_cannot_downgrade_to_unbound_exact_source(
    staging, codec, tmp_path
):
    def downgrade(marker: dict[str, Any]) -> None:
        marker["image_mode"] = "exact-source"

    bundle, contract = make_bundle(staging, codec, tmp_path, mutate_marker=downgrade)
    with pytest.raises(staging.SafetyError, match="cannot retain subject admission"):
        validate(codec, bundle, contract)


@posix_only
def test_archived_marker_must_remain_stopped(staging, codec, tmp_path):
    def running(marker: dict[str, Any]) -> None:
        marker["lifecycle"] = "ready"

    bundle, contract = make_bundle(staging, codec, tmp_path, mutate_marker=running)
    with pytest.raises(staging.SafetyError, match="conflicts with the manifest"):
        validate(codec, bundle, contract)


@posix_only
def test_foreign_hrh_source_frame_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path, hrh_head="d" * 40)
    with pytest.raises(
        staging.SafetyError, match="does not match the required HRH source"
    ):
        validate(codec, bundle, contract)


# --------------------------------------------------------------------------
# Archive/member safety before any restore mutation.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["/etc/passwd", "../escape", "a/../../escape", "windows\\path", "a/./../../x"],
)
def test_unsafe_member_names_are_refused(staging, codec, tmp_path, name):
    contract = reference_contract(
        staging,
        codec,
        project=PROJECT,
        state_dir=tmp_path / f"{PROJECT}.synthetic-clinical-staging",
    )
    with pytest.raises(staging.SafetyError):
        codec.safe_archive_name(contract, name)


def test_safe_member_names_are_normalized(staging, codec, tmp_path):
    contract = reference_contract(
        staging,
        codec,
        project=PROJECT,
        state_dir=tmp_path / f"{PROJECT}.synthetic-clinical-staging",
    )
    assert codec.safe_archive_name(contract, "./volumes/a.tar") == "volumes/a.tar"
    assert codec.safe_archive_name(contract, ".") == ""
    assert codec.safe_archive_name(contract, "a//b") == "a/b"


def _contract_for(staging, codec, tmp_path):
    return reference_contract(
        staging,
        codec,
        project=PROJECT,
        state_dir=tmp_path / f"{PROJECT}.synthetic-clinical-staging",
    )


@posix_only
def test_symlink_members_are_refused_before_extraction(staging, codec, tmp_path):
    contract = _contract_for(staging, codec, tmp_path)
    archive = tmp_path / "linked.tar"
    with tarfile.open(archive, "x") as handle:
        member = tarfile.TarInfo("escape")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        handle.addfile(member)
    with pytest.raises(staging.SafetyError, match="link or special member"):
        codec.inspect_safe_tar(contract, archive, require_regular_file=False)
    with pytest.raises(staging.SafetyError, match="link or special member"):
        codec.archive_ownership_sha256(contract, archive)


def test_duplicate_members_are_refused(staging, codec, tmp_path):
    contract = _contract_for(staging, codec, tmp_path)
    archive = tmp_path / "duplicate.tar"
    import io

    with tarfile.open(archive, "x") as handle:
        for _ in range(2):
            member = tarfile.TarInfo("state/data")
            member.size = 3
            handle.addfile(member, io.BytesIO(b"abc"))
    with pytest.raises(staging.SafetyError, match="duplicate members"):
        codec.inspect_safe_tar(contract, archive, require_regular_file=True)


def test_corrupt_archive_is_refused(staging, codec, tmp_path):
    contract = _contract_for(staging, codec, tmp_path)
    archive = tmp_path / "corrupt.tar"
    archive.write_bytes(b"not a tar archive at all")
    with pytest.raises(staging.SafetyError, match="unreadable or corrupt"):
        codec.inspect_safe_tar(contract, archive, require_regular_file=True)


def test_empty_archive_is_refused_when_a_regular_file_is_required(
    staging, codec, tmp_path
):
    contract = _contract_for(staging, codec, tmp_path)
    archive = tmp_path / "empty.tar"
    with tarfile.open(archive, "x"):
        pass
    with pytest.raises(staging.SafetyError, match="does not contain a regular file"):
        codec.inspect_safe_tar(contract, archive, require_regular_file=True)


@posix_only
def test_state_archive_refuses_a_linked_state_tree(staging, codec, tmp_path):
    contract = _contract_for(staging, codec, tmp_path)
    state_dir = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    state_dir.mkdir(mode=0o700)
    (state_dir / "real").write_text("value\n", encoding="utf-8")
    (state_dir / "escape").symlink_to("/etc/passwd")
    with pytest.raises(staging.SafetyError, match="link or special file"):
        codec.create_state_archive(contract, state_dir, tmp_path / "state.tar")


@posix_only
def test_state_archive_refuses_to_overwrite_an_existing_archive(
    staging, codec, tmp_path
):
    contract = _contract_for(staging, codec, tmp_path)
    state_dir = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    state_dir.mkdir(mode=0o700)
    (state_dir / "real").write_text("value\n", encoding="utf-8")
    archive = tmp_path / "state.tar"
    archive.write_bytes(b"")
    with pytest.raises(staging.SafetyError, match="already exists"):
        codec.create_state_archive(contract, state_dir, archive)


# --------------------------------------------------------------------------
# Bundle-level negative controls.
# --------------------------------------------------------------------------


@posix_only
def test_external_manifest_hash_must_match(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    bundle.manifest_sha256 = "f" * 64
    with pytest.raises(staging.SafetyError, match="external manifest hash"):
        validate(codec, bundle, contract)


@posix_only
def test_missing_completion_marker_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    (bundle.backup_dir / BACKUP_COMPLETE_NAME).unlink()
    with pytest.raises(staging.SafetyError, match="complete marker is missing"):
        validate(codec, bundle, contract)


@posix_only
def test_substituted_completion_marker_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    (bundle.backup_dir / BACKUP_COMPLETE_NAME).write_bytes(b"complete")
    with pytest.raises(staging.SafetyError, match="complete marker is invalid"):
        validate(codec, bundle, contract)


@posix_only
def test_extra_bundle_member_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    (bundle.backup_dir / "extra.tar").write_bytes(b"")
    with pytest.raises(staging.SafetyError, match="unexpected or missing members"):
        validate(codec, bundle, contract)


@posix_only
def test_symlinked_bundle_member_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    target = tmp_path / "elsewhere.tar"
    target.write_bytes((bundle.backup_dir / BACKUP_STATE_ARCHIVE).read_bytes())
    (bundle.backup_dir / BACKUP_STATE_ARCHIVE).unlink()
    (bundle.backup_dir / BACKUP_STATE_ARCHIVE).symlink_to(target)
    with pytest.raises(staging.SafetyError, match="must not contain symbolic links"):
        validate(codec, bundle, contract)


@posix_only
def test_tampered_volume_archive_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    victim = (
        bundle.backup_dir / BACKUP_VOLUME_DIR / f"{contract.backup_volume_keys[0]}.tar"
    )
    _write_tar_over(victim, {"substituted/data": b"foreign"})
    with pytest.raises(staging.SafetyError, match="hash or size differs"):
        validate(codec, bundle, contract)


def _write_tar_over(path: Path, entries: Mapping[str, bytes]) -> None:
    path.unlink()
    _write_tar(path, entries)


@posix_only
def test_missing_volume_archive_is_rejected(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    (
        bundle.backup_dir / BACKUP_VOLUME_DIR / f"{contract.backup_volume_keys[0]}.tar"
    ).unlink()
    with pytest.raises(staging.SafetyError, match="unexpected or missing members"):
        validate(codec, bundle, contract)


@posix_only
def test_excluded_volume_is_never_part_of_the_bundle(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    manifest = validate(codec, bundle, contract)
    assert (
        f"{BACKUP_VOLUME_DIR}/{EXCLUDED_RECOVERY_VOLUME}.tar" not in manifest["members"]
    )
    assert not (
        bundle.backup_dir / BACKUP_VOLUME_DIR / f"{EXCLUDED_RECOVERY_VOLUME}.tar"
    ).exists()


@posix_only
def test_public_manifest_discloses_no_secret_or_member_paths(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    raw = (bundle.backup_dir / BACKUP_MANIFEST_NAME).read_text(encoding="utf-8")
    assert SECRET_CANARY not in raw
    manifest = json.loads(raw)
    for metadata in manifest["members"].values():
        assert set(metadata) == {"sha256", "size", "ownership_sha256"}
        assert re.fullmatch("[a-f0-9]{64}", metadata["ownership_sha256"])
    # The archived marker's subject admission stays inside the private state
    # archive; only its digest reaches the public manifest.
    assert "subject_admission" not in raw


# --------------------------------------------------------------------------
# Snapshot materialization: the external directory is never trusted twice.
# --------------------------------------------------------------------------


@posix_only
def test_snapshot_is_a_private_immutable_copy(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    parent = tmp_path / "restore-parent"
    parent.mkdir(mode=0o700)
    snapshot = codec.materialize_backup_snapshot(
        contract, bundle.backup_dir, parent, snapshot_stem="restore"
    )
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o700
    for member in snapshot.rglob("*"):
        expected = 0o700 if member.is_dir() else 0o600
        assert stat.S_IMODE(member.stat().st_mode) == expected
    assert (snapshot / BACKUP_STATE_ARCHIVE).read_bytes() == (
        bundle.backup_dir / BACKUP_STATE_ARCHIVE
    ).read_bytes()
    # Mutating the external directory afterwards cannot change the snapshot.
    _write_tar_over(bundle.backup_dir / BACKUP_STATE_ARCHIVE, {"foreign": b"x"})
    assert (snapshot / BACKUP_STATE_ARCHIVE).read_bytes() != (
        bundle.backup_dir / BACKUP_STATE_ARCHIVE
    ).read_bytes()


@posix_only
def test_snapshot_refuses_a_symlinked_input(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    parent = tmp_path / "restore-parent"
    parent.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.tar"
    target.write_bytes(b"")
    victim = (
        bundle.backup_dir / BACKUP_VOLUME_DIR / f"{contract.backup_volume_keys[0]}.tar"
    )
    victim.unlink()
    victim.symlink_to(target)
    with pytest.raises(staging.SafetyError, match="unexpected or missing members"):
        codec.materialize_backup_snapshot(
            contract, bundle.backup_dir, parent, snapshot_stem="restore"
        )
    assert list(parent.iterdir()) == []


@posix_only
def test_snapshot_requires_an_existing_private_parent(staging, codec, tmp_path):
    bundle, contract = make_bundle(staging, codec, tmp_path)
    with pytest.raises(
        staging.SafetyError, match="parent directory must already exist"
    ):
        codec.materialize_backup_snapshot(
            contract, bundle.backup_dir, tmp_path / "absent", snapshot_stem="restore"
        )


# --------------------------------------------------------------------------
# Persistent operator lock.
# --------------------------------------------------------------------------


def _unique_project() -> str:
    return "clinicalstaging" + secrets.token_hex(8)


@posix_only
def test_operator_lock_namespace_is_the_compose_project(operator_lock, tmp_path):
    project = _unique_project()
    first = operator_lock.operator_lock_path(tmp_path / "state-a", project)
    second = operator_lock.operator_lock_path(tmp_path / "state-b", project)
    other = operator_lock.operator_lock_path(tmp_path / "state-a", _unique_project())
    assert first == second
    assert first != other


@posix_only
def test_operator_lock_rejects_a_multi_segment_identity(operator_lock, tmp_path):
    with pytest.raises(operator_lock.OperatorLockError, match="single path segment"):
        operator_lock.operator_lock_path(tmp_path, "../escape")


@posix_only
def test_operator_lock_is_reentrant_for_one_thread(operator_lock, tmp_path):
    project = _unique_project()
    with operator_lock.persistent_operator_lock(tmp_path, project):
        with operator_lock.persistent_operator_lock(tmp_path, project):
            pass
    # The durable path survives release; deleting it would let a second
    # operator take a lock on a fresh inode.
    assert operator_lock.operator_lock_path(tmp_path, project).is_file()


@posix_only
def test_operator_lock_excludes_a_concurrent_holder(operator_lock, tmp_path):
    import fcntl

    project = _unique_project()
    entered = threading.Event()
    release = threading.Event()
    blocked: list[bool] = []

    def hold():
        with operator_lock.persistent_operator_lock(tmp_path, project):
            entered.set()
            release.wait(10)

    worker = threading.Thread(target=hold)
    worker.start()
    try:
        assert entered.wait(10)
        path = operator_lock.operator_lock_path(tmp_path, project)
        fd = os.open(path, os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
                blocked.append(False)
            except BlockingIOError:
                blocked.append(True)
        finally:
            os.close(fd)
    finally:
        release.set()
        worker.join(10)
    assert blocked == [True]


@posix_only
def test_operator_lock_refuses_a_symlinked_lock_path(operator_lock, tmp_path):
    project = _unique_project()
    path = operator_lock.operator_lock_path(tmp_path, project)
    target = tmp_path / "planted.lock"
    target.write_bytes(b"")
    if path.exists() or path.is_symlink():
        path.unlink()
    path.symlink_to(target)
    try:
        with pytest.raises(
            operator_lock.OperatorLockError, match="could not safely open"
        ):
            with operator_lock.persistent_operator_lock(tmp_path, project):
                pass
    finally:
        path.unlink()


@posix_only
def test_operator_lock_refuses_a_parent_it_does_not_own(
    operator_lock, tmp_path, monkeypatch
):
    foreign_uid = os.getuid() + 4242
    monkeypatch.setattr(operator_lock.os, "getuid", lambda: foreign_uid)
    with pytest.raises(operator_lock.OperatorLockError, match="operator-owned"):
        operator_lock.operator_lock_parent()
