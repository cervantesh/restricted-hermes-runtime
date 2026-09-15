"""Lifecycle controls for cold backup and restore.

These exercise the staging lifecycle itself, not the codec helpers: a bundle is
produced through `ClinicalStaging.backup` and consumed through
`ClinicalStaging.restore`, with only the Docker-touching steps replaced. The
codec's own member/tamper controls live in
`test_clinical_cold_recovery_codec.py`.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tarfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="the operator recovery boundary is POSIX-only"
)


def load_module():
    spec = importlib.util.spec_from_file_location("clinical_staging", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def module():
    return load_module()


PROJECT = "clinicalstagingrecovery"
SECRET_CANARY = "canary-a17cf0d4e2b94c31"


class QuietShell:
    """A Docker double that reports an empty, conflict-free host."""

    def __init__(self):
        self.commands: list[tuple[str, ...]] = []

    def run(self, *args: str, **_kwargs):
        self.commands.append(args)
        if args[:3] == ("docker", "container", "ls"):
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:3] in {
            ("docker", "volume", "inspect"),
            ("docker", "network", "inspect"),
        }:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def git(self, *_args, **_kwargs) -> str:
        return ""


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
        # The constructor seals a pre-execution admission; only a marker whose
        # lifecycle has advanced carries the executed RepoDigests.
        "executed_repo_digests": {},
    }


def _marker_admission() -> dict[str, Any]:
    admission = _subject_admission()
    admission["executed_repo_digests"] = dict(admission["subjects"])
    return admission


def _frame(module) -> dict[str, str]:
    return {
        "runtime_head": "b" * 40,
        "runtime_tree": "c" * 40,
        "hrh_head": module.REQUIRED_HRH_SHA,
        "hrh_tree": module.REQUIRED_HRH_TREE,
    }


def make_target(module, tmp_path: Path, *, admitted: bool = True):
    """Build a real stopped state directory and a staging instance for it.

    The seed material and `compose.env` are produced by the staging module's
    own helpers, so the bundle this target yields is a genuine one: the
    restored sealed-environment check has something real to verify.
    """
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    state.mkdir(mode=0o700)
    (state / "evidence").mkdir(mode=0o700)

    admission = _subject_admission() if admitted else None
    staging = module.ClinicalStaging(
        runtime,
        hrh,
        state,
        PROJECT,
        18443,
        shell=QuietShell(),
        subject_admission=admission,
    )
    staging._seed_material(state)
    # A recognizable value in the private seed; the published manifest and
    # receipt must never carry it.
    (state / "seed" / "actor_password").write_text(SECRET_CANARY, encoding="ascii")
    os.chmod(state / "seed" / "actor_password", 0o600)

    marker = module.new_marker(
        project=PROJECT,
        state_dir=state,
        state_id=secrets.token_hex(16),
        env_sha256="0" * 64,
        lifecycle="stopped",
        expected_images={
            service: f"sha256:{index:064x}"
            for index, service in enumerate(module.LONG_RUNNING_SERVICES, 1)
        },
        image_mode="subject-admitted" if admitted else "exact-source",
        subject_admission=_marker_admission() if admitted else None,
        **_frame(module),
    )
    values = staging._env_values(marker)
    env_raw = staging._env_bytes(values)
    (state / "compose.env").write_bytes(env_raw)
    os.chmod(state / "compose.env", 0o600)
    marker["compose_env_sha256"] = hashlib.sha256(env_raw).hexdigest()
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    return staging, marker, values


def _stub_docker_backup(module, staging, monkeypatch, *, volumes_from):
    """Replace only the container-run archive step with a real tar writer."""
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_a, **_k: _frame(module))
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: None)
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *_a, **_k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        staging, "_assert_unmounted_backup_volumes", lambda _volumes: None
    )

    def fake_backup_volume(key, volume, backup_dir):
        assert volume == volumes_from[key]
        target = backup_dir / module.BACKUP_VOLUME_DIR / f"{key}.tar"
        with tarfile.open(target, "x") as archive:
            payload = f"{key}-payload".encode("utf-8")
            member = tarfile.TarInfo(f"{key}/data")
            member.size = len(payload)
            member.mode = 0o600
            member.mtime = 0
            archive.addfile(member, io.BytesIO(payload))

    monkeypatch.setattr(staging, "_backup_volume", fake_backup_volume)


def make_bundle(module, tmp_path: Path, monkeypatch, *, admitted: bool = True):
    staging, marker, values = make_target(module, tmp_path, admitted=admitted)
    _stub_docker_backup(module, staging, monkeypatch, volumes_from=marker["volumes"])
    backup_dir = tmp_path / "cold-backup"
    receipt = staging.backup(backup_dir)
    return staging, marker, backup_dir, receipt, values


def _stub_docker_restore(module, staging, monkeypatch):
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_a, **_k: _frame(module))
    monkeypatch.setattr(staging, "_create_volumes", lambda _marker: None)
    monkeypatch.setattr(staging, "_restore_volume", lambda *_a, **_k: None)
    monkeypatch.setattr(staging, "_start_restored_stack", lambda: None)
    monkeypatch.setattr(
        staging,
        "status",
        lambda **_k: {
            "observed_at": "2026-09-15T00:00:00+00:00",
            "lifecycle": "recovering",
        },
    )


def restore_target(module, source, *, admitted: bool = True):
    """Simulate the loss of the live target and reopen the same state path.

    The manifest and the archived marker both bind the absolute state
    directory, so a cold restore recovers *this* target; it is not a clone
    facility for a new path.
    """
    shutil.rmtree(source.state_dir)
    admission = _subject_admission() if admitted else None
    return module.ClinicalStaging(
        source.runtime,
        source.hrh,
        source.state_dir,
        PROJECT,
        18443,
        shell=QuietShell(),
        subject_admission=admission,
    )


# --------------------------------------------------------------------------
# One serialized authority
# --------------------------------------------------------------------------


def test_backup_and_restore_use_the_lifecycle_serialization(module):
    for name in (
        "backup",
        "restore",
        "init",
        "up",
        "status",
        "stop",
        "reset",
        "destroy",
    ):
        source = getattr(module.ClinicalStaging, name)
        assert getattr(source, "__wrapped__", None) is not None, name


@posix_only
def test_one_authority_covers_two_state_dirs_naming_the_same_project(module, tmp_path):
    """The per-state lock cannot see a project collision; the durable one can."""
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    project = "clinicalstaging" + secrets.token_hex(6)
    first_dir = tmp_path / "a" / f"{project}.synthetic-clinical-staging"
    second_dir = tmp_path / "b" / f"{project}.synthetic-clinical-staging"
    first = module.ClinicalStaging(
        runtime, hrh, first_dir, project, 18443, shell=QuietShell()
    )
    second = module.ClinicalStaging(
        runtime, hrh, second_dir, project, 18443, shell=QuietShell()
    )
    assert first.state_dir != second.state_dir

    entered = threading.Event()
    blocked_entered = threading.Event()

    def hold_second():
        with second._lifecycle_lock():
            blocked_entered.set()

    with first._lifecycle_lock():
        entered.set()
        worker = threading.Thread(target=hold_second)
        worker.start()
        time.sleep(0.2)
        assert not blocked_entered.is_set(), (
            "a second state directory entered the same Compose project concurrently"
        )
    worker.join(timeout=10)
    assert blocked_entered.is_set()


@posix_only
def test_state_lock_alone_does_not_see_the_project_collision(module, tmp_path):
    """Falsifier for the control above: this is exactly the gap being closed."""
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    project = "clinicalstaging" + secrets.token_hex(6)
    first = module.ClinicalStaging(
        runtime,
        hrh,
        tmp_path / "a" / f"{project}.synthetic-clinical-staging",
        project,
        18443,
        shell=QuietShell(),
    )
    second = module.ClinicalStaging(
        runtime,
        hrh,
        tmp_path / "b" / f"{project}.synthetic-clinical-staging",
        project,
        18443,
        shell=QuietShell(),
    )
    with first._state_lifecycle_lock():
        with second._state_lifecycle_lock():
            pass  # two distinct state paths, so the per-state lock never collides


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------


@posix_only
def test_backup_publishes_a_validatable_bundle(module, tmp_path, monkeypatch):
    staging, marker, backup_dir, receipt, _values = make_bundle(
        module, tmp_path, monkeypatch
    )
    assert receipt["schema"] == module.BACKUP_SCHEMA
    assert receipt["excluded_volume"] == module.EXCLUDED_RECOVERY_VOLUME
    assert re.fullmatch("[a-f0-9]{64}", receipt["manifest_sha256"])
    contract = module.backup_contract(PROJECT, staging.state_dir)
    manifest = module._bundle.validate_backup_bundle(
        contract, backup_dir, receipt["manifest_sha256"], PROJECT, staging.state_dir
    )
    assert manifest["state_id"] == marker["state_id"]
    assert set(manifest["members"]) == {
        module.BACKUP_STATE_ARCHIVE,
        *(
            f"{module.BACKUP_VOLUME_DIR}/{key}.tar"
            for key in module.BACKED_UP_VOLUME_KEYS
        ),
    }


@posix_only
def test_backup_receipt_and_manifest_carry_no_secret_or_private_path(
    module, tmp_path, monkeypatch
):
    staging, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    published = json.dumps(receipt, sort_keys=True)
    generated = values["CLINICAL_MM_DB_PASSWORD"]
    assert len(generated) >= 32
    assert SECRET_CANARY not in published and generated not in published
    assert str(staging.state_dir) not in published
    assert "seed" not in published
    manifest_raw = (backup_dir / module.BACKUP_MANIFEST_NAME).read_text(
        encoding="utf-8"
    )
    assert SECRET_CANARY not in manifest_raw and generated not in manifest_raw
    assert "subject_admission" not in manifest_raw
    assert "actor_password" not in manifest_raw


@posix_only
def test_backup_refuses_a_target_that_already_exists(module, tmp_path, monkeypatch):
    staging, marker, _values = make_target(module, tmp_path)
    _stub_docker_backup(module, staging, monkeypatch, volumes_from=marker["volumes"])
    existing = tmp_path / "cold-backup"
    existing.mkdir()
    with pytest.raises(module.SafetyError, match="must be a new directory"):
        staging.backup(existing)


@posix_only
def test_backup_refuses_a_target_inside_state_or_build_context(
    module, tmp_path, monkeypatch
):
    staging, marker, _values = make_target(module, tmp_path)
    _stub_docker_backup(module, staging, monkeypatch, volumes_from=marker["volumes"])
    for candidate in (
        staging.state_dir / "inside",
        staging.runtime / "inside",
        staging.hrh / "inside",
        staging.state_dir,
    ):
        with pytest.raises(module.SafetyError, match="backup path"):
            staging.backup(candidate)


@posix_only
def test_backup_requires_a_cold_marker(module, tmp_path, monkeypatch):
    staging, marker, _values = make_target(module, tmp_path)
    _stub_docker_backup(module, staging, monkeypatch, volumes_from=marker["volumes"])
    monkeypatch.undo()
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_a, **_k: _frame(module))
    running = dict(marker, lifecycle="ready")
    module.write_json_atomic(
        staging.state_dir / module.MARKER_NAME, running, mode=0o600
    )
    with pytest.raises(module.SafetyError, match="rejects marker lifecycle 'ready'"):
        staging.backup(tmp_path / "cold-backup")


@posix_only
def test_failed_backup_leaves_no_partial_bundle(module, tmp_path, monkeypatch):
    staging, marker, _values = make_target(module, tmp_path)
    _stub_docker_backup(module, staging, monkeypatch, volumes_from=marker["volumes"])

    def explode(*_args, **_kwargs):
        raise RuntimeError("volume export failed")

    monkeypatch.setattr(staging, "_backup_volume", explode)
    backup_dir = tmp_path / "cold-backup"
    with pytest.raises(RuntimeError, match="volume export failed"):
        staging.backup(backup_dir)
    assert not backup_dir.exists()
    assert list(tmp_path.glob(".cold-backup.partial-*")) == []


@posix_only
def test_backup_never_archives_the_excluded_transport_volume(
    module, tmp_path, monkeypatch
):
    _source2, _marker, backup_dir, _receipt, _values = make_bundle(module, tmp_path, monkeypatch)
    volumes = {item.name for item in (backup_dir / module.BACKUP_VOLUME_DIR).iterdir()}
    assert f"{module.EXCLUDED_RECOVERY_VOLUME}.tar" not in volumes
    assert volumes == {f"{key}.tar" for key in module.BACKED_UP_VOLUME_KEYS}


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------


@posix_only
def test_restore_round_trips_into_a_clean_destination(module, tmp_path, monkeypatch):
    source, marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    result = target.restore(backup_dir, receipt["manifest_sha256"])
    assert result["verification"] == "mechanical_restore_only"
    assert result["state_id"] == marker["state_id"]
    assert "not a causal recovery verification" in result["nonclaims"]
    restored = module.read_marker(target.state_dir, PROJECT)
    assert restored["lifecycle"] == "ready"
    assert restored["subject_admission"] == marker["subject_admission"]
    # The private state came back, including the material the manifest hides.
    assert (target.state_dir / "seed" / "actor_password").read_text(
        encoding="ascii"
    ) == SECRET_CANARY
    assert (
        stat.S_IMODE((target.state_dir / "seed" / "actor_password").stat().st_mode)
        == 0o600
    )
    receipt_path = (
        target.state_dir
        / "evidence"
        / "recovery"
        / f"restore-{receipt['manifest_sha256']}.json"
    )
    assert json.loads(receipt_path.read_text(encoding="utf-8")) == result
    assert SECRET_CANARY not in json.dumps(result, sort_keys=True)
    # Nothing is left behind in the destination parent.
    assert not list(target.state_dir.parent.glob(".*bundle-*"))
    assert not list(target.state_dir.parent.glob(".*recovering-*"))


@posix_only
def test_restore_refuses_a_bundle_from_another_subject_line(
    module, tmp_path, monkeypatch
):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    other = _subject_admission()
    other["manifest_sha256"] = "9" * 64
    target.subject_admission = other
    _stub_docker_restore(module, target, monkeypatch)
    with pytest.raises(
        module.SafetyError, match="subject admission differs from the sealed target"
    ):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert not target.state_dir.exists()


@posix_only
def test_restore_refuses_a_bundle_for_an_unadmitted_target(
    module, tmp_path, monkeypatch
):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source, admitted=False)
    _stub_docker_restore(module, target, monkeypatch)
    with pytest.raises(
        module.SafetyError, match="image mode differs from the sealed target"
    ):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert not target.state_dir.exists()


@posix_only
@pytest.mark.parametrize(
    "corrupt",
    ["hash", "complete", "member", "symlink", "extra", "traversal"],
)
def test_restore_refuses_a_corrupt_bundle_without_touching_the_destination(
    module, tmp_path, monkeypatch, corrupt
):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    manifest_sha = receipt["manifest_sha256"]
    victim = (
        backup_dir / module.BACKUP_VOLUME_DIR / f"{module.BACKED_UP_VOLUME_KEYS[0]}.tar"
    )
    if corrupt == "hash":
        manifest_sha = "f" * 64
    elif corrupt == "complete":
        (backup_dir / module.BACKUP_COMPLETE_NAME).write_bytes(b"complete")
    elif corrupt == "member":
        victim.unlink()
        with tarfile.open(victim, "x") as archive:
            member = tarfile.TarInfo("substituted/data")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    elif corrupt == "symlink":
        elsewhere = tmp_path / "elsewhere.tar"
        elsewhere.write_bytes(victim.read_bytes())
        victim.unlink()
        victim.symlink_to(elsewhere)
    elif corrupt == "extra":
        (backup_dir / "unexpected.tar").write_bytes(b"")
    elif corrupt == "traversal":
        victim.unlink()
        with tarfile.open(victim, "x") as archive:
            member = tarfile.TarInfo("../../escape")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))

    with pytest.raises(module.SafetyError):
        target.restore(backup_dir, manifest_sha)
    assert not target.state_dir.exists()
    assert not list(target.state_dir.parent.glob(".*bundle-*"))
    assert not list(target.state_dir.parent.glob(".*recovering-*"))


@posix_only
def test_restore_refuses_a_foreign_source_frame(module, tmp_path, monkeypatch):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    monkeypatch.setattr(
        module,
        "verify_source_frame",
        lambda *_a, **_k: {**_frame(module), "runtime_head": "d" * 40},
    )
    with pytest.raises(
        module.SafetyError, match="differs from the validated backup source frame"
    ):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert not target.state_dir.exists()


@posix_only
def test_restore_refuses_a_non_empty_destination(module, tmp_path, monkeypatch):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    target.state_dir.mkdir(mode=0o700, parents=True)
    (target.state_dir / "occupied").write_text("x", encoding="ascii")
    _stub_docker_restore(module, target, monkeypatch)
    with pytest.raises(module.SafetyError, match="absent or empty state destination"):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert (target.state_dir / "occupied").read_text(encoding="ascii") == "x"


@posix_only
def test_restore_refuses_a_destination_with_conflicting_docker_state(
    module, tmp_path, monkeypatch
):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)

    class ConflictingShell(QuietShell):
        def run(self, *args: str, **kwargs):
            if args[:3] == ("docker", "volume", "inspect"):
                return SimpleNamespace(returncode=0, stdout="[{}]", stderr="")
            return super().run(*args, **kwargs)

    target.shell = ConflictingShell()
    with pytest.raises(
        module.SafetyError, match="conflicts with existing Docker volume"
    ):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert not target.state_dir.exists()


# --------------------------------------------------------------------------
# Restart / crash controls
# --------------------------------------------------------------------------


@posix_only
def test_failure_after_publication_leaves_a_non_operational_recovering_target(
    module, tmp_path, monkeypatch
):
    source, _marker, backup_dir, receipt, values = make_bundle(module, tmp_path, monkeypatch)
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    stopped: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        target,
        "compose",
        lambda *args, **_k: (
            stopped.append(args) or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )

    def explode(*_args, **_kwargs):
        raise RuntimeError("restored stack did not start")

    monkeypatch.setattr(target, "_start_restored_stack", explode)
    with pytest.raises(module.SafetyError, match="run destroy before retrying"):
        target.restore(backup_dir, receipt["manifest_sha256"])

    marker = module.read_marker(target.state_dir, PROJECT)
    assert marker["lifecycle"] == "recovering"
    assert any(args[0] == "stop" for args in stopped)
    # Non-operational: the ordinary commands refuse a recovering target.
    monkeypatch.setattr(target, "_verify_marker_and_source", lambda: marker)
    for command, allowed in (("up", {"ready", "stopped"}), ("status", {"ready"})):
        with pytest.raises(
            module.SafetyError, match="rejects marker lifecycle 'recovering'"
        ):
            module.ClinicalStaging._require_lifecycle(marker, command, allowed)
    # Nothing transient survives the failure.
    assert not list(target.state_dir.parent.glob(".*bundle-*"))
    assert not list(target.state_dir.parent.glob(".*recovering-*"))


def test_recovering_is_cleanable_but_never_settled(module):
    """`destroy` must reach a half-restored target; `status` must not."""
    assert "recovering" in module.LIFECYCLE_STATES
    assert "recovering" not in module.SETTLED_LIFECYCLES
    labels = {
        module.PROJECT_LABEL: PROJECT,
        module.STATE_LABEL: "a" * 32,
        module.SYNTHETIC_LABEL: "true",
    }
    # A restore that died before creating volumes leaves none; destroy must
    # still be able to verify and proceed.
    assert (
        module.verify_destructive_volumes(PROJECT, "a" * 32, set(), {}, "recovering")
        == []
    )
    assert module.verify_destructive_resources(
        PROJECT, "a" * 32, {}, {}, "recovering"
    ) == ([], [])
    # The allowlist is still enforced in that state.
    with pytest.raises(module.SafetyError, match="unexpected project volumes"):
        module.verify_destructive_volumes(
            PROJECT, "a" * 32, set(), {"foreign_volume": labels}, "recovering"
        )
    with pytest.raises(module.SafetyError, match="unexpected project network"):
        module.verify_destructive_resources(
            PROJECT, "a" * 32, {}, {"foreign_net": labels}, "recovering"
        )


def test_status_rejects_recovering_unless_restore_allows_it(
    module, tmp_path, monkeypatch
):
    marker = {"lifecycle": "recovering"}
    with pytest.raises(
        module.SafetyError, match="rejects marker lifecycle 'recovering'"
    ):
        module.ClinicalStaging._require_lifecycle(marker, "status", {"ready"})
    module.ClinicalStaging._require_lifecycle(marker, "status", {"ready", "recovering"})
    # The CLI cannot reach the allowance.
    parsed = module.parse_args([
        "--hrh-root",
        str(tmp_path),
        "--state-dir",
        str(tmp_path),
        "--project",
        PROJECT,
        "status",
    ])
    assert not hasattr(parsed, "_allow_recovering")


# --------------------------------------------------------------------------
# Recovery helper boundary
# --------------------------------------------------------------------------


def test_recovery_helper_image_matches_the_admitted_composed_subject(module):
    compose = (
        ROOT / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"
    ).read_text(encoding="utf-8")
    assert f"image: {module.RECOVERY_HELPER_IMAGE}" in compose


@posix_only
def test_backup_helper_runs_read_only_with_one_capability(
    module, tmp_path, monkeypatch
):
    staging, marker, _values = make_target(module, tmp_path)
    captured: list[tuple[str, ...]] = []

    class CapturingShell(QuietShell):
        def run(self, *args: str, **kwargs):
            if args[:2] == ("docker", "run"):
                captured.append(args)
                target = tmp_path / "bundle" / module.BACKUP_VOLUME_DIR / "x.tar"
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return super().run(*args, **kwargs)

    staging.shell = CapturingShell()
    monkeypatch.setattr(module._bundle, "inspect_safe_tar", lambda *_a, **_k: ())
    monkeypatch.setattr(module, "fsync_file", lambda _path: None)
    key = module.BACKED_UP_VOLUME_KEYS[0]
    staging._backup_volume(key, marker["volumes"][key], tmp_path)
    command = captured[0]
    assert command.count("--cap-add") == 1
    assert "DAC_OVERRIDE" in command
    assert "CHOWN" not in command and "FOWNER" not in command
    assert "--read-only" in command and "--privileged" not in command
    assert f"src={marker['volumes'][key]},dst=/source,readonly" in " ".join(command)


@posix_only
def test_restore_helper_gains_only_ownership_capabilities(
    module, tmp_path, monkeypatch
):
    staging, marker, _values = make_target(module, tmp_path)
    captured: list[tuple[str, ...]] = []

    class CapturingShell(QuietShell):
        def run(self, *args: str, **kwargs):
            if args[:2] == ("docker", "run"):
                captured.append(args)
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return super().run(*args, **kwargs)

    staging.shell = CapturingShell()
    key = module.BACKED_UP_VOLUME_KEYS[0]
    staging._restore_volume(key, marker["volumes"][key], tmp_path)
    command = captured[0]
    assert {"DAC_OVERRIDE", "CHOWN", "FOWNER"} <= set(command)
    assert command.count("--cap-add") == 3
    assert "dst=/backup,readonly" in " ".join(command)


def test_helper_boundary_rejects_every_added_authority(module):
    source = "type=volume,src=v,dst=/source,readonly"
    backup = "type=bind,src=/b,dst=/backup"
    base = (
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "0:0",
        "--entrypoint",
        "sh",
        "--mount",
        source,
        "--mount",
        backup,
        module.RECOVERY_HELPER_IMAGE,
        "-ec",
        "tar -cf x .",
    )
    caps = frozenset({"DAC_OVERRIDE"})
    module.verify_recovery_helper_boundary(
        base, source_mount=source, backup_mount=backup, capabilities=caps
    )
    for mutation in (
        (*base[:2], "--privileged", *base[2:]),
        (*base, "--mount", "type=bind,src=/,dst=/host"),
        tuple(item for item in base if item != "--read-only"),
        (*base[:9], "SYS_ADMIN", *base[10:]),
        (*base[:-3], "alpine:latest", *base[-2:]),
    ):
        with pytest.raises(module.SafetyError):
            module.verify_recovery_helper_boundary(
                mutation, source_mount=source, backup_mount=backup, capabilities=caps
            )


# --------------------------------------------------------------------------
# Archived marker cannot weaken the live contract
# --------------------------------------------------------------------------


def test_backup_contract_binds_the_live_marker_validator(module, tmp_path):
    state = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    contract = module.backup_contract(PROJECT, state)
    assert set(contract.marker_keys) == set(module.MARKER_KEYS)
    assert contract.required_hrh_head == module.REQUIRED_HRH_SHA
    assert contract.backup_volume_keys == module.BACKED_UP_VOLUME_KEYS
    good = module.new_marker(
        project=PROJECT,
        state_dir=state,
        state_id="a" * 32,
        env_sha256="b" * 64,
        lifecycle="stopped",
        image_mode="exact-source",
        **_frame(module),
    )
    contract.validate_marker(good)
    with pytest.raises(module.SafetyError):
        contract.validate_marker({**good, "image_mode": "subject-admitted"})
    with pytest.raises(module.SafetyError):
        contract.validate_marker({
            key: value for key, value in good.items() if key != "image_mode"
        })


def test_cli_exposes_backup_and_restore_with_explicit_digests(module, tmp_path):
    parsed = module.parse_args([
        "--hrh-root",
        str(tmp_path),
        "--state-dir",
        str(tmp_path),
        "--project",
        PROJECT,
        "restore",
        "--backup-dir",
        str(tmp_path / "b"),
        "--manifest-sha256",
        "a" * 64,
    ])
    assert parsed.command == "restore" and parsed.manifest_sha256 == "a" * 64
    parsed = module.parse_args([
        "--hrh-root",
        str(tmp_path),
        "--state-dir",
        str(tmp_path),
        "--project",
        PROJECT,
        "backup",
        "--backup-dir",
        str(tmp_path / "b"),
    ])
    assert parsed.command == "backup"
    with pytest.raises(SystemExit):
        module.parse_args([
            "--hrh-root",
            str(tmp_path),
            "--state-dir",
            str(tmp_path),
            "--project",
            PROJECT,
            "restore",
            "--backup-dir",
            str(tmp_path / "b"),
        ])


# --------------------------------------------------------------------------
# Backup leaves a target `destroy` can still reach
# --------------------------------------------------------------------------


@posix_only
def test_backup_records_the_teardown_it_performs(module, tmp_path, monkeypatch):
    source, marker, _backup_dir, receipt, _values = make_bundle(
        module, tmp_path, monkeypatch
    )
    assert receipt["lifecycle"] == "cold"
    assert receipt["archived_lifecycle"] == "stopped"
    after = module.read_marker(source.state_dir, PROJECT)
    assert after["lifecycle"] == "cold"
    assert after["state_id"] == marker["state_id"]


def test_a_torn_down_target_stays_destroyable(module):
    """`backup` removes the Compose containers and networks it archived around.

    A marker that still claimed `stopped` afterwards would make the exact-set
    requirement in the destructive guards unsatisfiable, so `destroy` and
    `reset` would refuse the target and its volumes could only be removed out
    of band.
    """
    state_id = "a" * 32
    volumes = set(module.volume_names(PROJECT).values())
    labels = {
        module.PROJECT_LABEL: PROJECT,
        module.STATE_LABEL: state_id,
        module.SYNTHETIC_LABEL: "true",
    }
    discovered = {name: labels for name in volumes}
    # This is the shape a completed backup leaves: volumes, no services, no
    # networks.
    assert module.verify_destructive_resources(PROJECT, state_id, {}, {}, "cold") == (
        [],
        [],
    )
    assert module.verify_destructive_volumes(
        PROJECT, state_id, volumes, discovered, "cold"
    ) == sorted(volumes)
    # The gap this closes: the same shape under a `stopped` marker is refused.
    with pytest.raises(module.SafetyError, match="requires the exact service set"):
        module.verify_destructive_resources(PROJECT, state_id, {}, {}, "stopped")
    # `cold` is still not an operational state.
    cold = {"lifecycle": "cold"}
    with pytest.raises(module.SafetyError, match="rejects marker lifecycle"):
        module.ClinicalStaging._require_lifecycle(cold, "status", {"ready"})
    with pytest.raises(module.SafetyError, match="rejects marker lifecycle"):
        module.ClinicalStaging._require_lifecycle(cold, "backup", {"stopped"})
    # But `up` can rebuild it.
    module.ClinicalStaging._require_lifecycle(cold, "up", {"ready", "stopped", "cold"})
    assert "cold" not in module.SETTLED_LIFECYCLES
    assert "cold" in module.LIFECYCLE_STATES


# --------------------------------------------------------------------------
# The restored sealed environment must select the admitted target
# --------------------------------------------------------------------------


def bundle_with_env(module, tmp_path, monkeypatch, mutate):
    """Produce an internally consistent bundle whose compose.env was edited.

    Every digest is recomputed, so the bundle validates; only the values
    Compose will interpolate differ. This is the attack that
    `compose_env_sha256` alone cannot catch, because whoever builds the bundle
    controls both the file and the hash recorded for it.
    """
    staging, marker, _values = make_target(module, tmp_path)
    raw = (staging.state_dir / "compose.env").read_text(encoding="utf-8")
    edited = mutate(raw)
    (staging.state_dir / "compose.env").write_text(edited, encoding="utf-8")
    marker["compose_env_sha256"] = hashlib.sha256(edited.encode("utf-8")).hexdigest()
    module.write_json_atomic(staging.state_dir / module.MARKER_NAME, marker, mode=0o600)
    _stub_docker_backup(module, staging, monkeypatch, volumes_from=marker["volumes"])
    backup_dir = tmp_path / "cold-backup"
    receipt = staging.backup(backup_dir)
    return staging, backup_dir, receipt


@posix_only
@pytest.mark.parametrize(
    ("label", "mutate", "message"),
    [
        (
            "foreign image",
            lambda raw: re.sub(
                r"CLINICAL_INGRESS_IMAGE=.*",
                "CLINICAL_INGRESS_IMAGE=docker.io/library/mattermost:latest",
                raw,
            ),
            "CLINICAL_INGRESS_IMAGE",
        ),
        (
            "foreign volume",
            lambda raw: re.sub(
                r"CLINICAL_VOLUME_HRH_DB=.*",
                "CLINICAL_VOLUME_HRH_DB=somebody_elses_volume",
                raw,
            ),
            "CLINICAL_VOLUME_HRH_DB",
        ),
        (
            "foreign hrh root",
            lambda raw: re.sub(
                r"CLINICAL_HRH_ROOT=.*", "CLINICAL_HRH_ROOT=/tmp/other", raw
            ),
            "CLINICAL_HRH_ROOT",
        ),
        (
            "injected key",
            lambda raw: raw + "CLINICAL_EXTRA=1\n",
            "unknown or missing keys",
        ),
    ],
)
def test_restore_refuses_an_environment_that_selects_an_unadmitted_target(
    module, tmp_path, monkeypatch, label, mutate, message
):
    source, backup_dir, receipt = bundle_with_env(module, tmp_path, monkeypatch, mutate)
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    with pytest.raises(module.SafetyError, match=message):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert not target.state_dir.exists(), label
    assert not list(target.state_dir.parent.glob(".*recovering-*"))


@posix_only
def test_restore_refuses_a_malformed_environment(module, tmp_path, monkeypatch):
    source, backup_dir, receipt = bundle_with_env(
        module, tmp_path, monkeypatch, lambda raw: raw + "no-separator-line\n"
    )
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    with pytest.raises(module.SafetyError, match="compose environment is malformed"):
        target.restore(backup_dir, receipt["manifest_sha256"])
    assert not target.state_dir.exists()


# --------------------------------------------------------------------------
# Secret-bearing remnants of a killed command
# --------------------------------------------------------------------------


@posix_only
def test_killed_recovery_remnants_are_reconciled(module, tmp_path, monkeypatch):
    source, _marker, _values = make_target(module, tmp_path)
    parent = source.state_dir.parent
    remnants = []
    for shape in ("recovering", "bundle", "partial", "init"):
        remnant = parent / f".{source.state_dir.name}.{shape}-{secrets.token_hex(8)}"
        remnant.mkdir(mode=0o700)
        (remnant / "compose.env").write_text(SECRET_CANARY, encoding="ascii")
        remnants.append(remnant)
    unrelated = parent / f".{source.state_dir.name}.unrelated-0000000000000000"
    unrelated.mkdir(mode=0o700)

    source._reconcile_owned_initialization_orphans()
    assert all(not remnant.exists() for remnant in remnants)
    assert unrelated.exists(), "cleanup must stay inside its exact name allowlist"


@posix_only
def test_remnant_cleanup_fails_closed_on_a_linked_remnant(module, tmp_path):
    source, _marker, _values = make_target(module, tmp_path)
    parent = source.state_dir.parent
    remnant = parent / f".{source.state_dir.name}.bundle-{secrets.token_hex(8)}"
    remnant.mkdir(mode=0o700)
    (remnant / "escape").symlink_to("/etc/passwd")
    with pytest.raises(module.SafetyError, match="contains a symlink"):
        source._reconcile_owned_initialization_orphans()
    assert remnant.exists()


@posix_only
def test_destroy_reconciles_remnants_beside_the_state_directory(
    module, tmp_path, monkeypatch
):
    source, _marker, _values = make_target(module, tmp_path)
    parent = source.state_dir.parent
    remnant = parent / f".{source.state_dir.name}.bundle-{secrets.token_hex(8)}"
    remnant.mkdir(mode=0o700)
    (remnant / "compose.env").write_text(SECRET_CANARY, encoding="ascii")
    monkeypatch.setattr(source, "_require_linux", lambda: None)
    monkeypatch.setattr(source, "_destroy_resources", lambda: None)
    result = source.destroy()
    assert result["lifecycle"] == "destroyed"
    assert not source.state_dir.exists()
    assert not remnant.exists(), "destroy left a secret-bearing remnant on disk"


@posix_only
def test_per_state_lock_refuses_a_planted_symlink(module, tmp_path):
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    staging = module.ClinicalStaging(
        runtime, hrh, state, PROJECT, 18443, shell=QuietShell()
    )
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = state.parent / f".{state.name}.lifecycle.lock"
    target = tmp_path / "planted"
    target.write_bytes(b"")
    lock.symlink_to(target)
    with pytest.raises(OSError):
        with staging._state_lifecycle_lock():
            pass
    assert target.read_bytes() == b""


# --------------------------------------------------------------------------
# Causal verification is gated on the composed drill, not on restore
# --------------------------------------------------------------------------


def _causal(module, **overrides):
    checks = {name: True for name in module.CAUSAL_RECOVERY_CHECKS}
    checks.update(overrides)
    return checks


def _restored_ready(module, tmp_path, monkeypatch):
    """A restored, ready target holding a mechanical receipt."""
    source, _marker, backup_dir, receipt, _values = make_bundle(
        module, tmp_path, monkeypatch
    )
    target = restore_target(module, source)
    _stub_docker_restore(module, target, monkeypatch)
    target.restore(backup_dir, receipt["manifest_sha256"])
    marker = module.read_marker(target.state_dir, PROJECT)
    monkeypatch.setattr(target, "_verify_marker_and_source", lambda: marker)
    return target, receipt["manifest_sha256"], marker


@posix_only
def test_causal_verification_binds_the_mechanical_receipt(module, tmp_path, monkeypatch):
    target, manifest_sha, marker = _restored_ready(module, tmp_path, monkeypatch)
    verified = target.finalize_cold_recovery_verification(
        manifest_sha, _causal(module)
    )
    assert verified["verification"] == "causal_e2e_verified"
    assert verified["manifest_sha256"] == manifest_sha
    assert verified["state_id"] == marker["state_id"]
    assert set(verified["causal_checks"]) == set(module.CAUSAL_RECOVERY_CHECKS)
    assert "not a representative-host receipt" in verified["nonclaims"]
    published = (
        target.state_dir / "evidence" / "recovery" / f"verified-{manifest_sha}.json"
    )
    assert json.loads(published.read_text(encoding="utf-8")) == verified
    # The mechanical receipt is not replaced or relabelled.
    mechanical = json.loads(
        (target.state_dir / "evidence" / "recovery" / f"restore-{manifest_sha}.json")
        .read_text(encoding="utf-8")
    )
    assert mechanical["verification"] == "mechanical_restore_only"
    assert SECRET_CANARY not in json.dumps(verified, sort_keys=True)


@posix_only
def test_causal_verification_refuses_an_incomplete_or_failed_drill(
    module, tmp_path, monkeypatch
):
    target, manifest_sha, _marker = _restored_ready(module, tmp_path, monkeypatch)
    one = sorted(module.CAUSAL_RECOVERY_CHECKS)[0]
    for checks in (
        {},
        _causal(module, **{one: False}),
        {key: value for key, value in _causal(module).items() if key != one},
        {**_causal(module), "invented_check": True},
    ):
        with pytest.raises(module.SafetyError, match="incomplete or invalid"):
            target.finalize_cold_recovery_verification(manifest_sha, checks)
    assert not list(
        (target.state_dir / "evidence" / "recovery").glob("verified-*.json")
    )


@posix_only
def test_causal_verification_refuses_an_unbound_manifest(module, tmp_path, monkeypatch):
    target, manifest_sha, _marker = _restored_ready(module, tmp_path, monkeypatch)
    other = "b" * 64
    assert other != manifest_sha
    with pytest.raises(module.SafetyError, match="mechanical restore receipt is unavailable"):
        target.finalize_cold_recovery_verification(other, _causal(module))
    with pytest.raises(module.SafetyError, match="must be a lowercase SHA-256"):
        target.finalize_cold_recovery_verification("not-a-digest", _causal(module))
    assert not list(
        (target.state_dir / "evidence" / "recovery").glob("verified-*.json")
    )


@posix_only
def test_causal_verification_refuses_a_forged_mechanical_receipt(
    module, tmp_path, monkeypatch
):
    target, manifest_sha, _marker = _restored_ready(module, tmp_path, monkeypatch)
    path = target.state_dir / "evidence" / "recovery" / f"restore-{manifest_sha}.json"
    forged = json.loads(path.read_text(encoding="utf-8"))
    forged["verification"] = "causal_e2e_verified"
    module.write_json_atomic(path, forged, mode=0o600)
    with pytest.raises(module.SafetyError, match="does not bind this verification"):
        target.finalize_cold_recovery_verification(manifest_sha, _causal(module))


@posix_only
def test_causal_verification_requires_a_ready_target(module, tmp_path, monkeypatch):
    target, manifest_sha, marker = _restored_ready(module, tmp_path, monkeypatch)
    monkeypatch.setattr(
        target, "_verify_marker_and_source", lambda: dict(marker, lifecycle="cold")
    )
    with pytest.raises(module.SafetyError, match="rejects marker lifecycle"):
        target.finalize_cold_recovery_verification(manifest_sha, _causal(module))


# --------------------------------------------------------------------------
# Destroy proves its own bounded absence
# --------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("leftover", ["container", "network", "volume"])
def test_destroy_fails_when_its_own_namespace_survives(module, tmp_path, monkeypatch, leftover):
    source, _marker, _values = make_target(module, tmp_path)

    class LingeringShell(QuietShell):
        def run(self, *args: str, **kwargs):
            if leftover == "container" and args[:4] == (
                "docker", "container", "ls", "--all",
            ):
                return SimpleNamespace(
                    returncode=0, stdout=f"{PROJECT}-ingress-1\n", stderr=""
                )
            if leftover == "network" and args[:3] == ("docker", "network", "inspect"):
                return SimpleNamespace(returncode=0, stdout="[{}]", stderr="")
            if leftover == "volume" and args[:3] == ("docker", "volume", "inspect"):
                return SimpleNamespace(returncode=0, stdout="[{}]", stderr="")
            return super().run(*args, **kwargs)

    source.shell = LingeringShell()
    monkeypatch.setattr(source, "_require_linux", lambda: None)
    monkeypatch.setattr(source, "_destroy_resources", lambda: None)
    with pytest.raises(module.SafetyError, match=f"project {leftover}s? remains? after destroy"):
        source.destroy()


@posix_only
def test_destroy_absence_check_stays_inside_the_project_namespace(module, tmp_path):
    source, _marker, _values = make_target(module, tmp_path)

    class ForeignShell(QuietShell):
        def run(self, *args: str, **kwargs):
            if args[:4] == ("docker", "container", "ls", "--all"):
                # Another project's containers must not fail this teardown.
                return SimpleNamespace(
                    returncode=0,
                    stdout="clinicalstagingother-ingress-1\nunrelated\n",
                    stderr="",
                )
            return super().run(*args, **kwargs)

    source.shell = ForeignShell()
    source._assert_destroyed_absent()


# --------------------------------------------------------------------------
# Ingress readiness is a bounded barrier, not a single observation
# --------------------------------------------------------------------------


READY_LINE = "mattermost_ingress_outcome=authenticated_ready\n"
STARTED_AT = "2026-09-15T03:01:37.109884947Z"


def _ready_target(module, tmp_path, monkeypatch, *, states, logs):
    """A staging instance whose ingress inspections and logs are scripted."""
    source, _marker, _values = make_target(module, tmp_path)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    inspections = list(states)
    log_values = list(logs)

    def next_inspection():
        value = inspections.pop(0) if len(inspections) > 1 else inspections[0]
        return {"ingress": {"State": value}}

    def fake_compose(*args, **_kwargs):
        if args[:2] == ("logs", "--no-color"):
            assert args[3] == STARTED_AT, "the window must be the container start time"
            value = log_values.pop(0) if len(log_values) > 1 else log_values[0]
            return SimpleNamespace(returncode=0, stdout=value, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(source, "_container_inspections", next_inspection)
    monkeypatch.setattr(source, "compose", fake_compose)
    return source


@posix_only
def test_ingress_readiness_waits_instead_of_racing(module, tmp_path, monkeypatch):
    """Restore starts ingress moments before status observes it."""
    running = {"Running": True, "Status": "running"}
    source = _ready_target(
        module,
        tmp_path,
        monkeypatch,
        states=[running],
        logs=["", "", READY_LINE],
    )
    source._await_ingress_ready(STARTED_AT)


@posix_only
def test_ingress_readiness_fails_fast_when_ingress_exits(module, tmp_path, monkeypatch):
    source = _ready_target(
        module,
        tmp_path,
        monkeypatch,
        states=[{"Running": False, "Status": "exited"}],
        logs=[""],
    )
    with pytest.raises(module.SafetyError, match="exited before authenticated readiness"):
        source._await_ingress_ready(STARTED_AT)


@posix_only
def test_ingress_readiness_still_fails_closed_on_timeout(module, tmp_path, monkeypatch):
    source = _ready_target(
        module,
        tmp_path,
        monkeypatch,
        states=[{"Running": True, "Status": "running"}],
        logs=[""],
    )
    clock = iter([0.0, 0.0, 1000.0, 1000.0, 2000.0, 2000.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))
    with pytest.raises(module.SafetyError, match="not authenticated-ready"):
        source._await_ingress_ready(STARTED_AT)


@posix_only
def test_ingress_readiness_never_accepts_an_earlier_run(module, tmp_path, monkeypatch):
    """The window is the container's own start time, so a stale line cannot pass."""
    source, _marker, _values = make_target(module, tmp_path)
    windows: list[str] = []

    def fake_compose(*args, **_kwargs):
        if args[:2] == ("logs", "--no-color"):
            windows.append(args[3])
            return SimpleNamespace(returncode=0, stdout=READY_LINE, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        source,
        "_container_inspections",
        lambda: {"ingress": {"State": {"Running": True, "Status": "running"}}},
    )
    monkeypatch.setattr(source, "compose", fake_compose)
    source._await_ingress_ready(STARTED_AT)
    assert windows == [STARTED_AT]
