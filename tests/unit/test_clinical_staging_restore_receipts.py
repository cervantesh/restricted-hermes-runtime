"""Executable RED contract for published cold-backup recovery receipts.

The source-build assertions are compatibility controls.  The published-mode
assertions intentionally describe behavior that production does not implement
yet; they must fail at the missing receipt boundary, not because of a malformed
fixture.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
CODEC_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_backup_bundle.py"

BACKUP_SCHEMA = "restricted-synthetic-clinical-cold-backup-receipt-published.v1"
MECHANICAL_SCHEMA = "restricted-synthetic-clinical-cold-restore-published.v1"
CAUSAL_SCHEMA = "restricted-synthetic-clinical-cold-restore-verification-published.v1"

BACKUP_FIELDS = {
    "schema", "synthetic_only", "project", "state_id", "mode",
    "manifest_sha256", "backup_identity_sha256", "capsule_id",
    "capsule_ciphertext_sha256", "capsule_ciphertext_size",
    "backup_recovery_trust_sha256", "backup_recovery_policy_epoch",
    "recipient_sha256", "sealer_sha256", "runtime_source", "hrh_candidate",
    "effective_images", "excluded_volume", "backed_up_at", "nonclaims",
}
MECHANICAL_FIELDS = {
    "schema", "synthetic_only", "project", "state_id", "mode",
    "manifest_sha256", "backup_identity_sha256", "capsule_id",
    "capsule_ciphertext_sha256", "backup_recovery_trust_sha256",
    "backup_recovery_policy_epoch", "restore_recovery_trust_sha256",
    "restore_recovery_policy_epoch", "restore_recipient_status",
    "recipient_sha256", "runtime_source", "hrh_candidate", "effective_images",
    "excluded_volume", "status_observed_at", "verification", "restored_at",
    "nonclaims",
}
CAUSAL_FIELDS = {
    "schema", "synthetic_only", "project", "state_id", "mode",
    "manifest_sha256", "mechanical_receipt_sha256", "backup_identity_sha256",
    "capsule_id", "capsule_ciphertext_sha256", "backup_recovery_trust_sha256",
    "backup_recovery_policy_epoch", "restore_recovery_trust_sha256",
    "restore_recovery_policy_epoch", "restore_recipient_status",
    "recipient_sha256", "runtime_source", "hrh_candidate", "effective_images",
    "verification", "causal_checks", "verified_at", "nonclaims",
}

BACKUP_NONCLAIMS = [
    "not a scheduled backup", "not PHI-authorized", "not production",
    "not a compliance certification",
]
MECHANICAL_NONCLAIMS = [
    "not a causal recovery verification", "not PHI-authorized", "not production",
    "not a compliance certification",
]
CAUSAL_NONCLAIMS = [
    "not PHI-authorized", "not production", "not a compliance certification",
]


class ReceiptSafetyError(RuntimeError):
    """Expected fail-closed error surface for the published receipt codec."""


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _published_fixture() -> dict[str, Any]:
    runtime_source = {"head": "1" * 40, "tree": "2" * 40}
    hrh_candidate = {
        "head": "3" * 40,
        "tree": "4" * 40,
        "image_id": "sha256:" + "5" * 64,
    }
    effective_images = {
        "hrh": "sha256:" + "6" * 64,
        "hrh-migrate": "sha256:" + "7" * 64,
    }
    identity = {
        "schema": "restricted-synthetic-clinical-backup-identity.v1",
        "project": "clinicalstagingdemo",
        "state_id": "8" * 32,
        "runtime_source": runtime_source,
        "hrh_candidate": hrh_candidate,
        "effective_images": effective_images,
        "capsule_id": "9" * 32,
        "recipient_sha256": "a" * 64,
        "sealer_sha256": "b" * 64,
        "recovery_trust_sha256": "c" * 64,
        "recovery_policy_epoch": 7,
    }
    manifest = {
        "schema": "restricted-synthetic-clinical-cold-backup-published.v2",
        "synthetic_only": True,
        "project": identity["project"],
        "state_id": identity["state_id"],
        "backup_identity_sha256": _sha(identity),
        "capsule_id": identity["capsule_id"],
        "capsule_ciphertext_sha256": "d" * 64,
        "capsule_ciphertext_size": 4096,
        "backup_recovery_trust_sha256": identity["recovery_trust_sha256"],
        "backup_recovery_policy_epoch": identity["recovery_policy_epoch"],
        "recipient_sha256": identity["recipient_sha256"],
        "sealer_sha256": identity["sealer_sha256"],
        "runtime_source": runtime_source,
        "hrh_candidate": hrh_candidate,
        "effective_images": effective_images,
        "excluded_volume": "clinical_socket",
    }
    restore_trust = {
        "schema": "restricted-synthetic-clinical-recovery-trust.v1",
        "policy_epoch": 8,
        "recipients": [
            {"recipient_sha256": "a" * 64, "status": "retired"},
            {"recipient_sha256": "e" * 64, "status": "active"},
        ],
    }
    return {
        "identity": identity,
        "manifest": manifest,
        "manifest_sha256": _sha(manifest),
        "restore_trust": restore_trust,
        "restore_trust_sha256": _sha(restore_trust),
    }


def _codec_contract(codec, tmp_path: Path | None = None):
    return codec.BackupContract(
        error_type=ReceiptSafetyError,
        schema="restricted-synthetic-clinical-staging.v1",
        marker_name="clinical-staging.json",
        backup_schema="restricted-synthetic-clinical-cold-backup.v1",
        manifest_name="manifest.json",
        complete_name="COMPLETE",
        state_archive_name="state.tar",
        volume_directory="volumes",
        volume_keys=("hrh_secret", "clinical_socket"),
        backup_volume_keys=("hrh_secret",),
        excluded_volume="clinical_socket",
        required_hrh_head="3" * 40,
        required_hrh_tree="4" * 40,
        volume_names=lambda project: {"hrh_secret": f"{project}_hrh_secret"},
        validate_project=lambda project: project,
        fsync_file=lambda _path: None,
        fsync_directory=lambda _path: None,
        write_json_atomic=lambda path, value, **_kwargs: path.write_bytes(_canonical(value)),
    )


def _require_builder(codec, name: str):
    builder = getattr(codec, name, None)
    assert callable(builder), f"U4R RED: missing {name} published receipt builder"
    return builder


def _assert_closed(receipt: Mapping[str, Any], fields: set[str]) -> None:
    assert set(receipt) == fields


def _assert_bound_common(receipt: Mapping[str, Any], fixture: Mapping[str, Any]) -> None:
    manifest = fixture["manifest"]
    assert receipt["synthetic_only"] is True
    for field in (
        "project", "state_id", "backup_identity_sha256", "capsule_id",
        "capsule_ciphertext_sha256", "backup_recovery_trust_sha256",
        "backup_recovery_policy_epoch", "recipient_sha256", "runtime_source",
        "hrh_candidate", "effective_images",
    ):
        assert receipt[field] == manifest[field]
    assert receipt["manifest_sha256"] == fixture["manifest_sha256"]


def test_source_v1_causal_receipt_remains_exact_under_frozen_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R01: the new published contract cannot silently rewrite source-v1."""
    staging_module = _load(STAGING_PATH, "clinical_staging_receipt_source_control")
    project = "clinicalstagingdemo"
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir(); hrh.mkdir(); (state / "evidence" / "recovery").mkdir(parents=True)
    marker = staging_module.new_marker(
        project=project, state_dir=state, state_id="8" * 32,
        env_sha256="2" * 64, runtime_head="1" * 40, runtime_tree="2" * 40,
        hrh_head=staging_module.REQUIRED_HRH_SHA,
        hrh_tree=staging_module.REQUIRED_HRH_TREE, lifecycle="ready",
    )
    manifest_sha256 = "f" * 64
    staging_module.write_json_atomic(state / staging_module.MARKER_NAME, marker, mode=0o600)
    staging_module.write_json_atomic(
        state / "evidence" / "recovery" / f"restore-{manifest_sha256}.json",
        {"manifest_sha256": manifest_sha256, "verification": "mechanical_restore_only"},
        mode=0o600,
    )
    fixed = datetime(2026, 8, 1, 12, 30, tzinfo=UTC)

    class FrozenDateTime:
        @classmethod
        def now(cls, _tz):
            return fixed

    staging = staging_module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging_module, "datetime", FrozenDateTime)
    checks = {key: True for key in staging_module.CAUSAL_RECOVERY_CHECKS}
    receipt = staging.finalize_cold_recovery_verification(manifest_sha256, checks)
    assert _canonical(receipt) == _canonical({
        "schema": "restricted-synthetic-clinical-cold-backup.v1",
        "synthetic_only": True,
        "project": project,
        "state_id": "8" * 32,
        "manifest_sha256": manifest_sha256,
        "verification": "causal_e2e_verified",
        "causal_checks": {key: True for key in sorted(staging_module.CAUSAL_RECOVERY_CHECKS)},
        "verified_at": fixed.isoformat(),
        "nonclaims": ["not PHI", "not production", "not a compliance certification"],
    })


def test_source_v1_backup_receipt_remains_exact_with_normalized_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_receipt_backup_control")
    project = "clinicalstagingdemo"
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir(); hrh.mkdir(); state.mkdir(); (state / "seed").mkdir(); (state / "evidence").mkdir()
    (state / "compose.env").write_text("CLINICAL_SYNTHETIC=true\n", encoding="utf-8")
    marker = staging_module.new_marker(
        project=project, state_dir=state, state_id="8" * 32,
        env_sha256=staging_module.file_sha256(state / "compose.env"),
        runtime_head="1" * 40, runtime_tree="2" * 40,
        hrh_head=staging_module.REQUIRED_HRH_SHA,
        hrh_tree=staging_module.REQUIRED_HRH_TREE, lifecycle="stopped",
    )
    staging_module.write_json_atomic(state / staging_module.MARKER_NAME, marker, mode=0o600)
    staging = staging_module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: None)
    monkeypatch.setattr(staging, "compose", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(staging, "_assert_unmounted_backup_volumes", lambda _volumes: None)
    monkeypatch.setattr(staging_module, "create_state_archive", lambda _state, path: path.write_bytes(b"state"))
    monkeypatch.setattr(staging, "_backup_volume", lambda key, _name, target: (target / "volumes" / f"{key}.tar").write_bytes(b"volume"))
    monkeypatch.setattr(staging_module, "fsync_directory", lambda _path: None)
    monkeypatch.setattr(staging_module, "build_backup_manifest", lambda *_args: {"schema": staging_module.BACKUP_SCHEMA})
    monkeypatch.setattr(staging_module, "write_backup_completion", lambda path: (path / staging_module.BACKUP_COMPLETE_NAME).write_bytes(b"complete\n"))
    backup = tmp_path / "backup"
    receipt = staging.backup(backup)
    normalized = dict(receipt, backup_dir="<BACKUP>")
    assert _canonical(normalized) == _canonical({
        "schema": "restricted-synthetic-clinical-cold-backup.v1",
        "synthetic_only": True, "project": project, "state_id": "8" * 32,
        "backup_dir": "<BACKUP>",
        "manifest_sha256": staging_module.file_sha256(backup / staging_module.BACKUP_MANIFEST_NAME),
        "excluded_volume": "clinical_socket", "lifecycle": "stopped",
        "nonclaims": ["not a scheduled backup", "not encrypted", "not production"],
    })


def test_source_v1_mechanical_receipt_remains_exact_under_frozen_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_receipt_mechanical_control")
    project = "clinicalstagingdemo"
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    state, backup, snapshot = (
        tmp_path / f"{project}.synthetic-clinical-staging",
        tmp_path / "backup",
        tmp_path / "snapshot",
    )
    runtime.mkdir(); hrh.mkdir(); backup.mkdir()
    compose_bytes = b"CLINICAL_SYNTHETIC=true\n"
    marker = staging_module.new_marker(
        project=project, state_dir=state, state_id="8" * 32,
        env_sha256=hashlib.sha256(compose_bytes).hexdigest(),
        runtime_head="1" * 40, runtime_tree="2" * 40,
        hrh_head=staging_module.REQUIRED_HRH_SHA,
        hrh_tree=staging_module.REQUIRED_HRH_TREE, lifecycle="stopped",
    )
    source = {"runtime_head": "1" * 40, "runtime_tree": "2" * 40,
              "hrh_head": staging_module.REQUIRED_HRH_SHA,
              "hrh_tree": staging_module.REQUIRED_HRH_TREE}
    manifest_sha256 = "f" * 64
    manifest = {"source": source, "compose_env_sha256": marker["compose_env_sha256"]}
    staging = staging_module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging_module, "validate_backup_path", lambda path, **_kwargs: path)

    def make_snapshot(*_args, **_kwargs):
        snapshot.mkdir()
        (snapshot / staging_module.BACKUP_MANIFEST_NAME).write_text("{}\n", encoding="utf-8")
        return snapshot

    def extract(_archive, target):
        (target / "compose.env").write_bytes(compose_bytes)
        staging_module.write_json_atomic(target / staging_module.MARKER_NAME, marker, mode=0o600)

    monkeypatch.setattr(staging_module, "materialize_backup_snapshot", make_snapshot)
    monkeypatch.setattr(staging_module, "validate_backup_bundle", lambda *_args: manifest)
    monkeypatch.setattr(staging_module, "verify_source_frame", lambda *_args: source)
    monkeypatch.setattr(staging, "_require_empty_restore_destination", lambda: None)
    monkeypatch.setattr(staging, "_extract_safe_state_archive", extract)
    monkeypatch.setattr(staging, "_create_volumes", lambda _marker: None)
    monkeypatch.setattr(staging, "_restore_volume", lambda *_args: None)
    monkeypatch.setattr(staging, "_start_restored_stack", lambda: None)
    monkeypatch.setattr(staging, "status", lambda **_kwargs: {"observed_at": "2026-08-01T12:29:00Z"})
    monkeypatch.setattr(staging_module, "fsync_directory", lambda _path: None)
    fixed = datetime(2026, 8, 1, 12, 30, tzinfo=UTC)

    class FrozenDateTime:
        @classmethod
        def now(cls, _tz):
            return fixed

    monkeypatch.setattr(staging_module, "datetime", FrozenDateTime)
    receipt = staging.restore(backup, manifest_sha256)
    assert _canonical(receipt) == _canonical({
        "schema": "restricted-synthetic-clinical-cold-backup.v1",
        "synthetic_only": True, "project": project, "state_id": "8" * 32,
        "manifest_sha256": manifest_sha256, "excluded_volume": "clinical_socket",
        "source": source, "status_observed_at": "2026-08-01T12:29:00Z",
        "verification": "mechanical_restore_only", "restored_at": fixed.isoformat(),
        "nonclaims": [
            "not a causal recovery verification", "not a hot restore",
            "not encrypted", "not production",
        ],
    })


def test_published_backup_receipt_is_closed_and_operation_specific(tmp_path: Path) -> None:
    codec = _load(CODEC_PATH, "clinical_backup_bundle_receipt_backup_red")
    fixture = _published_fixture()
    receipt = _require_builder(codec, "build_backup_receipt")(
        _codec_contract(codec), fixture["manifest"], tmp_path / "published-backup",
        identity=fixture["identity"], manifest_sha256=fixture["manifest_sha256"],
        backed_up_at="2026-08-01T12:30:00Z",
    )
    _assert_closed(receipt, BACKUP_FIELDS)
    _assert_bound_common(receipt, fixture)
    assert receipt["schema"] == BACKUP_SCHEMA
    assert receipt["mode"] == "published_backup"
    assert receipt["capsule_ciphertext_size"] == 4096
    assert receipt["sealer_sha256"] == "b" * 64
    assert receipt["excluded_volume"] == "clinical_socket"
    assert receipt["nonclaims"] == BACKUP_NONCLAIMS


def test_published_mechanical_receipt_preserves_archived_and_fresh_authority() -> None:
    codec = _load(CODEC_PATH, "clinical_backup_bundle_receipt_mechanical_red")
    fixture = _published_fixture()
    receipt = _require_builder(codec, "build_restore_receipt")(
        _codec_contract(codec), fixture["manifest"], fixture["manifest_sha256"],
        identity=fixture["identity"],
        restore_trust=fixture["restore_trust"],
        restore_trust_sha256=fixture["restore_trust_sha256"],
        status_observed_at="2026-08-01T12:29:00Z",
        restored_at="2026-08-01T12:30:00Z",
    )
    _assert_closed(receipt, MECHANICAL_FIELDS)
    _assert_bound_common(receipt, fixture)
    assert receipt["schema"] == MECHANICAL_SCHEMA
    assert receipt["mode"] == "published_restore"
    assert receipt["backup_recovery_trust_sha256"] == "c" * 64
    assert receipt["backup_recovery_policy_epoch"] == 7
    assert receipt["restore_recovery_trust_sha256"] == fixture["restore_trust_sha256"]
    assert receipt["restore_recovery_policy_epoch"] == 8
    assert receipt["restore_recipient_status"] == "retired"
    assert receipt["verification"] == "mechanical_restore_only"
    assert receipt["nonclaims"] == MECHANICAL_NONCLAIMS


def test_published_causal_receipt_hashes_exact_mechanical_bytes() -> None:
    codec = _load(CODEC_PATH, "clinical_backup_bundle_receipt_causal_red")
    fixture = _published_fixture()
    mechanical = {
        "schema": MECHANICAL_SCHEMA,
        "synthetic_only": True,
        "project": fixture["manifest"]["project"],
        "state_id": fixture["manifest"]["state_id"],
        "mode": "published_restore",
        "manifest_sha256": fixture["manifest_sha256"],
        "backup_identity_sha256": fixture["manifest"]["backup_identity_sha256"],
        "capsule_id": fixture["manifest"]["capsule_id"],
        "capsule_ciphertext_sha256": fixture["manifest"]["capsule_ciphertext_sha256"],
        "backup_recovery_trust_sha256": "c" * 64,
        "backup_recovery_policy_epoch": 7,
        "restore_recovery_trust_sha256": fixture["restore_trust_sha256"],
        "restore_recovery_policy_epoch": 8,
        "restore_recipient_status": "retired",
        "recipient_sha256": "a" * 64,
        "runtime_source": fixture["manifest"]["runtime_source"],
        "hrh_candidate": fixture["manifest"]["hrh_candidate"],
        "effective_images": fixture["manifest"]["effective_images"],
        "excluded_volume": "clinical_socket",
        "status_observed_at": "2026-08-01T12:29:00Z",
        "verification": "mechanical_restore_only",
        "restored_at": "2026-08-01T12:30:00Z",
        "nonclaims": MECHANICAL_NONCLAIMS,
    }
    mechanical_bytes = _canonical(mechanical)
    checks = {"backup_data_observed": True, "gateway_observed": True, "restart_observed": True}
    receipt = _require_builder(codec, "build_causal_receipt")(
        _codec_contract(codec), mechanical_bytes, fixture["manifest"], fixture["identity"],
        fixture["restore_trust"], fixture["restore_trust_sha256"], checks,
        verified_at="2026-08-01T12:31:00Z",
    )
    _assert_closed(receipt, CAUSAL_FIELDS)
    _assert_bound_common(receipt, fixture)
    assert receipt["schema"] == CAUSAL_SCHEMA
    assert receipt["mode"] == "published_restore_verification"
    assert receipt["mechanical_receipt_sha256"] == hashlib.sha256(mechanical_bytes).hexdigest()
    assert receipt["restore_recipient_status"] == "retired"
    assert receipt["verification"] == "causal_e2e_verified"
    assert receipt["causal_checks"] == checks
    assert receipt["nonclaims"] == CAUSAL_NONCLAIMS


@pytest.mark.parametrize(
    ("mutant", "reason"),
    (
        ({"schema": "restricted-synthetic-clinical-cold-backup.v1"}, "cross-mode schema"),
        ({"mode": "published_backup"}, "cross-mode operation"),
        ({"restore_recipient_status": "active"}, "fresh authority substitution"),
        ({"effective_images": {"hrh": "sha256:" + "0" * 64}}, "candidate substitution"),
    ),
)
def test_published_causal_builder_kills_cross_mode_and_substitution_mutants(
    mutant: Mapping[str, Any], reason: str,
) -> None:
    codec = _load(CODEC_PATH, f"clinical_backup_bundle_mutant_{reason.replace(' ', '_')}")
    fixture = _published_fixture()
    mechanical = {
        "schema": MECHANICAL_SCHEMA, "synthetic_only": True,
        "project": fixture["manifest"]["project"], "state_id": fixture["manifest"]["state_id"],
        "mode": "published_restore", "manifest_sha256": fixture["manifest_sha256"],
        "backup_identity_sha256": fixture["manifest"]["backup_identity_sha256"],
        "capsule_id": fixture["manifest"]["capsule_id"],
        "capsule_ciphertext_sha256": fixture["manifest"]["capsule_ciphertext_sha256"],
        "backup_recovery_trust_sha256": "c" * 64, "backup_recovery_policy_epoch": 7,
        "restore_recovery_trust_sha256": fixture["restore_trust_sha256"],
        "restore_recovery_policy_epoch": 8, "restore_recipient_status": "retired",
        "recipient_sha256": "a" * 64, "runtime_source": fixture["manifest"]["runtime_source"],
        "hrh_candidate": fixture["manifest"]["hrh_candidate"],
        "effective_images": fixture["manifest"]["effective_images"],
        "excluded_volume": "clinical_socket", "status_observed_at": "2026-08-01T12:29:00Z",
        "verification": "mechanical_restore_only", "restored_at": "2026-08-01T12:30:00Z",
        "nonclaims": MECHANICAL_NONCLAIMS,
    }
    mechanical.update(mutant)
    builder = _require_builder(codec, "build_causal_receipt")
    with pytest.raises(ReceiptSafetyError, match="bind|schema|mode|authority|image"):
        builder(
            _codec_contract(codec), _canonical(mechanical), fixture["manifest"], fixture["identity"],
            fixture["restore_trust"], fixture["restore_trust_sha256"],
            {"backup_data_observed": True, "gateway_observed": True, "restart_observed": True},
            verified_at="2026-08-01T12:31:00Z",
        )


def test_published_causal_builder_rejects_duplicate_and_minimal_mechanical_receipts() -> None:
    codec = _load(CODEC_PATH, "clinical_backup_bundle_duplicate_red")
    fixture = _published_fixture()
    builder = _require_builder(codec, "build_causal_receipt")
    inputs = (
        b'{"schema":"x","schema":"y"}\n',
        _canonical({"schema": MECHANICAL_SCHEMA, "verification": "mechanical_restore_only"}),
    )
    for mechanical_bytes in inputs:
        with pytest.raises(ReceiptSafetyError, match="duplicate|fields|mechanical"):
            builder(
                _codec_contract(codec), mechanical_bytes, fixture["manifest"], fixture["identity"],
                fixture["restore_trust"], fixture["restore_trust_sha256"],
                {"backup_data_observed": True, "gateway_observed": True, "restart_observed": True},
                verified_at="2026-08-01T12:31:00Z",
            )
