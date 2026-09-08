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
import os
import sys
import tarfile
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Mapping

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
CODEC_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_backup_bundle.py"
VERIFIER_PATH = ROOT / "tools" / "verify_hrh_published_candidate.py"

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
CAUSAL_CHECKS = (
    "already_delivered_not_redelivered", "artifacts_clean", "duration_bounded",
    "expired_policy_fails_closed", "isolation_preserved", "source_deletion_persisted",
    "unknown_delivery_is_ambiguous_once",
)


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


def _persisted(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _sha(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _public_evidence_tar() -> tuple[bytes, str]:
    verifier = _load(VERIFIER_PATH, "receipt_fixture_published_verifier")
    names = (*verifier.EVIDENCE_FILES, "SHA256SUMS.json", "trust.json", "verification.json")
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name in names:
            payload = _canonical({"synthetic": name})
            info = tarfile.TarInfo(name)
            info.size, info.uid, info.gid, info.mode, info.mtime = len(payload), 0, 0, 0o600, 0
            archive.addfile(info, BytesIO(payload))
    ownership = [{"name": name, "kind": "file", "uid": 0, "gid": 0, "mode": 0o600}
                 for name in names]
    return stream.getvalue(), hashlib.sha256(_canonical({"entries": ownership})).hexdigest()


def _published_fixture() -> dict[str, Any]:
    recipient = "age106z8cqt3xncqk4r8qzv9zjvtjeupz2nyepc45y63ft3l4v0yxauqvn082m"
    runtime_source = {"runtime_head": "1" * 40, "runtime_tree": "2" * 40}
    subjects = {
        "web": "registry.invalid/hrh/web@sha256:" + "5" * 64,
        "migrate": "registry.invalid/hrh/migrate@sha256:" + "6" * 64,
        "evidence": "registry.invalid/hrh/evidence@sha256:" + "7" * 64,
    }
    hrh_candidate = {
        "clinical_contract_revision": "3" * 40,
        "build_source_revision": "4" * 40,
        "platform": {"os": "linux", "architecture": "amd64"},
        "publisher_identity": "synthetic@example.invalid",
        "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "kms_public_key_sha256": "8" * 64,
        "subjects": subjects,
        "trust_sha256": "9" * 64,
        "receipt_sha256": "a" * 64,
        "receipt_signature_sha256": "b" * 64,
        "evidence_manifest_sha256": "c" * 64,
        "verification_sha256": "d" * 64,
    }
    effective_images = {
        "hrh": {"subject": subjects["web"], "image_id": "sha256:" + "e" * 64,
                "repo_digest": subjects["web"],
                "platform": {"os": "linux", "architecture": "amd64"}},
        "hrh-migrate": {"subject": subjects["migrate"], "image_id": "sha256:" + "f" * 64,
                        "repo_digest": subjects["migrate"],
                        "platform": {"os": "linux", "architecture": "amd64"}},
    }
    volumes = {name: f"clinicalstagingdemo_{name}" for name in (
        "mattermost_db", "mattermost_data", "mattermost_tls", "hrh_db", "hrh_tls",
        "hrh_secret", "clinical_config", "ingress_config", "ingress_outbox",
        "controller_state", "clinical_socket",
    )}
    backup_trust = {
        "schema": "restricted-synthetic-clinical-recovery-trust.v1",
        "policy_epoch": 7, "scheme": "age-x25519-v1", "sealer_sha256": "0" * 64,
        "recipients": [{
            "recipient": recipient,
            "recipient_sha256": "d7e4c51b9091c0044800b11562f89df3b960fbcef2e82ff6ae454adec72d0f63",
            "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
            "status": "active",
        }],
    }
    identity = {
        "schema": "restricted-synthetic-clinical-backup-identity-published.v1",
        "project": "clinicalstagingdemo",
        "state_id": "1" * 32, "compose_env_sha256": "2" * 64,
        "runtime_source": runtime_source,
        "hrh_candidate": hrh_candidate,
        "effective_images": effective_images,
        "volumes": volumes, "excluded_volume": "clinical_socket",
        "capsule_id": "3" * 32,
        "recipient_sha256": backup_trust["recipients"][0]["recipient_sha256"],
        "sealer_sha256": backup_trust["sealer_sha256"],
        "recovery_trust_sha256": _sha(backup_trust),
        "recovery_policy_epoch": 7,
    }
    identity_bytes = _canonical(identity)
    capsule_bytes = b"synthetic-age-ciphertext"
    public_evidence_bytes, public_evidence_ownership = _public_evidence_tar()
    public_evidence = {
        "sha256": hashlib.sha256(public_evidence_bytes).hexdigest(),
        "size": len(public_evidence_bytes), "ownership_sha256": public_evidence_ownership,
    }
    members = {
        "backup-identity.json": {"sha256": hashlib.sha256(identity_bytes).hexdigest(),
                                 "size": len(identity_bytes), "ownership_sha256": "6" * 64},
        "public-evidence.tar": dict(public_evidence),
        "recovery-trust.json": {"sha256": _sha(backup_trust),
                                "size": len(_canonical(backup_trust)), "ownership_sha256": "7" * 64},
    }
    manifest = {
        "schema": "restricted-synthetic-clinical-cold-backup-published.v2",
        "synthetic_only": True, "complete": True,
        "backup_identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
        "recovery_trust_sha256": _sha(backup_trust),
        "public_evidence": public_evidence,
        "recovery_capsule": {"capsule_id": identity["capsule_id"],
                             "ciphertext_sha256": hashlib.sha256(capsule_bytes).hexdigest(),
                             "ciphertext_size": len(capsule_bytes)},
        "members": members,
    }
    restore_trust = json.loads(json.dumps(backup_trust))
    restore_trust["policy_epoch"] = 8
    restore_trust["recipients"][0]["status"] = "retired"
    restore_trust["recipients"].append({
        "recipient": "age1t3fs297r3w63m5rqhm0gz02plwyj75923w85yyavsmzulh3mk3mqnexkzu",
        "recipient_sha256": "86489544e034f48a012a2ec01c7cfb53fb6403db0a415ae6c64daa345bec8299",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z", "status": "active",
    })
    restore_trust["recipients"].sort(key=lambda item: item["recipient_sha256"])
    current_marker = {
        "schema": "restricted-synthetic-clinical-staging-published.v1",
        "synthetic_only": True, "project": identity["project"],
        "state_dir": "<STATE>", "state_id": identity["state_id"],
        "compose_env_sha256": identity["compose_env_sha256"], "lifecycle": "ready",
        "runtime_head": runtime_source["runtime_head"], "runtime_tree": runtime_source["runtime_tree"],
        "volumes": volumes, "hrh_candidate": hrh_candidate, "effective_images": effective_images,
    }
    return {
        "identity": identity, "identity_bytes": identity_bytes,
        "backup_trust": backup_trust, "backup_trust_bytes": _canonical(backup_trust),
        "manifest": manifest, "manifest_bytes": _canonical(manifest),
        "manifest_sha256": _sha(manifest),
        "restore_trust": restore_trust,
        "restore_trust_sha256": _sha(restore_trust),
        "capsule_bytes": capsule_bytes, "current_marker": current_marker,
        "public_evidence_bytes": public_evidence_bytes,
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
    identity, manifest = fixture["identity"], fixture["manifest"]
    assert receipt["synthetic_only"] is True
    for field in (
        "project", "state_id", "recipient_sha256", "runtime_source",
        "hrh_candidate", "effective_images",
    ):
        assert receipt[field] == identity[field]
    assert receipt["backup_identity_sha256"] == manifest["backup_identity_sha256"]
    assert receipt["capsule_id"] == manifest["recovery_capsule"]["capsule_id"]
    assert receipt["capsule_ciphertext_sha256"] == manifest["recovery_capsule"]["ciphertext_sha256"]
    assert receipt["backup_recovery_trust_sha256"] == identity["recovery_trust_sha256"]
    assert receipt["backup_recovery_policy_epoch"] == identity["recovery_policy_epoch"]
    assert receipt["manifest_sha256"] == fixture["manifest_sha256"]


def _published_mechanical(fixture: Mapping[str, Any]) -> dict[str, Any]:
    identity, capsule = fixture["identity"], fixture["manifest"]["recovery_capsule"]
    return {
        "schema": MECHANICAL_SCHEMA, "synthetic_only": True,
        "project": identity["project"], "state_id": identity["state_id"],
        "mode": "published_restore", "manifest_sha256": fixture["manifest_sha256"],
        "backup_identity_sha256": fixture["manifest"]["backup_identity_sha256"],
        "capsule_id": capsule["capsule_id"],
        "capsule_ciphertext_sha256": capsule["ciphertext_sha256"],
        "backup_recovery_trust_sha256": identity["recovery_trust_sha256"],
        "backup_recovery_policy_epoch": identity["recovery_policy_epoch"],
        "restore_recovery_trust_sha256": fixture["restore_trust_sha256"],
        "restore_recovery_policy_epoch": fixture["restore_trust"]["policy_epoch"],
        "restore_recipient_status": "retired", "recipient_sha256": identity["recipient_sha256"],
        "runtime_source": identity["runtime_source"], "hrh_candidate": identity["hrh_candidate"],
        "effective_images": identity["effective_images"], "excluded_volume": "clinical_socket",
        "status_observed_at": "2026-08-01T12:29:00Z",
        "verification": "mechanical_restore_only", "restored_at": "2026-08-01T12:30:00Z",
        "nonclaims": MECHANICAL_NONCLAIMS,
    }


def _expected_published_causal(fixture: Mapping[str, Any], mechanical_bytes: bytes) -> dict[str, Any]:
    mechanical = json.loads(mechanical_bytes)
    return {
        key: mechanical[key] for key in (
            "project", "state_id", "manifest_sha256", "backup_identity_sha256", "capsule_id",
            "capsule_ciphertext_sha256", "backup_recovery_trust_sha256",
            "backup_recovery_policy_epoch", "restore_recovery_trust_sha256",
            "restore_recovery_policy_epoch", "restore_recipient_status", "recipient_sha256",
            "runtime_source", "hrh_candidate", "effective_images",
        )
    } | {
        "schema": CAUSAL_SCHEMA, "synthetic_only": True,
        "mode": "published_restore_verification",
        "mechanical_receipt_sha256": hashlib.sha256(mechanical_bytes).hexdigest(),
        "verification": "causal_e2e_verified",
        "causal_checks": {name: True for name in CAUSAL_CHECKS},
        "verified_at": "2026-08-01T12:31:00Z", "nonclaims": CAUSAL_NONCLAIMS,
    }


def _expected_published_backup(fixture: Mapping[str, Any]) -> dict[str, Any]:
    identity, capsule = fixture["identity"], fixture["manifest"]["recovery_capsule"]
    return {
        "schema": BACKUP_SCHEMA, "synthetic_only": True, "project": identity["project"],
        "state_id": identity["state_id"], "mode": "published_backup",
        "manifest_sha256": fixture["manifest_sha256"],
        "backup_identity_sha256": fixture["manifest"]["backup_identity_sha256"],
        "capsule_id": capsule["capsule_id"], "capsule_ciphertext_sha256": capsule["ciphertext_sha256"],
        "capsule_ciphertext_size": capsule["ciphertext_size"],
        "backup_recovery_trust_sha256": identity["recovery_trust_sha256"],
        "backup_recovery_policy_epoch": identity["recovery_policy_epoch"],
        "recipient_sha256": identity["recipient_sha256"], "sealer_sha256": identity["sealer_sha256"],
        "runtime_source": identity["runtime_source"], "hrh_candidate": identity["hrh_candidate"],
        "effective_images": identity["effective_images"], "excluded_volume": "clinical_socket",
        "backed_up_at": "2026-08-01T12:30:00Z", "nonclaims": BACKUP_NONCLAIMS,
    }


def test_published_authority_fixture_is_independently_self_consistent() -> None:
    fixture = _published_fixture()
    for trust in (fixture["backup_trust"], fixture["restore_trust"]):
        hashes = [item["recipient_sha256"] for item in trust["recipients"]]
        assert hashes == sorted(hashes)
        for recipient in trust["recipients"]:
            assert recipient["recipient_sha256"] == hashlib.sha256(
                (recipient["recipient"] + "\n").encode("ascii")
            ).hexdigest()
    assert fixture["identity"]["recovery_trust_sha256"] == hashlib.sha256(
        fixture["backup_trust_bytes"]
    ).hexdigest()
    assert fixture["manifest"]["backup_identity_sha256"] == hashlib.sha256(
        fixture["identity_bytes"]
    ).hexdigest()
    assert fixture["manifest_sha256"] == hashlib.sha256(fixture["manifest_bytes"]).hexdigest()
    with tarfile.open(fileobj=BytesIO(fixture["public_evidence_bytes"]), mode="r:") as archive:
        verifier = _load(VERIFIER_PATH, "receipt_fixture_inventory_verifier")
        members = archive.getmembers()
        expected = [
            *verifier.EVIDENCE_FILES, "SHA256SUMS.json", "trust.json", "verification.json"
        ]
        assert [member.name for member in members] == expected
        assert len({member.name for member in members}) == len(members)
        assert all(member.isfile() for member in members)


def test_source_v1_causal_receipt_remains_exact_under_frozen_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R01: the new published contract cannot silently rewrite source-v1."""
    staging_module = _load(STAGING_PATH, "clinical_staging_receipt_source_control")
    project = "clinicalstagingdemo"
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    (state / "evidence" / "recovery").mkdir(parents=True)
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
    monkeypatch.setattr(staging_module, "validate_backup_path", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging_module, "datetime", FrozenDateTime)
    checks = {key: True for key in CAUSAL_CHECKS}
    receipt = staging.finalize_cold_recovery_verification(manifest_sha256, checks)
    expected_bytes = _canonical({
        "schema": "restricted-synthetic-clinical-cold-backup.v1",
        "synthetic_only": True,
        "project": project,
        "state_id": "8" * 32,
        "manifest_sha256": manifest_sha256,
        "verification": "causal_e2e_verified",
        "causal_checks": {key: True for key in CAUSAL_CHECKS},
        "verified_at": fixed.isoformat(),
        "nonclaims": ["not PHI", "not production", "not a compliance certification"],
    })
    assert _canonical(receipt) == expected_bytes
    assert (state / "evidence" / "recovery" / f"verified-restore-{manifest_sha256}.json").read_bytes() == _persisted(json.loads(expected_bytes))


def test_source_v1_backup_receipt_remains_exact_with_normalized_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_receipt_backup_control")
    project = "clinicalstagingdemo"
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    (state / "seed").mkdir()
    (state / "evidence").mkdir()
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
    runtime.mkdir()
    hrh.mkdir()
    backup.mkdir()
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
    expected_bytes = _canonical({
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
    assert _canonical(receipt) == expected_bytes
    assert (state / "evidence" / "recovery" / f"restore-{manifest_sha256}.json").read_bytes() == _persisted(json.loads(expected_bytes))


def test_reachable_published_backup_consumes_receipt_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_published_backup_flow_red")
    fixture = _published_fixture()
    project = fixture["identity"]["project"]
    runtime = tmp_path / "runtime"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    state.mkdir()
    (state / "seed").mkdir()
    (state / "evidence").mkdir()
    (state / "compose.env").write_text("CLINICAL_SYNTHETIC=true\n", encoding="utf-8")
    marker = dict(fixture["current_marker"], state_dir=str(state.resolve()), lifecycle="stopped")
    calls = []

    def builder(*args, **kwargs):
        calls.append((args, kwargs))
        return _expected_published_backup(fixture)

    monkeypatch.setattr(staging_module, "_codec_build_backup_receipt", builder, raising=False)
    staging = staging_module.ClinicalStaging(
        runtime, None, state, project, 18443,
        mode_plan=staging_module.hrh_mode.HRHModePlan("backup", "published"),
    )
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging_module, "validate_backup_path", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: None)
    monkeypatch.setattr(staging, "compose", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(staging, "_assert_unmounted_backup_volumes", lambda _volumes: None)
    monkeypatch.setattr(staging_module, "create_state_archive", lambda _state, path: path.write_bytes(b"state"))
    monkeypatch.setattr(staging, "_backup_volume", lambda key, _name, target: (target / "volumes" / f"{key}.tar").write_bytes(b"volume"))
    monkeypatch.setattr(staging_module, "fsync_directory", lambda _path: None)
    monkeypatch.setattr(staging_module, "build_backup_manifest", lambda *_args: fixture["manifest"])
    monkeypatch.setattr(
        staging_module.hrh_mode, "_verifier",
        lambda _runtime: type("Verifier", (), {"EVIDENCE_FILES": ()}),
    )
    def finish(*_args, receipt_builder, **_kwargs):
        return receipt_builder()

    monkeypatch.setattr(staging_module.recovery_codec, "finish_published_backup", finish)
    backup = tmp_path / "published-backup"
    receipt = staging.backup(
        backup, recovery_trust=tmp_path / "trust.json",
        recovery_sealer=tmp_path / "age", recovery_capsule=tmp_path / "capsule.age",
    )
    assert len(calls) == 1, "U4R RED: reachable published backup bypassed its receipt builder"
    assert receipt == _expected_published_backup(fixture)


def _published_backup_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module_name: str,
):
    staging_module = _load(STAGING_PATH, module_name)
    fixture = _published_fixture()
    project = fixture["identity"]["project"]
    runtime = tmp_path / "runtime"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    state.mkdir()
    marker = dict(
        fixture["current_marker"],
        state_dir=str(state.resolve()),
        lifecycle="stopped",
    )
    effects: list[str] = []
    staging = staging_module.ClinicalStaging(
        runtime, None, state, project, 18443,
        mode_plan=staging_module.hrh_mode.HRHModePlan("backup", "published"),
    )
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: None)
    monkeypatch.setattr(
        staging_module.hrh_mode,
        "_verifier",
        lambda _runtime: type("Verifier", (), {"EVIDENCE_FILES": ()}),
    )
    monkeypatch.setattr(
        staging_module,
        "create_state_archive",
        lambda _state, path: (effects.append("archive"), path.write_bytes(b"state")),
    )
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *_args, **_kwargs: effects.append("docker"),
    )
    monkeypatch.setattr(staging, "_assert_unmounted_backup_volumes", lambda _volumes: None)
    monkeypatch.setattr(
        staging,
        "_backup_volume",
        lambda key, _name, target: (
            effects.append(f"volume:{key}"),
            (target / "volumes" / f"{key}.tar").write_bytes(b"volume"),
        ),
    )
    trust = tmp_path / "invalid-recovery-trust.json"
    trust.write_bytes(b"{}\n")
    return staging_module, staging, trust, effects


def test_published_backup_validates_trust_before_archive_or_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module, staging, trust, effects = _published_backup_boundary(
        tmp_path, monkeypatch, "clinical_staging_backup_preflight_red",
    )
    with pytest.raises((staging_module.SafetyError, staging_module.recovery_codec.CapsuleError)):
        staging.backup(
            tmp_path / "public-backup",
            recovery_trust=trust,
            recovery_sealer=tmp_path / "age",
            recovery_capsule=tmp_path / "capsule.age",
        )
    assert effects == []


def test_next_published_backup_reconciles_an_owned_stale_private_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module, staging, trust, _effects = _published_backup_boundary(
        tmp_path, monkeypatch, "clinical_staging_backup_reconcile_red",
    )
    run_id = "4" * 32
    stale = tmp_path / f".capsule-run-{run_id}"
    stale.mkdir(mode=0o700)
    owner = staging_module.recovery_codec._owner(
        stale, project=staging.project, run_id=run_id, mode="backup",
    )
    (stale / ".clinical-recovery-owner.json").write_bytes(_canonical(owner))
    (stale / "plaintext.tar").write_bytes(b"synthetic-private")
    os.utime(stale, (1, 1))
    monkeypatch.setattr(
        staging_module.recovery_codec,
        "finish_published_backup",
        lambda *_args, **_kwargs: {"synthetic_only": True},
    )

    staging.backup(
        tmp_path / "public-backup",
        recovery_trust=trust,
        recovery_sealer=tmp_path / "age",
        recovery_capsule=tmp_path / "capsule.age",
    )
    assert not stale.exists()


def test_reachable_published_restore_consumes_builder_and_persists_exact_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_published_restore_flow_red")
    fixture = _published_fixture()
    project = fixture["identity"]["project"]
    runtime, state, backup, snapshot = (
        tmp_path / "runtime", tmp_path / f"{project}.synthetic-clinical-staging",
        tmp_path / "backup", tmp_path / "snapshot",
    )
    runtime.mkdir()
    backup.mkdir()
    marker = dict(fixture["current_marker"], state_dir=str(state.resolve()), lifecycle="stopped")
    compose_bytes = b"CLINICAL_SYNTHETIC=true\n"
    marker["compose_env_sha256"] = hashlib.sha256(compose_bytes).hexdigest()
    legacy_manifest_adapter = dict(
        fixture["manifest"], source=fixture["identity"]["runtime_source"],
        compose_env_sha256=marker["compose_env_sha256"],
    )
    calls = []

    def builder(*args, **kwargs):
        calls.append((args, kwargs))
        return _published_mechanical(fixture)

    def make_snapshot(*_args, **_kwargs):
        snapshot.mkdir()
        (snapshot / staging_module.BACKUP_MANIFEST_NAME).write_text("{}\n")
        return snapshot

    def extract(_archive, target):
        (target / "compose.env").write_bytes(compose_bytes)
        staging_module.write_json_atomic(target / staging_module.MARKER_NAME, marker, mode=0o600)

    monkeypatch.setattr(staging_module, "_codec_build_restore_receipt", builder, raising=False)
    staging = staging_module.ClinicalStaging(
        runtime, None, state, project, 18443,
        mode_plan=staging_module.hrh_mode.HRHModePlan("restore", "published"),
    )
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging_module, "validate_backup_path", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_module, "materialize_backup_snapshot", make_snapshot)
    monkeypatch.setattr(staging_module, "validate_backup_bundle", lambda *_args: legacy_manifest_adapter)
    monkeypatch.setattr(staging_module, "verify_source_frame", lambda *_args: fixture["identity"]["runtime_source"])
    monkeypatch.setattr(staging, "_require_empty_restore_destination", lambda: None)
    monkeypatch.setattr(staging, "_extract_safe_state_archive", extract)
    monkeypatch.setattr(staging, "_create_volumes", lambda _marker: None)
    monkeypatch.setattr(staging, "_restore_volume", lambda *_args: None)
    monkeypatch.setattr(staging, "_start_restored_stack", lambda: None)
    monkeypatch.setattr(staging, "status", lambda **_kwargs: {"observed_at": "2026-08-01T12:29:00Z"})
    monkeypatch.setattr(staging_module, "fsync_directory", lambda _path: None)
    prepared = {"synthetic": True}
    monkeypatch.setattr(staging_module.recovery_codec, "prepare_published_restore", lambda *_args, **_kwargs: prepared)
    monkeypatch.setattr(
        staging_module.hrh_mode, "acquire_published_candidate",
        lambda *_args, **_kwargs: type("Acquisition", (), {"candidate": fixture["identity"]["hrh_candidate"]})(),
    )

    def restore(*_args, receipt_builder, **_kwargs):
        receipt = receipt_builder()
        receipt_dir = state / "evidence" / "recovery"
        receipt_dir.mkdir(parents=True)
        (receipt_dir / f"restore-{fixture['manifest_sha256']}.json").write_bytes(_canonical(receipt))
        return receipt

    monkeypatch.setattr(staging_module.recovery_codec, "restore_published_backup", restore)
    receipt = staging.restore(
        backup, fixture["manifest_sha256"], recovery_trust=tmp_path / "trust.json",
        recovery_sealer=tmp_path / "age", recovery_capsule=tmp_path / "capsule.age",
        recovery_identity_reader=lambda: b"synthetic\n",
    )
    assert len(calls) == 1, "U4R RED: reachable published restore bypassed its receipt builder"
    expected_bytes = _canonical(_published_mechanical(fixture))
    assert receipt == json.loads(expected_bytes)
    assert (state / "evidence" / "recovery" / f"restore-{fixture['manifest_sha256']}.json").read_bytes() == expected_bytes


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
    assert receipt["capsule_ciphertext_size"] == len(fixture["capsule_bytes"])
    assert receipt["sealer_sha256"] == fixture["identity"]["sealer_sha256"]
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
    assert receipt["backup_recovery_trust_sha256"] == fixture["identity"]["recovery_trust_sha256"]
    assert receipt["backup_recovery_policy_epoch"] == 7
    assert receipt["restore_recovery_trust_sha256"] == fixture["restore_trust_sha256"]
    assert receipt["restore_recovery_policy_epoch"] == 8
    assert receipt["restore_recipient_status"] == "retired"
    assert receipt["verification"] == "mechanical_restore_only"
    assert receipt["nonclaims"] == MECHANICAL_NONCLAIMS


def test_published_causal_receipt_hashes_exact_mechanical_bytes() -> None:
    codec = _load(CODEC_PATH, "clinical_backup_bundle_receipt_causal_red")
    fixture = _published_fixture()
    mechanical = _published_mechanical(fixture)
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


def _exercise_published_finalizer(
    staging_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    fixture: Mapping[str, Any], mechanical_bytes: bytes,
    marker_overrides: Mapping[str, Any] | None = None,
    *,
    expected_mechanical_receipt_sha256: str | None = None,
    public_member_overrides: Mapping[str, bytes] | None = None,
) -> tuple[dict[str, Any], list[tuple[tuple[Any, ...], dict[str, Any]]], Path]:
    project = fixture["identity"]["project"]
    runtime = tmp_path / "runtime"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    (state / "evidence" / "recovery").mkdir(parents=True)
    marker = dict(fixture["current_marker"], state_dir=str(state.resolve()))
    marker.update(marker_overrides or {})
    staging_module.write_json_atomic(state / staging_module.MARKER_NAME, marker, mode=0o600)
    public = tmp_path / "public-backup"
    public.mkdir()
    public_members = {
        "backup-identity.json": fixture["identity_bytes"],
        "backup-manifest.json": fixture["manifest_bytes"],
        "public-evidence.tar": fixture["public_evidence_bytes"],
        "recovery-trust.json": fixture["backup_trust_bytes"],
        "COMPLETE": b"complete\n",
    }
    public_members.update(public_member_overrides or {})
    for name, payload in public_members.items():
        (public / name).write_bytes(payload)
    mechanical_path = state / "evidence" / "recovery" / f"restore-{fixture['manifest_sha256']}.json"
    mechanical_path.write_bytes(mechanical_bytes)
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    expected = _expected_published_causal(fixture, mechanical_bytes)

    def builder(*args, **kwargs):
        calls.append((args, kwargs))
        return expected

    monkeypatch.setattr(staging_module, "_codec_build_causal_receipt", builder, raising=False)
    staging = staging_module.ClinicalStaging(
        runtime, None, state, project, 18443,
        mode_plan=staging_module.hrh_mode.HRHModePlan("finalize-cold-recovery-verification", "published"),
    )
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    fixed = datetime(2026, 8, 1, 12, 31, tzinfo=UTC)

    class FrozenDateTime:
        @classmethod
        def now(cls, _tz):
            return fixed

    monkeypatch.setattr(staging_module, "datetime", FrozenDateTime)
    receipt = staging.finalize_cold_recovery_verification(
        fixture["manifest_sha256"], {name: True for name in CAUSAL_CHECKS},
        backup_dir=public,
        expected_mechanical_receipt_sha256=(
            expected_mechanical_receipt_sha256
            or hashlib.sha256(_canonical(_published_mechanical(fixture))).hexdigest()
        ),
    )
    return receipt, calls, state / "evidence" / "recovery" / f"verified-restore-{fixture['manifest_sha256']}.json"


def test_published_finalizer_consumes_bound_builder_and_persists_exact_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_published_causal_flow_red")
    fixture = _published_fixture()
    mechanical_bytes = _canonical(_published_mechanical(fixture))
    receipt, calls, artifact = _exercise_published_finalizer(
        staging_module, tmp_path, monkeypatch, fixture, mechanical_bytes
    )
    assert len(calls) == 1, "U4R RED: the reachable finalizer bypassed the published receipt builder"
    args, kwargs = calls[0]
    assert len(args) == 1  # the existing BackupContract dependency
    assert kwargs["manifest"] == fixture["manifest"]
    assert kwargs["identity"] == fixture["identity"]
    assert kwargs["current_marker"]["state_id"] == fixture["current_marker"]["state_id"]
    assert kwargs["mechanical_receipt_bytes"] == mechanical_bytes
    assert kwargs["expected_manifest_sha256"] == fixture["manifest_sha256"]
    assert kwargs["expected_mechanical_receipt_sha256"] == hashlib.sha256(mechanical_bytes).hexdigest()
    expected_bytes = _canonical(_expected_published_causal(fixture, mechanical_bytes))
    assert receipt == json.loads(expected_bytes)
    assert artifact.read_bytes() == _persisted(json.loads(expected_bytes))


def test_published_finalizer_rejects_invalid_complete_before_causal_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_missing_complete_red")
    fixture = _published_fixture()
    mechanical_bytes = _canonical(_published_mechanical(fixture))
    with pytest.raises(staging_module.SafetyError):
        _exercise_published_finalizer(
            staging_module,
            tmp_path,
            monkeypatch,
            fixture,
            mechanical_bytes,
            public_member_overrides={"COMPLETE": b"incomplete\n"},
        )


@pytest.mark.parametrize(
    ("target", "field", "replacement"),
    (
        ("mechanical", "manifest_sha256", "0" * 64),
        ("mechanical", "backup_identity_sha256", "0" * 64),
        ("mechanical", "capsule_id", "0" * 32),
        ("mechanical", "capsule_ciphertext_sha256", "0" * 64),
        ("mechanical", "backup_recovery_trust_sha256", "0" * 64),
        ("mechanical", "backup_recovery_policy_epoch", 9),
        ("mechanical", "restore_recovery_trust_sha256", "x" * 64),
        ("mechanical", "restore_recovery_policy_epoch", True),
        ("mechanical", "restore_recipient_status", "revoked"),
        ("mechanical", "recipient_sha256", "0" * 64),
        ("mechanical", "excluded_volume", "other"),
        ("mechanical", "synthetic_only", False),
        ("mechanical", "verification", "causal_e2e_verified"),
        ("mechanical", "nonclaims", ["not production"]),
        ("mechanical", "status_observed_at", "2026-08-01T12:29:00+00:00"),
        ("mechanical", "restored_at", "not-a-timestamp"),
        ("marker", "project", "clinicalstagingother"),
        ("marker", "state_id", "0" * 32),
        ("marker", "runtime_head", "0" * 40),
        ("marker", "hrh_candidate", {}), ("marker", "effective_images", {}),
    ),
)
def test_published_finalizer_rejects_each_substituted_binding_without_artifact(
    target: str, field: str, replacement: Any,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, f"clinical_staging_substitution_{field}")
    fixture = _published_fixture()
    mechanical = _published_mechanical(fixture)
    marker_overrides = None
    if target == "mechanical":
        mechanical[field] = replacement
    else:
        marker_overrides = {field: replacement}
    artifact = tmp_path / f"{fixture['identity']['project']}.synthetic-clinical-staging" / "evidence" / "recovery" / f"verified-restore-{fixture['manifest_sha256']}.json"
    with pytest.raises(staging_module.SafetyError):
        raw = _canonical(mechanical)
        _exercise_published_finalizer(
            staging_module, tmp_path, monkeypatch, fixture, raw,
            marker_overrides=marker_overrides,
            expected_mechanical_receipt_sha256=hashlib.sha256(raw).hexdigest(),
        )
    assert not artifact.exists()


def test_published_finalizer_rejects_duplicate_mechanical_bytes_without_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_duplicate_mechanical_flow")
    fixture = _published_fixture()
    raw = _canonical(_published_mechanical(fixture)).replace(
        b'"schema":"' + MECHANICAL_SCHEMA.encode() + b'"',
        b'"schema":"' + MECHANICAL_SCHEMA.encode() + b'","schema":"' + MECHANICAL_SCHEMA.encode() + b'"',
    )
    artifact = tmp_path / f"{fixture['identity']['project']}.synthetic-clinical-staging" / "evidence" / "recovery" / f"verified-restore-{fixture['manifest_sha256']}.json"
    with pytest.raises(staging_module.SafetyError):
        _exercise_published_finalizer(
            staging_module, tmp_path, monkeypatch, fixture, raw,
            expected_mechanical_receipt_sha256=hashlib.sha256(raw).hexdigest(),
        )
    assert not artifact.exists()


def test_published_finalizer_rejects_pristine_mechanical_hash_mismatch_without_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_mechanical_anchor_mismatch")
    fixture = _published_fixture()
    raw = _canonical(_published_mechanical(fixture))
    artifact = tmp_path / f"{fixture['identity']['project']}.synthetic-clinical-staging" / "evidence" / "recovery" / f"verified-restore-{fixture['manifest_sha256']}.json"
    with pytest.raises(staging_module.SafetyError):
        _exercise_published_finalizer(
            staging_module, tmp_path, monkeypatch, fixture, raw,
            expected_mechanical_receipt_sha256="0" * 64,
        )
    assert not artifact.exists()


def test_published_finalizer_rejects_substituted_public_bundle_against_external_manifest_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_module = _load(STAGING_PATH, "clinical_staging_public_bundle_substitution")
    fixture = _published_fixture()
    raw = _canonical(_published_mechanical(fixture))
    substituted = dict(fixture["manifest"], synthetic_only=False)
    artifact = tmp_path / f"{fixture['identity']['project']}.synthetic-clinical-staging" / "evidence" / "recovery" / f"verified-restore-{fixture['manifest_sha256']}.json"
    with pytest.raises(staging_module.SafetyError):
        _exercise_published_finalizer(
            staging_module, tmp_path, monkeypatch, fixture, raw,
            expected_mechanical_receipt_sha256=hashlib.sha256(raw).hexdigest(),
            public_member_overrides={"backup-manifest.json": _canonical(substituted)},
        )
    assert not artifact.exists()


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
    mechanical = _published_mechanical(fixture)
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
