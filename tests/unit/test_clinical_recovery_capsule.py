"""U4R capsule RED contract for the frozen published-recovery v2 design.

Pinned base: d6a572f96b79e8f6383ffe9bef94da17c5ff841a
Contract: docs/design/durable-published-hrh-recovery-capsule.v2.md

This file deliberately contains no production stub.  Every RED row calls the
future ``clinical_recovery_capsule`` module through ``_api``.  While that
module is absent, each row reports ``PREREQUISITE RED``.  Once it exists, the
same row must prove its own observable predicate rather than treating import
success as implementation success.

This unit owns executable RED predicates B02-B03, B05-B07, B09, B11,
B16-B18, B20-B21 and B27-B28.  B04, B08, B10, B12-B15, B26 and B29 are
PARTIAL: B12 still needs the real SIGKILL publication witness, B13 does not
prove the integrated caller authenticated the public manifest first, B14 does
not exercise a stalled stdin acquisition deadline, and B29 is POSIX-only.
B19 and B22-B25 are NOT_VERIFIED because they require integrated acquisition,
cross-path restore, receipts and service lifecycle effects.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING_DIR = ROOT / "deploy" / "clinical-staging"
CAPSULE_PATH = STAGING_DIR / "clinical_recovery_capsule.py"
STAGING_PATH = STAGING_DIR / "clinical_staging.py"
CODEC_PATH = STAGING_DIR / "clinical_backup_bundle.py"
VERIFIER_PATH = ROOT / "tools" / "verify_hrh_published_candidate.py"

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)
PROJECT = "clinicalstagingcapsule"
STATE_ID = "1" * 32
CAPSULE_ID = "2" * 32
SHA = "a" * 64
PUBLIC_SCHEMA = "restricted-synthetic-clinical-cold-backup-published.v2"
IDENTITY_SCHEMA = "restricted-synthetic-clinical-backup-identity-published.v1"
CAPSULE_SCHEMA = "restricted-synthetic-clinical-recovery-capsule.v1"
TRUST_SCHEMA = "restricted-synthetic-clinical-recovery-trust.v1"
PUBLISHED_V1 = "restricted-synthetic-clinical-cold-backup-published.v1"
SOURCE_V1 = "restricted-synthetic-clinical-cold-backup.v1"
PUBLIC_NAMES = {
    "COMPLETE",
    "backup-identity.json",
    "backup-manifest.json",
    "public-evidence.tar",
    "recovery-trust.json",
}
VOLUME_KEYS = (
    "mattermost_db",
    "mattermost_data",
    "mattermost_tls",
    "hrh_db",
    "hrh_tls",
    "hrh_secret",
    "clinical_config",
    "ingress_config",
    "ingress_outbox",
    "controller_state",
)
PRIVATE_NAMES = {
    "capsule-manifest.json",
    "state.tar",
    *(f"volumes/{name}.tar" for name in VOLUME_KEYS),
}
PUBLIC_SECRET = b"SYNTHETIC-CREDENTIAL-MUST-NOT-BE-PUBLIC"
PRIVATE_PATH = b"/synthetic/private/identity/path"
EXECUTABLE_RED_ROWS = {
    "B02", "B03", "B05", "B06", "B07", "B09", "B11", "B16", "B17",
    "B18", "B20", "B21", "B27", "B28",
}
PARTIAL_ROWS = {"B04", "B08", "B10", "B12", "B13", "B14", "B15", "B26", "B29"}
NOT_VERIFIED_ROWS = {"B19", "B22", "B23", "B24", "B25"}
assert EXECUTABLE_RED_ROWS | PARTIAL_ROWS | NOT_VERIFIED_ROWS == {
    f"B{index:02}" for index in range(2, 30)
}
assert not (
    EXECUTABLE_RED_ROWS & PARTIAL_ROWS
    or EXECUTABLE_RED_ROWS & NOT_VERIFIED_ROWS
    or PARTIAL_ROWS & NOT_VERIFIED_ROWS
)


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _api(row: str) -> ModuleType:
    if not CAPSULE_PATH.is_file():
        pytest.fail(
            f"PREREQUISITE RED [{row}]: clinical_recovery_capsule.py is absent",
            pytrace=False,
        )
    module = _load(CAPSULE_PATH, f"clinical_recovery_capsule_{row.lower()}")
    return module


def _fn(module: ModuleType, row: str, name: str):
    value = getattr(module, name, None)
    if not callable(value):
        pytest.fail(f"PREREQUISITE RED [{row}]: missing API {name}", pytrace=False)
    return value


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _member(data: bytes) -> dict[str, Any]:
    ownership = _canonical({"uid": 0, "gid": 0, "mode": 0o600})
    return {"sha256": _digest(data), "size": len(data), "ownership_sha256": _digest(ownership)}


@contextmanager
def _age_material() -> Iterator[dict[str, Any]]:
    age = shutil.which("age")
    keygen = shutil.which("age-keygen")
    if not age or not keygen:
        pytest.skip("real age boundary is NOT_VERIFIED because age is unavailable")
    with tempfile.TemporaryDirectory(prefix="clinical-age-red-") as raw:
        root = Path(raw)
        identity = root / "identity.txt"
        wrong_identity = root / "wrong-identity.txt"
        subprocess.run([keygen, "-o", str(identity)], check=True, capture_output=True)
        subprocess.run(
            [keygen, "-o", str(wrong_identity)], check=True, capture_output=True
        )
        recipient = subprocess.run(
            [keygen, "-y", str(identity)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        yield {
            "root": root,
            "age": Path(age),
            "recipient": recipient,
            "identity": identity.read_bytes(),
            "wrong_identity": wrong_identity.read_bytes(),
        }
    assert not root.exists(), "synthetic age identities survived the test boundary"


@pytest.fixture
def age_material():
    with _age_material() as material:
        yield material


@pytest.fixture
def trust(age_material):
    recipient = age_material["recipient"]
    return {
        "schema": TRUST_SCHEMA,
        "policy_epoch": 7,
        "scheme": "age-x25519-v1",
        "sealer_sha256": hashlib.sha256(age_material["age"].read_bytes()).hexdigest(),
        "recipients": [
            {
                "recipient": recipient,
                "recipient_sha256": _digest((recipient + "\n").encode("ascii")),
                "not_before": "2026-09-08T00:00:00Z",
                "not_after": "2027-09-08T00:00:00Z",
                "status": "active",
            }
        ],
    }


@pytest.fixture
def public_identity(trust):
    subjects = {
        "web": "registry.invalid/hrh/web@sha256:" + "b" * 64,
        "migrate": "registry.invalid/hrh/migrate@sha256:" + "c" * 64,
        "evidence": "registry.invalid/hrh/evidence@sha256:" + "d" * 64,
    }
    candidate = {
        "clinical_contract_revision": "b" * 40,
        "build_source_revision": "c" * 40,
        "platform": {"os": "linux", "architecture": "amd64"},
        "publisher_identity": "synthetic@example.invalid",
        "kms_key_version": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "kms_public_key_sha256": "1" * 64,
        "subjects": subjects,
        "trust_sha256": "2" * 64,
        "receipt_sha256": "3" * 64,
        "receipt_signature_sha256": "4" * 64,
        "evidence_manifest_sha256": "5" * 64,
        "verification_sha256": "6" * 64,
    }
    effective = {
        service: {
            "subject": subjects[role],
            "image_id": "sha256:" + digit * 64,
            "repo_digest": subjects[role],
            "platform": {"os": "linux", "architecture": "amd64"},
        }
        for service, role, digit in (
            ("hrh", "web", "7"),
            ("hrh-migrate", "migrate", "8"),
        )
    }
    return {
        "schema": IDENTITY_SCHEMA,
        "project": PROJECT,
        "state_id": STATE_ID,
        "compose_env_sha256": "9" * 64,
        "runtime_source": {"runtime_head": "d" * 40, "runtime_tree": "e" * 40},
        "hrh_candidate": candidate,
        "effective_images": effective,
        "volumes": {
            name: f"{PROJECT}_{name}" for name in (*VOLUME_KEYS, "clinical_socket")
        },
        "excluded_volume": "clinical_socket",
        "capsule_id": CAPSULE_ID,
        "recipient_sha256": trust["recipients"][0]["recipient_sha256"],
        "recovery_policy_epoch": trust["policy_epoch"],
        "recovery_trust_sha256": _digest(_canonical(trust)),
        "sealer_sha256": trust["sealer_sha256"],
    }


def _tar_bytes(files: dict[str, bytes], order: tuple[str, ...] | None = None) -> bytes:
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name in order if order is not None else sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.uid = 0
            info.gid = 0
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, BytesIO(data))
    return stream.getvalue()


def _capsule_plaintext(public_identity: dict[str, Any]) -> bytes:
    private = {
        "state.tar": _tar_bytes(
            {"synthetic-state": b"private-state:" + PUBLIC_SECRET + b":" + PRIVATE_PATH}
        )
    }
    private.update(
        {
            f"volumes/{name}.tar": _tar_bytes(
                {"synthetic-volume": f"private-volume:{name}".encode()}
            )
            for name in VOLUME_KEYS
        }
    )
    manifest = {
        "schema": CAPSULE_SCHEMA,
        "capsule_id": CAPSULE_ID,
        "backup_identity_sha256": _digest(_canonical(public_identity)),
        "project": PROJECT,
        "state_id": STATE_ID,
        "compose_env_sha256": public_identity["compose_env_sha256"],
        "members": {name: _member(data) for name, data in private.items()},
    }
    return _tar_bytes({"capsule-manifest.json": _canonical(manifest), **private})


def _tar_members(payload: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=BytesIO(payload), mode="r:") as archive:
        return {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isreg()
        }


def _mutated_capsule_tar(payload: bytes, mutation: str) -> bytes:
    files = _tar_members(payload)
    if mutation == "extra":
        files["extra"] = b"forbidden"
        return _tar_bytes(files)
    if mutation == "missing":
        files.pop("state.tar")
        return _tar_bytes(files)
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            archive.addfile(info, BytesIO(data))
        info = tarfile.TarInfo({"traversal": "../escape", "symlink": "link",
                                "special": "device", "duplicate": "state.tar"}[mutation])
        if mutation == "symlink":
            info.type, info.linkname = tarfile.SYMTYPE, "state.tar"
        elif mutation == "special":
            info.type = tarfile.CHRTYPE
        else:
            info.size = 1
        archive.addfile(info, BytesIO(b"x") if info.isreg() else None)
    return stream.getvalue()


def _fixture_recovery_pair(tmp_path: Path, public_identity, trust) -> dict[str, Any]:
    public = tmp_path / "public"
    public.mkdir()
    identity_bytes = _canonical(public_identity)
    trust_bytes = _canonical(trust)
    verifier = _load(VERIFIER_PATH, "clinical_capsule_pair_verifier")
    evidence_order = (
        *verifier.EVIDENCE_FILES,
        "SHA256SUMS.json",
        "trust.json",
        "verification.json",
    )
    evidence_files = {
        name: f"synthetic-public-evidence:{name}\n".encode()
        for name in evidence_order
    }
    evidence_bytes = _tar_bytes(evidence_files, evidence_order)
    capsule_bytes = b"synthetic-age-ciphertext-without-private-fixture-bytes"
    capsule_path = tmp_path / "private.age"
    capsule_path.write_bytes(capsule_bytes)
    (public / "backup-identity.json").write_bytes(identity_bytes)
    (public / "recovery-trust.json").write_bytes(trust_bytes)
    (public / "public-evidence.tar").write_bytes(evidence_bytes)
    identity_member = _member(identity_bytes)
    evidence_member = _member(evidence_bytes)
    trust_member = _member(trust_bytes)
    manifest = {
        "schema": PUBLIC_SCHEMA,
        "synthetic_only": True,
        "complete": True,
        "backup_identity_sha256": _digest(identity_bytes),
        "recovery_trust_sha256": _digest(trust_bytes),
        "public_evidence": dict(evidence_member),
        "recovery_capsule": {
            "capsule_id": CAPSULE_ID,
            "ciphertext_sha256": _digest(capsule_bytes),
            "ciphertext_size": len(capsule_bytes),
        },
        "members": {
            "backup-identity.json": identity_member,
            "public-evidence.tar": evidence_member,
            "recovery-trust.json": trust_member,
        },
    }
    manifest_bytes = _canonical(manifest)
    (public / "backup-manifest.json").write_bytes(manifest_bytes)
    (public / "COMPLETE").write_bytes(b"complete\n")
    return {
        "public_dir": public,
        "capsule_path": capsule_path,
        "capsule_bytes": capsule_bytes,
        "public_identity": public_identity,
        "manifest": manifest,
        "external_manifest_sha256": _digest(manifest_bytes),
    }


def _reseal_fixture_pair(bundle: dict[str, Any], changed_identity) -> dict[str, Any]:
    resealed = copy.deepcopy(bundle)
    public = bundle["public_dir"].parent / "resealed"
    public.mkdir()
    identity_bytes = _canonical(changed_identity)
    for name in ("public-evidence.tar", "recovery-trust.json", "COMPLETE"):
        (public / name).write_bytes((bundle["public_dir"] / name).read_bytes())
    manifest = copy.deepcopy(bundle["manifest"])
    manifest["backup_identity_sha256"] = _digest(identity_bytes)
    manifest["members"]["backup-identity.json"] = _member(identity_bytes)
    manifest_bytes = _canonical(manifest)
    (public / "backup-identity.json").write_bytes(identity_bytes)
    (public / "backup-manifest.json").write_bytes(manifest_bytes)
    resealed.update(
        public_dir=public,
        public_identity=changed_identity,
        manifest=manifest,
        external_manifest_sha256=_digest(manifest_bytes),
    )
    return resealed


def test_source_v1_schema_and_canonical_codec_control_are_green():
    staging = _load(STAGING_PATH, "clinical_staging_capsule_source_control")
    codec = sys.modules["clinical_backup_bundle"]
    assert staging.BACKUP_SCHEMA == SOURCE_V1
    assert codec.canonical_json_bytes(staging._backup_contract(), {"b": 2, "a": 1}) == (
        b'{"a":1,"b":2}\n'
    )


def test_test_owned_capsule_mutants_and_reseal_fixture_are_well_formed(
    public_identity, trust, tmp_path
):
    plaintext = _capsule_plaintext(public_identity)
    assert set(_tar_members(plaintext)) == PRIVATE_NAMES
    assert "extra" in _tar_members(_mutated_capsule_tar(plaintext, "extra"))
    assert "state.tar" not in _tar_members(_mutated_capsule_tar(plaintext, "missing"))
    bundle = _fixture_recovery_pair(tmp_path, public_identity, trust)
    changed = copy.deepcopy(public_identity)
    changed["state_id"] = "f" * 32
    resealed = _reseal_fixture_pair(bundle, changed)
    assert resealed["manifest"]["backup_identity_sha256"] == _digest(_canonical(changed))
    assert resealed["external_manifest_sha256"] == _digest(
        (resealed["public_dir"] / "backup-manifest.json").read_bytes()
    )
    assert resealed["external_manifest_sha256"] != bundle["external_manifest_sha256"]
    assert set(bundle["manifest"]) == {
        "schema", "synthetic_only", "complete", "backup_identity_sha256",
        "recovery_trust_sha256", "public_evidence", "recovery_capsule", "members",
    }
    assert set(bundle["manifest"]["members"]) == {
        "backup-identity.json", "public-evidence.tar", "recovery-trust.json",
    }
    manifest = bundle["manifest"]
    public = bundle["public_dir"]
    assert manifest["schema"] == PUBLIC_SCHEMA
    assert manifest["synthetic_only"] is True and manifest["complete"] is True
    assert manifest["public_evidence"] == manifest["members"]["public-evidence.tar"]
    assert manifest["backup_identity_sha256"] == _digest(
        (public / "backup-identity.json").read_bytes()
    )
    assert manifest["recovery_trust_sha256"] == _digest(
        (public / "recovery-trust.json").read_bytes()
    )
    for name, declaration in manifest["members"].items():
        actual = (public / name).read_bytes()
        assert declaration == _member(actual)
    capsule = bundle["capsule_bytes"]
    assert manifest["recovery_capsule"] == {
        "capsule_id": CAPSULE_ID,
        "ciphertext_sha256": _digest(capsule),
        "ciphertext_size": len(capsule),
    }
    assert {path.name for path in public.iterdir()} == PUBLIC_NAMES
    assert (public / "COMPLETE").read_bytes() == b"complete\n"


@pytest.mark.parametrize(
    "flag",
    ["--recovery-trust", "--recovery-sealer", "--recovery-capsule"],
)
def test_source_v1_rejects_every_v2_backup_flag_before_effects(flag, tmp_path):
    staging = _load(
        STAGING_PATH,
        f"clinical_staging_source_flag_{flag[2:].replace('-', '_')}",
    )
    argv = [
        "--state-dir",
        str(tmp_path / "state"),
        "--project",
        PROJECT,
        "--hrh-root",
        str(tmp_path / "hrh"),
        "backup",
        "--backup-dir",
        str(tmp_path / "backup"),
        flag,
        str(tmp_path / "forbidden"),
    ]
    with pytest.raises(SystemExit):
        staging.parse_args(argv)


def test_real_age_x25519_stdin_identity_round_trip_and_diagnostic_divergence(age_material):
    age = str(age_material["age"])
    recipient = age_material["recipient"]
    plaintext = b"SYNTHETIC-NON-PHI age boundary\n"
    encrypted = subprocess.run(
        [age, "--encrypt", "--recipient", recipient],
        input=plaintext,
        check=True,
        capture_output=True,
        env={},
    ).stdout
    with tempfile.TemporaryDirectory(prefix="clinical-age-cipher-") as raw:
        capsule = Path(raw) / "capsule.age"
        capsule.write_bytes(encrypted)
        good = subprocess.run(
            [age, "--decrypt", "--identity", "-", str(capsule)],
            input=age_material["identity"],
            capture_output=True,
            env={},
        )
        wrong = subprocess.run(
            [age, "--decrypt", "--identity", "-", str(capsule)],
            input=age_material["wrong_identity"],
            capture_output=True,
            env={},
        )
    assert good.returncode == 0 and good.stdout == plaintext and not good.stderr
    assert wrong.returncode != 0 and wrong.stderr
    assert plaintext not in wrong.stderr


def test_b02_complete_published_backup_interface_is_parseable(tmp_path):
    staging = _load(STAGING_PATH, "clinical_staging_b02")
    argv = [
        "--state-dir",
        str(tmp_path / "state"),
        "--project",
        PROJECT,
        "backup",
        "--backup-dir",
        str(tmp_path / "public"),
        "--recovery-trust",
        str(tmp_path / "trust.json"),
        "--recovery-sealer",
        str(tmp_path / "age"),
        "--recovery-capsule",
        str(tmp_path / "private.age"),
    ]
    try:
        parsed = staging.parse_args(argv)
    except SystemExit:
        pytest.fail("PREREQUISITE RED [B02]: complete v2 backup CLI is unavailable", pytrace=False)
    assert parsed.command == "backup"
    assert parsed.recovery_trust == tmp_path / "trust.json"
    assert parsed.recovery_sealer == tmp_path / "age"
    assert parsed.recovery_capsule == tmp_path / "private.age"


def test_b02_complete_published_restore_interface_is_parseable(tmp_path):
    staging = _load(STAGING_PATH, "clinical_staging_b02_restore")
    argv = [
        "--state-dir", str(tmp_path / "state"),
        "--project", PROJECT,
        "restore",
        "--backup-dir", str(tmp_path / "public"),
        "--expected-manifest-sha256", "a" * 64,
        "--hrh-mode", "published",
        "--hrh-trust", str(tmp_path / "hrh-trust.json"),
        "--hrh-evidence", str(tmp_path / "hrh-evidence"),
        "--hrh-docker-config", str(tmp_path / "docker-config.json"),
        "--recovery-trust", str(tmp_path / "recovery-trust.json"),
        "--recovery-sealer", str(tmp_path / "age"),
        "--recovery-capsule", str(tmp_path / "private.age"),
        "--recovery-identity-stdin",
    ]
    try:
        parsed = staging.parse_args(argv)
    except SystemExit:
        pytest.fail(
            "PREREQUISITE RED [B02]: complete v2 restore CLI is unavailable",
            pytrace=False,
        )
    assert parsed.command == "restore"
    assert parsed.recovery_identity_stdin is True


def test_b02_published_restore_rejects_missing_identity_declaration(tmp_path):
    staging = _load(STAGING_PATH, "clinical_staging_b02_identity_required")
    argv = [
        "--state-dir", str(tmp_path / "state"),
        "--project", PROJECT,
        "restore",
        "--backup-dir", str(tmp_path / "public"),
        "--expected-manifest-sha256", "a" * 64,
        "--hrh-mode", "published",
        "--hrh-trust", str(tmp_path / "hrh-trust.json"),
        "--hrh-evidence", str(tmp_path / "hrh-evidence"),
        "--hrh-docker-config", str(tmp_path / "docker-config.json"),
        "--recovery-trust", str(tmp_path / "recovery-trust.json"),
        "--recovery-sealer", str(tmp_path / "age"),
        "--recovery-capsule", str(tmp_path / "private.age"),
    ]
    with pytest.raises(SystemExit):
        staging.parse_args(argv)


def test_b29_default_sealer_path_does_not_use_the_legacy_capture_runner(
    tmp_path, monkeypatch
):
    class LegacyCaptureRunnerReached(RuntimeError):
        pass

    def legacy_capture_runner(*_args, **_kwargs):
        raise LegacyCaptureRunnerReached

    monkeypatch.setattr(subprocess, "run", legacy_capture_runner)
    module = _load(CAPSULE_PATH, "clinical_recovery_capsule_default_sealer_red")
    with pytest.raises(module.CapsuleError):
        module.encrypt_private_capsule(
            sealer=tmp_path / "missing-age",
            recipient="age1synthetic",
            plaintext=b"synthetic-private",
            output=tmp_path / "capsule.age",
            timeout_seconds=0.1,
            environment={},
        )


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra"])
def test_b02_backup_options_are_exact_and_duplicate_rejecting(tmp_path, mutation):
    staging = _load(STAGING_PATH, f"clinical_staging_b02_{mutation}")
    options = [
        "--recovery-trust", str(tmp_path / "trust.json"),
        "--recovery-sealer", str(tmp_path / "age"),
        "--recovery-capsule", str(tmp_path / "private.age"),
    ]
    baseline = [
        "--state-dir", str(tmp_path / "state"), "--project", PROJECT,
        "backup", "--backup-dir", str(tmp_path / "public"), *options,
    ]
    try:
        staging.parse_args(baseline)
    except SystemExit:
        pytest.fail(
            "PREREQUISITE RED [B02]: complete v2 CLI must exist before "
            f"the {mutation} negative control can be evaluated",
            pytrace=False,
        )

    if mutation == "missing":
        mutated = baseline[:-2]
    elif mutation == "duplicate":
        mutated = baseline + ["--recovery-trust", str(tmp_path / "other.json")]
    else:
        mutated = baseline + ["--recovery-extra", "forbidden"]
    with pytest.raises(SystemExit):
        staging.parse_args(mutated)


def test_b03_exact_recovery_trust_is_canonical_and_selects_one_active(trust):
    module = _api("B03")
    parsed = _fn(module, "B03", "parse_recovery_trust")(_canonical(trust), now=NOW)
    selected = _fn(module, "B03", "select_backup_recipient")(parsed, now=NOW)
    assert selected["recipient_sha256"] == trust["recipients"][0]["recipient_sha256"]


@pytest.mark.parametrize(
    "mutation",
    ["noncanonical", "duplicate-json", "extra", "boolean-epoch", "two-active", "ssh", "bad-time", "bad-status"],
)
def test_b03_recovery_trust_rejects_each_closed_boundary(trust, mutation):
    module = _api("B03")
    value = copy.deepcopy(trust)
    raw = _canonical(value)
    if mutation == "noncanonical":
        raw = json.dumps(value, indent=2).encode()
    elif mutation == "duplicate-json":
        raw = raw.replace(b'"policy_epoch":7', b'"policy_epoch":7,"policy_epoch":8')
    elif mutation == "extra":
        value["extra"] = True
        raw = _canonical(value)
    elif mutation == "boolean-epoch":
        value["policy_epoch"] = True
        raw = _canonical(value)
    elif mutation == "two-active":
        value["recipients"].append(copy.deepcopy(value["recipients"][0]))
        value["recipients"][1]["recipient_sha256"] = "f" * 64
        raw = _canonical(value)
    elif mutation == "ssh":
        value["recipients"][0]["recipient"] = "ssh-ed25519 AAAA"
        raw = _canonical(value)
    elif mutation == "bad-time":
        value["recipients"][0]["not_after"] = value["recipients"][0]["not_before"]
        raw = _canonical(value)
    elif mutation == "bad-status":
        value["recipients"][0]["status"] = "disabled"
        raw = _canonical(value)
    with pytest.raises(module.CapsuleError):
        _fn(module, "B03", "parse_recovery_trust")(raw, now=NOW)


@pytest.mark.skipif(os.name == "nt", reason="B04 POSIX mode and rename-after-open witness is not representable on Windows")
def test_b04_sealer_is_snapshotted_from_one_open_file_before_path_substitution(
    age_material, trust, tmp_path
):
    module = _api("B04")
    source = tmp_path / "age"
    source.write_bytes(age_material["age"].read_bytes())
    source.chmod(0o700)
    expected = _digest(source.read_bytes())

    def opener(path, flags):
        descriptor = os.open(path, flags)
        path.replace(tmp_path / "operator-path-moved")
        path.write_bytes(b"substituted-after-open")
        return descriptor

    snapshot = _fn(module, "B04", "snapshot_sealer")(
        source, tmp_path / "run", expected, opener=opener
    )
    assert snapshot != source
    assert _digest(snapshot.read_bytes()) == expected
    assert snapshot.stat().st_mode & 0o777 == 0o500


def test_b05_b06_public_bundle_is_exact_and_secret_free(
    trust, public_identity, tmp_path
):
    module = _api("B05")
    verifier = _load(VERIFIER_PATH, "clinical_capsule_hrh_verifier")
    public = tmp_path / "public"
    evidence_names = (
        *verifier.EVIDENCE_FILES,
        "SHA256SUMS.json",
        "trust.json",
        "verification.json",
    )
    _fn(module, "B05", "build_public_bundle")(
        public,
        public_identity=public_identity,
        recovery_trust=_canonical(trust),
        evidence={name: f"public:{name}".encode() for name in evidence_names},
        capsule_sha256="e" * 64,
        capsule_size=4096,
    )
    assert {path.name for path in public.iterdir()} == PUBLIC_NAMES
    with tarfile.open(public / "public-evidence.tar", "r:") as evidence_tar:
        members = evidence_tar.getmembers()
        names = [member.name for member in members]
        assert names == list(evidence_names)
        assert len(names) == len(set(names))
        assert all(member.isreg() for member in members)
    joined = b"".join(path.read_bytes() for path in public.iterdir() if path.is_file())
    assert PUBLIC_SECRET not in joined and PRIVATE_PATH not in joined


def test_b07_b21_capsule_plaintext_exactness_and_inner_binding(public_identity):
    module = _api("B07")
    plaintext = _capsule_plaintext(public_identity)
    result = _fn(module, "B07", "validate_capsule_plaintext")(
        plaintext, public_identity=public_identity
    )
    assert set(result["member_names"]) == PRIVATE_NAMES
    changed = copy.deepcopy(public_identity)
    changed["state_id"] = "f" * 32
    with pytest.raises(module.CapsuleError, match="RECOVERY_GENERATION_MISMATCH"):
        _fn(module, "B21", "validate_capsule_plaintext")(
            plaintext, public_identity=changed
        )


def test_b08_age_boundary_and_public_results_never_expose_private_canaries(
    age_material, trust, tmp_path
):
    module = _api("B08")
    invocations = []

    def runner(argv, **kwargs):
        invocations.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, stdout=b"synthetic-ciphertext", stderr=b"")

    result = _fn(module, "B08", "encrypt_private_capsule")(
        sealer=age_material["age"],
        recipient=age_material["recipient"],
        plaintext=b"private:" + PUBLIC_SECRET + b":" + PRIVATE_PATH,
        output=tmp_path / "capsule.age",
        timeout_seconds=10,
        environment={},
        runner=runner,
    )
    serialized = repr(result).encode() + bytes(result.get("stderr", b""))
    assert PUBLIC_SECRET not in serialized
    assert PRIVATE_PATH not in serialized
    assert len(invocations) == 1
    argv, kwargs = invocations[0]
    assert argv[1:] == ["--encrypt", "--recipient", age_material["recipient"]]
    assert kwargs["env"] == {}
    assert kwargs["input"] == b"private:" + PUBLIC_SECRET + b":" + PRIVATE_PATH


def test_b09_resealed_pair_cannot_replace_external_manifest_authority(
    trust, public_identity, tmp_path
):
    module = _api("B09")
    bundle = _fixture_recovery_pair(tmp_path, public_identity, trust)
    changed = copy.deepcopy(public_identity)
    changed["hrh_candidate"]["receipt_sha256"] = "f" * 64
    resealed = _reseal_fixture_pair(bundle, changed)
    with pytest.raises(module.CapsuleError):
        _fn(module, "B09", "validate_recovery_pair")(
            resealed,
            expected_manifest_sha256=bundle["external_manifest_sha256"],
            fresh_trust=_canonical(trust),
            acquired_generation=changed["hrh_candidate"],
        )


def test_b20_resealed_pair_rejects_only_acquired_generation_mismatch(
    trust, public_identity, tmp_path
):
    module = _api("B20")
    bundle = _fixture_recovery_pair(tmp_path, public_identity, trust)
    changed = copy.deepcopy(public_identity)
    changed["hrh_candidate"]["receipt_sha256"] = "f" * 64
    resealed = _reseal_fixture_pair(bundle, changed)
    with pytest.raises(module.CapsuleError, match="RECOVERY_GENERATION_MISMATCH"):
        _fn(module, "B20", "validate_recovery_pair")(
            resealed,
            expected_manifest_sha256=resealed["external_manifest_sha256"],
            fresh_trust=_canonical(trust),
            acquired_generation=public_identity["hrh_candidate"],
        )


PUBLICATION_STAGES = [
    "CAPSULE_CIPHERTEXT_FSYNCED", "CAPSULE_PUBLISHED",
    "CAPSULE_PARENT_FSYNCED", "PUBLIC_MANIFEST_FSYNCED",
    "PUBLIC_COMPLETE_FSYNCED", "PUBLIC_PUBLISHED", "PUBLIC_PARENT_FSYNCED",
]


@pytest.mark.parametrize("stage", PUBLICATION_STAGES)
def test_b10_b11_publication_failpoints_never_report_or_retain_partial_success(
    age_material, trust, public_identity, tmp_path, stage
):
    module = _api("B10")
    tmp_path.chmod(0o700)
    (tmp_path / "private").mkdir(mode=0o700)
    events = []

    def observe(candidate):
        events.append(candidate)
        if candidate == stage:
            raise RuntimeError("synthetic interruption")

    with pytest.raises(module.CapsuleError):
        _fn(module, "B11", "publish_recovery_pair")(
            public_dir=tmp_path / "public",
            capsule_path=tmp_path / "private" / "capsule.age",
            public_identity=public_identity,
            recovery_trust=_canonical(trust),
            private_plaintext=_capsule_plaintext(public_identity),
            sealer=age_material["age"],
            observer=observe,
        )
    assert events == PUBLICATION_STAGES[: PUBLICATION_STAGES.index(stage) + 1]
    assert not list(tmp_path.rglob("*.partial-*"))
    assert not list(tmp_path.rglob("plaintext.tar"))
    assert not list(tmp_path.rglob(".clinical-recovery-owner.json"))
    assert not list(tmp_path.rglob(".capsule-run-*"))
    public, capsule = tmp_path / "public", tmp_path / "private" / "capsule.age"
    if PUBLICATION_STAGES.index(stage) < PUBLICATION_STAGES.index("PUBLIC_PUBLISHED"):
        assert not public.exists() and not capsule.exists()
    else:
        assert capsule.is_file() and (public / "COMPLETE").is_file()
        assert not list(public.glob("*receipt*"))
    for artifact in tmp_path.rglob("*"):
        if artifact.is_file() and artifact != capsule:
            retained = artifact.read_bytes()
            assert PUBLIC_SECRET not in retained
            assert PRIVATE_PATH not in retained


def test_b12_orphan_is_explicit_and_cleanup_is_bounded(tmp_path):
    module = _api("B12")
    capsule = tmp_path / "requested.age"
    capsule.write_bytes(b"synthetic-encrypted-orphan")
    unrelated = tmp_path / "unrelated.age"
    unrelated.write_bytes(b"do-not-delete")
    run_id = "a" * 32
    owned_stage = tmp_path / f".capsule-run-{run_id}"
    owned_stage.mkdir()
    (owned_stage / "plaintext.tar").write_bytes(PUBLIC_SECRET)
    (owned_stage / ".clinical-recovery-owner.json").write_bytes(_canonical({
        "schema": "restricted-synthetic-clinical-recovery-run.v1",
        "project": PROJECT, "run_id": run_id,
        "root": str(owned_stage.resolve()), "mode": "backup",
    }))
    lookalike = tmp_path / f".capsule-run-{'b' * 32}"
    lookalike.mkdir()
    (lookalike / "plaintext.tar").write_bytes(b"unowned")
    result = _fn(module, "B12", "reconcile_capsule_outputs")(
        capsule_path=capsule,
        public_dir=tmp_path / "public",
        staging_parent=tmp_path,
        project=PROJECT,
        run_id=run_id,
        mode="backup",
    )
    assert result["code"] == "RECOVERY_CAPSULE_ORPHANED"
    assert capsule.exists() and unrelated.exists()
    assert not owned_stage.exists()
    assert lookalike.exists() and (lookalike / "plaintext.tar").read_bytes() == b"unowned"


@pytest.mark.parametrize("mutation", ["extra", "project", "run", "root", "mode"])
def test_b12_cleanup_requires_exact_closed_ownership_binding(tmp_path, mutation):
    module = _api("B12_OWNERSHIP")
    run_id = "a" * 32
    stage = tmp_path / f".capsule-run-{run_id}"
    stage.mkdir()
    marker = {
        "schema": "restricted-synthetic-clinical-recovery-run.v1",
        "project": PROJECT, "run_id": run_id,
        "root": str(stage.resolve()), "mode": "backup",
    }
    if mutation == "extra":
        marker["extra"] = True
    elif mutation == "project":
        marker["project"] = "other"
    elif mutation == "run":
        marker["run_id"] = "b" * 32
    elif mutation == "root":
        marker["root"] = str(tmp_path / "other")
    else:
        marker["mode"] = "restore"
    (stage / ".clinical-recovery-owner.json").write_bytes(_canonical(marker))
    (stage / "plaintext.tar").write_bytes(b"preserve")
    _fn(module, "B12", "reconcile_capsule_outputs")(
        capsule_path=tmp_path / "absent.age", public_dir=tmp_path / "public",
        staging_parent=tmp_path, project=PROJECT, run_id=run_id, mode="backup",
    )
    assert stage.is_dir() and (stage / "plaintext.tar").read_bytes() == b"preserve"


@pytest.mark.skipif(os.name == "nt", reason="B12 marker symlink nofollow control is POSIX-only")
def test_b12_cleanup_does_not_follow_an_ownership_marker_symlink(tmp_path):
    module = _api("B12_NOFOLLOW")
    run_id = "a" * 32
    stage = tmp_path / f".capsule-run-{run_id}"
    stage.mkdir()
    outside = tmp_path / "outside-owner.json"
    outside.write_bytes(_canonical({
        "schema": "restricted-synthetic-clinical-recovery-run.v1",
        "project": PROJECT, "run_id": run_id,
        "root": str(stage.resolve()), "mode": "backup",
    }))
    (stage / ".clinical-recovery-owner.json").symlink_to(outside)
    (stage / "plaintext.tar").write_bytes(b"preserve")
    _fn(module, "B12", "reconcile_capsule_outputs")(
        capsule_path=tmp_path / "absent.age", public_dir=tmp_path / "public",
        staging_parent=tmp_path, project=PROJECT, run_id=run_id, mode="backup",
    )
    assert stage.exists() and outside.exists()


def test_b13_manifest_bounds_are_authenticated_before_variable_copy(tmp_path):
    # PARTIAL: this freezes the bounded snapshot itself.  The integrated
    # restore caller must still prove manifest authentication happens first.
    module = _api("B13")
    source = tmp_path / "capsule.age"
    source.write_bytes(b"x" * 33)
    with pytest.raises(module.CapsuleError, match="RECOVERY_CAPSULE_MISMATCH"):
        _fn(module, "B13", "snapshot_declared_member")(
            source,
            tmp_path / "snapshot",
            declared_size=32,
            declared_sha256=_digest(b"x" * 32),
        )
    assert not (tmp_path / "snapshot").exists()


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"AGE-SECRET-KEY-1INVALID\n",
        b"AGE-SECRET-KEY-1INVALID\nAGE-SECRET-KEY-1SECOND\n",
        b"ssh-ed25519 AAAA\n",
        b"AGE-PLUGIN-EXAMPLE-1ABC\n",
        b"AGE-SECRET-KEY-1INVALID",
        "AGE-SECRET-KEY-1INVÁLID\n".encode(),
    ],
)
def test_b14_identity_input_is_one_bounded_native_record(payload):
    # PARTIAL: stalled acquisition and its deadline require the stdin wrapper.
    module = _api("B14")
    with pytest.raises(module.CapsuleError, match="RECOVERY_CAPSULE_UNAVAILABLE"):
        _fn(module, "B14", "validate_identity_input")(payload)


def test_b14_missing_identity_declaration_has_distinct_required_code():
    module = _api("B14")
    with pytest.raises(module.CapsuleError, match="^RECOVERY_IDENTITY_REQUIRED$"):
        _fn(module, "B14", "validate_identity_input")(None, declared=False)


def test_b15_wrong_identity_and_child_diagnostic_are_collapsed_and_partial_removed(
    age_material, tmp_path
):
    module = _api("B15")
    ciphertext = subprocess.run(
        [str(age_material["age"]), "--encrypt", "--recipient", age_material["recipient"]],
        input=b"private",
        check=True,
        capture_output=True,
        env={},
    ).stdout
    capsule = tmp_path / "capsule.age"
    capsule.write_bytes(ciphertext)
    output = tmp_path / "plaintext.tar"
    with pytest.raises(module.CapsuleError, match="^RECOVERY_CAPSULE_UNAVAILABLE$"):
        _fn(module, "B15", "decrypt_private_capsule")(
            sealer=age_material["age"],
            capsule=capsule,
            identity=age_material["wrong_identity"],
            output=output,
            timeout_seconds=10,
            environment={},
        )
    assert not output.exists()


def test_b15_existing_wrapper_output_prevents_child_start(age_material, tmp_path):
    module = _api("B15")
    output = tmp_path / "already-exists"
    output.write_bytes(b"preserve")
    calls = []
    with pytest.raises(module.CapsuleError, match="RECOVERY_OUTPUT_EXISTS"):
        _fn(module, "B15", "decrypt_private_capsule")(
            sealer=age_material["age"],
            capsule=tmp_path / "capsule.age",
            identity=age_material["identity"],
            output=output,
            timeout_seconds=10,
            environment={},
            runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == [] and output.read_bytes() == b"preserve"


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("not-yet-valid", "RECOVERY_RECIPIENT_NOT_YET_VALID"),
        ("expired", "RECOVERY_RECIPIENT_EXPIRED"),
        ("revoked", "RECOVERY_RECIPIENT_REVOKED"),
        ("removed", "RECOVERY_RECIPIENT_REVOKED"),
        ("epoch-rollback", "RECOVERY_POLICY_ROLLBACK"),
        ("extend-window", "RECOVERY_RECIPIENT_REVOKED"),
        ("retired-to-active", "RECOVERY_RECIPIENT_REVOKED"),
    ],
)
def test_b16_b26_fresh_policy_transition_is_closed_before_identity_read(
    trust, mutation, code
):
    module = _api("B16")
    archived = copy.deepcopy(trust)
    fresh = copy.deepcopy(trust)
    if mutation == "not-yet-valid":
        fresh["recipients"][0]["not_before"] = "2026-10-01T00:00:00Z"
    elif mutation == "expired":
        fresh["recipients"][0]["not_after"] = "2026-09-01T00:00:00Z"
    elif mutation == "revoked":
        fresh["recipients"][0]["status"] = "revoked"
    elif mutation == "removed":
        fresh["recipients"] = []
    elif mutation == "epoch-rollback":
        fresh["policy_epoch"] = archived["policy_epoch"] - 1
    elif mutation == "extend-window":
        fresh["recipients"][0]["not_after"] = "2028-09-08T00:00:00Z"
    elif mutation == "retired-to-active":
        archived["recipients"][0]["status"] = "retired"
    reads = []
    with pytest.raises(module.CapsuleError, match=code):
        _fn(module, "B26", "authorize_restore_trust")(
            _canonical(archived),
            _canonical(fresh),
            recipient_sha256=trust["recipients"][0]["recipient_sha256"],
            now=NOW,
            identity_reader=lambda: reads.append(True),
        )
    assert reads == []


def test_b16_fresh_policy_cannot_replace_the_archived_sealer(trust):
    module = _api("B16")
    archived = copy.deepcopy(trust)
    fresh = copy.deepcopy(trust)
    fresh["policy_epoch"] += 1
    fresh["sealer_sha256"] = "f" * 64
    reads = []
    with pytest.raises(module.CapsuleError, match="RECOVERY_TRUST_MISMATCH"):
        module.authorize_restore_trust(
            _canonical(archived),
            _canonical(fresh),
            recipient_sha256=trust["recipients"][0]["recipient_sha256"],
            now=NOW,
            identity_reader=lambda: reads.append(True),
        )
    assert reads == []


@pytest.mark.parametrize(
    "mutation",
    ["traversal", "symlink", "special", "duplicate", "extra", "missing"],
)
def test_b17_private_tar_rejects_each_member_attack(public_identity, mutation):
    module = _api("B17")
    plaintext = _capsule_plaintext(public_identity)
    mutated = _mutated_capsule_tar(plaintext, mutation)
    with pytest.raises(module.CapsuleError, match="RECOVERY_CAPSULE_INVALID"):
        _fn(module, "B17", "validate_capsule_plaintext")(
            mutated, public_identity=public_identity
        )


def test_b17_nested_volume_tar_is_validated_before_restore(public_identity, tmp_path):
    module = _api("B17")
    private_root = tmp_path / "private"
    (private_root / "volumes").mkdir(parents=True)
    safe_inner = _tar_bytes({"payload": b"synthetic"})
    (private_root / "state.tar").write_bytes(safe_inner)
    for key in VOLUME_KEYS:
        (private_root / "volumes" / f"{key}.tar").write_bytes(safe_inner)

    plaintext = module.build_capsule_plaintext(
        private_root, public_identity=public_identity
    )
    module.validate_capsule_plaintext(plaintext, public_identity=public_identity)

    files = _tar_members(plaintext)
    unsafe = BytesIO()
    with tarfile.open(fileobj=unsafe, mode="w:") as archive:
        payload = b"escape"
        member = tarfile.TarInfo("../escape")
        member.size, member.uid, member.gid, member.mode, member.mtime = (
            len(payload), 0, 0, 0o600, 0
        )
        archive.addfile(member, BytesIO(payload))
    target = f"volumes/{VOLUME_KEYS[0]}.tar"
    files[target] = unsafe.getvalue()
    manifest = json.loads(files["capsule-manifest.json"])
    manifest["members"][target]["sha256"] = _digest(files[target])
    manifest["members"][target]["size"] = len(files[target])
    files["capsule-manifest.json"] = _canonical(manifest)
    mutated = _tar_bytes(files, tuple(module.PRIVATE_NAMES))

    with pytest.raises(module.CapsuleError, match="RECOVERY_CAPSULE_INVALID"):
        module.validate_capsule_plaintext(mutated, public_identity=public_identity)


@pytest.mark.parametrize(
    "document",
    ["recovery-trust", "backup-manifest", "backup-identity", "capsule-manifest", "restored-marker"],
)
def test_b18_duplicate_json_members_are_never_last_wins(document):
    module = _api("B18")
    raw = b'{"schema":"first","schema":"second"}\n'
    with pytest.raises(module.CapsuleError, match="duplicate"):
        _fn(module, "B18", "parse_closed_json")(raw, document=document)


def test_b27_published_v1_is_refused_without_opening_state_tar(tmp_path):
    module = _api("B27")
    backup = tmp_path / "published-v1"
    backup.mkdir()
    (backup / "backup-manifest.json").write_bytes(
        _canonical({"schema": PUBLISHED_V1})
    )
    opened = []
    with pytest.raises(module.CapsuleError, match="PUBLISHED_BACKUP_V1_UNSAFE"):
        _fn(module, "B27", "classify_restore_bundle")(
            backup,
            open_member=lambda name: opened.append(name),
        )
    assert "state.tar" not in opened


@pytest.mark.parametrize("selected,actual", [(SOURCE_V1, PUBLIC_SCHEMA), (PUBLIC_SCHEMA, SOURCE_V1)])
def test_b28_cross_mode_schema_substitution_fails_before_mutation(selected, actual):
    module = _api("B28")
    mutations = []
    with pytest.raises(module.CapsuleError):
        _fn(module, "B28", "require_restore_schema")(
            selected, actual, mutate=lambda: mutations.append(True)
        )
    assert mutations == []


def test_b29_hung_sealer_is_group_terminated_and_all_partials_removed(
    tmp_path, monkeypatch
):
    if os.name != "posix":
        pytest.skip("B29 real process-group proof is NOT_VERIFIED on non-POSIX")
    module = _api("B29")
    child = tmp_path / "hang.py"
    child.write_text(
        "import os,time\n"
        "if os.fork()==0: time.sleep(60)\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    output = tmp_path / "partial"
    with pytest.raises(module.CapsuleError, match="^RECOVERY_SEALER_UNAVAILABLE$"):
        _fn(module, "B29", "run_sealer")(
            executable=Path(sys.executable),
            arguments=(str(child),),
            stdin=b"synthetic",
            output=output,
            timeout_seconds=0.2,
            environment={},
        )
    assert not output.exists()


@pytest.mark.skipif(os.name != "posix", reason="special-file and fd metadata witnesses are POSIX-only")
def test_b13_declared_snapshot_requires_one_stable_regular_file(tmp_path, monkeypatch):
    module = _api("B13_STABLE_FD")
    with pytest.raises(module.CapsuleError, match="^RECOVERY_CAPSULE_MISMATCH$"):
        _fn(module, "B13_STABLE_FD", "snapshot_declared_member")(
            Path("/dev/null"),
            tmp_path / "special-snapshot",
            declared_size=0,
            declared_sha256=_digest(b""),
        )
    source = tmp_path / "source"
    source.write_bytes(b"stable")
    source.chmod(0o600)
    real_open = os.open

    def mutate_after_open(path, flags):
        descriptor = real_open(path, flags)
        source.chmod(0o640)
        return descriptor

    monkeypatch.setattr(module.os, "open", mutate_after_open)
    with pytest.raises(module.CapsuleError, match="^RECOVERY_CAPSULE_MISMATCH$"):
        _fn(module, "B13_STABLE_FD", "snapshot_declared_member")(
            source,
            tmp_path / "changed-snapshot",
            declared_size=6,
            declared_sha256=_digest(b"stable"),
        )


def test_restore_taxonomy_distinguishes_missing_capsule_and_untrusted_sealer(tmp_path):
    module = _api("B15_TAXONOMY")
    with pytest.raises(module.CapsuleError, match="^RECOVERY_CAPSULE_MISSING$"):
        _fn(module, "B15_TAXONOMY", "snapshot_declared_member")(
            tmp_path / "missing.age",
            tmp_path / "snapshot.age",
            declared_size=1,
            declared_sha256=_digest(b"x"),
        )
    sealer = tmp_path / "age"
    sealer.write_bytes(b"substituted")
    sealer.chmod(0o700)
    with pytest.raises(module.CapsuleError, match="^RECOVERY_SEALER_UNTRUSTED$"):
        _fn(module, "B15_TAXONOMY", "snapshot_sealer")(
            sealer, tmp_path / "run", _digest(b"expected")
        )


def test_b12_candidate_scan_stops_at_the_ninth_entry(tmp_path, monkeypatch):
    module = _api("B12_SCAN_BOUND")
    for index in range(10):
        (tmp_path / f".capsule-run-{index:032x}").mkdir()
    entries = tuple(tmp_path.iterdir())
    path_type = type(tmp_path)
    real_iterdir = path_type.iterdir

    def bounded_iterdir(path):
        if path != tmp_path:
            yield from real_iterdir(path)
            return
        for index, entry in enumerate(entries):
            if index == 9:
                raise AssertionError("enumerated beyond the ninth candidate")
            yield entry

    monkeypatch.setattr(path_type, "iterdir", bounded_iterdir)
    with pytest.raises(module.CapsuleError, match="^RECOVERY_STAGING_UNAVAILABLE$"):
        _fn(module, "B12_SCAN_BOUND", "reconcile_owned_staging")(
            tmp_path, project=PROJECT
        )


@pytest.mark.skipif(os.name != "posix", reason="durable owner fd witness uses /proc/self/fd")
def test_b12_owner_markers_are_durable_before_private_sealing(
    trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B12_DURABLE_OWNER")
    public_parent, capsule_parent = tmp_path / "public-parent", tmp_path / "capsule-parent"
    public_parent.mkdir(mode=0o700)
    capsule_parent.mkdir(mode=0o700)
    events = []
    real_fsync = os.fsync

    def observe_fsync(descriptor):
        try:
            events.append(Path(os.readlink(f"/proc/self/fd/{descriptor}")))
        except OSError:
            pass
        real_fsync(descriptor)

    observed = {"durable": False}

    def stop_after_owner_check(**_kwargs):
        markers = [path for path in events if path.name == ".clinical-recovery-owner.json"]
        observed["durable"] = len(markers) == 2 and all(
            marker.parent in events[events.index(marker) + 1 :] for marker in markers
        )
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module.os, "fsync", observe_fsync)
    monkeypatch.setattr(module, "snapshot_sealer", lambda source, *_args, **_kwargs: source)
    monkeypatch.setattr(module, "encrypt_private_capsule", stop_after_owner_check)
    with pytest.raises(module.CapsuleError):
        module.publish_recovery_pair(
            public_dir=public_parent / "bundle",
            capsule_path=capsule_parent / "capsule.age",
            public_identity=public_identity,
            recovery_trust=_canonical(trust),
            private_plaintext=b"synthetic private",
            sealer=tmp_path / "age",
        )
    assert observed["durable"], "private sealing began before both owner markers and parents were fsynced"


def test_b11_manifest_failpoint_precedes_complete_visibility(
    trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B11_EXACT_STAGE")
    public_parent, capsule_parent = tmp_path / "public-parent", tmp_path / "capsule-parent"
    public_parent.mkdir(mode=0o700)
    capsule_parent.mkdir(mode=0o700)
    monkeypatch.setattr(module, "snapshot_sealer", lambda source, *_args, **_kwargs: source)

    def seal(**kwargs):
        kwargs["output"].write_bytes(b"ciphertext")
        return {"sha256": _digest(b"ciphertext"), "size": 10, "stderr": b""}

    monkeypatch.setattr(module, "encrypt_private_capsule", seal)
    observed = []

    def inspect_boundary(stage):
        observed.append(stage)
        if stage == "PUBLIC_MANIFEST_FSYNCED":
            staged = next(public_parent.glob(".capsule-run-*/public"))
            assert (staged / "backup-manifest.json").is_file()
            assert not (staged / "COMPLETE").exists()

    module.publish_recovery_pair(
        public_dir=public_parent / "bundle",
        capsule_path=capsule_parent / "capsule.age",
        public_identity=public_identity,
        recovery_trust=_canonical(trust),
        private_plaintext=b"synthetic private",
        sealer=tmp_path / "age",
        observer=inspect_boundary,
    )
    assert "PUBLIC_COMPLETE_FSYNCED" in observed


def test_default_sealer_hashes_without_rereading_private_output(tmp_path, monkeypatch):
    module = _api("B08_STREAM_HASH")

    def forbid_reread(*_args, **_kwargs):
        raise AssertionError("private sealer output was reread into memory")

    monkeypatch.setattr(module, "read_bounded_regular", forbid_reread)
    output = tmp_path / "sealed"
    result = module.run_sealer(
        executable=Path(sys.executable),
        arguments=("-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"),
        stdin=b"synthetic private",
        output=output,
        timeout_seconds=5,
        environment=dict(os.environ),
    )
    assert output.read_bytes() == b"synthetic private"
    assert result["sha256"] == _digest(b"synthetic private")


def test_restore_zeroes_mutable_identity_after_sealer_failure(
    age_material, tmp_path, monkeypatch
):
    module = _api("B08_ZERO_IDENTITY")
    run = tmp_path / "run"
    run.mkdir()
    candidate = {"synthetic": "candidate"}
    identity = {"hrh_candidate": candidate, "recipient_sha256": "a" * 64}
    captured = []
    prepared = {
        "run": run,
        "fresh_trust": b"fresh\n",
        "capsule": tmp_path / "capsule.age",
        "sealer": tmp_path / "age",
        "result": {"identity": identity, "manifest": {}, "archived_trust": b"archived\n"},
    }
    staging = type("Staging", (), {"state_dir": tmp_path / "state"})()
    monkeypatch.setattr(module, "parse_recovery_trust", lambda *_args, **_kwargs: {})

    def authorize(*_args, identity_reader, **_kwargs):
        identity_reader()
        return {}

    def fail_decrypt(*_args, identity, **_kwargs):
        captured.append(identity)
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "authorize_restore_trust", authorize)
    monkeypatch.setattr(module, "decrypt_private_capsule", fail_decrypt)
    with pytest.raises(module.CapsuleError):
        module.restore_published_backup(
            staging,
            tmp_path / "public",
            "b" * 64,
            recovery_trust_path=tmp_path / "trust",
            recovery_sealer=tmp_path / "age",
            capsule_path=tmp_path / "capsule.age",
            identity_reader=lambda: age_material["identity"].splitlines()[-1] + b"\n",
            acquired_generation=candidate,
            contract=object(),
            receipt_builder=lambda *_args, **_kwargs: {},
            renew_tls=False,
            now=NOW,
            prepared=prepared,
        )
    assert len(captured) == 1 and isinstance(captured[0], bytearray)
    assert captured[0] and not any(captured[0]), "identity buffer was not zeroed on failure"


def test_u5_restore_rebinds_effective_compose_paths_after_relocation(
    age_material, public_identity, tmp_path, monkeypatch
):
    """A published capsule must not retain producer-host bind-mount paths."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    module = _api("U5_RELOCATABLE_COMPOSE_ENV")
    old_runtime = tmp_path / "producer" / "runtime"
    old_state = tmp_path / "producer" / "state"
    new_runtime = tmp_path / "recovery-host" / "runtime"
    new_state = tmp_path / "recovery-host" / "state"
    new_harness = new_runtime / "tests" / "deployment" / "clinical-composed-e2e"
    old_port, new_port = 18443, 28443
    new_state.parent.mkdir(parents=True)
    new_runtime.mkdir(parents=True)
    private_key = Ed25519PrivateKey.generate()
    policy_private = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    policy_public = base64.b64encode(private_key.public_key().public_bytes_raw()).decode(
        "ascii"
    )
    identity = copy.deepcopy(public_identity)
    secret_values = {
        "CLINICAL_MM_DB_PASSWORD": "a" * 48,
        "CLINICAL_HRH_DB_PASSWORD": "b" * 48,
        "CLINICAL_HRH_SESSION_SECRET": "c" * 64,
        "CLINICAL_HRH_ENCRYPTION_KEY": "d" * 64,
    }
    archived_values = {
        **secret_values,
        "CLINICAL_HARNESS": (
            old_runtime / "tests" / "deployment" / "clinical-composed-e2e"
        ).as_posix(),
        "CLINICAL_SEED": (old_state / "seed").as_posix(),
        "CLINICAL_INGRESS_IMAGE": f"restricted-clinical-ingress:{identity['project']}",
        "CLINICAL_ADAPTER_IMAGE": f"restricted-clinical-adapter:{identity['project']}",
        "CLINICAL_POLICY_PUBLIC_KEY": policy_public,
        "CLINICAL_STAGING_PROJECT": identity["project"],
        "CLINICAL_STAGING_STATE_ID": identity["state_id"],
        "CLINICAL_STAGING_PORT": str(old_port),
        "CLINICAL_HRH_WEB_IMAGE": identity["hrh_candidate"]["subjects"]["web"],
        "CLINICAL_HRH_MIGRATE_IMAGE": identity["hrh_candidate"]["subjects"]["migrate"],
        **{
            f"CLINICAL_VOLUME_{key.upper()}": value
            for key, value in identity["volumes"].items()
        },
    }
    old_compose = "".join(
        f"{key}={value}\n" for key, value in archived_values.items()
    ).encode("utf-8")
    archived_compose_sha256 = hashlib.sha256(old_compose).hexdigest()
    identity["compose_env_sha256"] = archived_compose_sha256
    marker = {
        "schema": "restricted-synthetic-clinical-staging-published.v1",
        "synthetic_only": True,
        "project": identity["project"],
        "state_dir": str(old_state),
        "state_id": identity["state_id"],
        "compose_env_sha256": identity["compose_env_sha256"],
        "lifecycle": "stopped",
        "runtime_head": identity["runtime_source"]["runtime_head"],
        "runtime_tree": identity["runtime_source"]["runtime_tree"],
        "volumes": identity["volumes"],
        "hrh_candidate": identity["hrh_candidate"],
        "effective_images": identity["effective_images"],
    }
    run = tmp_path / "prepared-restore"
    run.mkdir()
    prepared = {
        "run": run,
        "fresh_trust": b"fresh-trust",
        "capsule": tmp_path / "capsule.age",
        "sealer": tmp_path / "age",
        "result": {
            "identity": identity,
            "manifest": {},
            "archived_trust": b"archived-trust",
        },
    }

    class Contract:
        @staticmethod
        def write_json_atomic(path, value, *, mode):
            del mode
            path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    class Staging:
        runtime = new_runtime
        state_dir = new_state
        harness = new_harness
        port = new_port
        project = identity["project"]
        observed_start = False
        ready_marker = None

        @staticmethod
        def _require_empty_restore_destination():
            assert not new_state.exists()

        @staticmethod
        def _extract_safe_state_archive(_archive, target):
            target.mkdir(exist_ok=True)
            (target / "compose.env").write_bytes(old_compose)
            (target / "seed").mkdir()
            (target / "seed" / "policy-private.pem").write_bytes(policy_private)
            (target / "staging-state.json").write_text(
                json.dumps(marker, sort_keys=True), encoding="utf-8"
            )

        @staticmethod
        def _create_volumes(_marker):
            return None

        @staticmethod
        def _restore_volume(*_args):
            return None

        @staticmethod
        def _start_restored_stack():
            Staging.observed_start = True
            raw = (new_state / "compose.env").read_bytes()
            values = dict(
                line.split("=", 1)
                for line in raw.decode("utf-8").splitlines()
            )
            assert set(values) == set(archived_values)
            # Keep the first predicate on relocation.  On the frozen base this
            # is the intended RED, rather than an incidental schema rejection.
            assert old_runtime.as_posix() not in raw.decode("utf-8")
            assert old_state.as_posix() not in raw.decode("utf-8")
            assert {
                name: values[name] for name in ("CLINICAL_SEED", "CLINICAL_HARNESS")
            } == {
                "CLINICAL_SEED": (new_state / "seed").as_posix(),
                "CLINICAL_HARNESS": new_harness.as_posix(),
            }
            assert {key: values[key] for key in secret_values} == secret_values
            expected_nonsecret = {
                key: value
                for key, value in archived_values.items()
                if key
                not in {
                    *secret_values,
                    "CLINICAL_HARNESS",
                    "CLINICAL_SEED",
                    "CLINICAL_STAGING_PORT",
                }
            }
            expected_nonsecret["CLINICAL_HARNESS"] = new_harness.as_posix()
            expected_nonsecret["CLINICAL_SEED"] = (new_state / "seed").as_posix()
            expected_nonsecret["CLINICAL_STAGING_PORT"] = str(new_port)
            assert {key: values[key] for key in expected_nonsecret} == expected_nonsecret
            effective_sha256 = hashlib.sha256(raw).hexdigest()
            restored_marker = json.loads(
                (new_state / "staging-state.json").read_text(encoding="utf-8")
            )
            assert restored_marker["compose_env_sha256"] == effective_sha256
            assert effective_sha256 != archived_compose_sha256

        @staticmethod
        def status(*, _allow_recovering):
            assert _allow_recovering is True
            return {"observed_at": "2026-09-08T12:00:01Z"}

        @staticmethod
        def _write_marker(value):
            Staging.ready_marker = copy.deepcopy(value)

        @staticmethod
        def _contain_failed_restore():
            return None

    monkeypatch.setattr(module, "parse_recovery_trust", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        module,
        "authorize_restore_trust",
        lambda *_args, identity_reader, **_kwargs: identity_reader(),
    )
    monkeypatch.setattr(
        module,
        "decrypt_private_capsule",
        lambda **kwargs: kwargs["output"].write_bytes(b"synthetic plaintext"),
    )

    def extract_plaintext(_plaintext, destination, **_kwargs):
        destination.mkdir()
        (destination / "state.tar").write_bytes(b"synthetic state archive")

    monkeypatch.setattr(module, "extract_capsule_plaintext", extract_plaintext)
    receipt_inputs = {}

    def build_receipt(*_args, **kwargs):
        receipt_inputs.update(kwargs)
        return {"schema": "synthetic-u5-restore-receipt.v1"}

    result = module.restore_published_backup(
        Staging(),
        tmp_path / "public",
        "b" * 64,
        recovery_trust_path=tmp_path / "trust",
        recovery_sealer=tmp_path / "age",
        capsule_path=tmp_path / "capsule.age",
        identity_reader=lambda: age_material["identity"].splitlines()[-1] + b"\n",
        acquired_generation=identity["hrh_candidate"],
        contract=Contract(),
        receipt_builder=build_receipt,
        renew_tls=False,
        now=NOW,
        prepared=prepared,
    )
    assert Staging.observed_start is True
    assert Staging.ready_marker["lifecycle"] == "ready"
    effective_sha256 = hashlib.sha256((new_state / "compose.env").read_bytes()).hexdigest()
    assert Staging.ready_marker["compose_env_sha256"] == effective_sha256
    assert receipt_inputs["archived_compose_env_sha256"] == archived_compose_sha256
    assert receipt_inputs["effective_compose_env_sha256"] == effective_sha256
    assert result["schema"] == "synthetic-u5-restore-receipt.v1"
    assert not old_runtime.exists()
    assert not old_state.exists()


@pytest.mark.skipif(os.name != "posix", reason="trusted-parent ownership and mode witness is POSIX-only")
def test_backup_rejects_world_writable_capsule_parent_before_inputs(tmp_path, monkeypatch):
    module = _api("B11_TRUSTED_PARENT")
    paths = {
        name: tmp_path / name
        for name in ("runtime", "state", "private-root", "public-parent", "capsule-parent")
    }
    for path in paths.values():
        path.mkdir()
    paths["capsule-parent"].chmod(0o777)
    staging = type(
        "Staging",
        (),
        {
            "runtime": paths["runtime"],
            "state_dir": paths["state"],
            "hrh": None,
            "project": PROJECT,
        },
    )()
    effects = []

    def reject_if_read(*_args, **_kwargs):
        effects.append("input-read")
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "read_bounded_regular", reject_if_read)
    with pytest.raises(module.CapsuleError):
        module.finish_published_backup(
            staging,
            paths["private-root"],
            {},
            paths["public-parent"] / "bundle",
            recovery_trust_path=tmp_path / "trust.json",
            recovery_sealer=tmp_path / "age",
            capsule_path=paths["capsule-parent"] / "capsule.age",
            contract=object(),
            receipt_builder=lambda *_args, **_kwargs: {},
            now=NOW,
            verifier_evidence_names=(),
        )
    assert effects == [], "untrusted output parent was accepted far enough to read inputs"


def test_restore_rejects_capsule_inside_state_root_before_snapshot(tmp_path, monkeypatch):
    module = _api("B13_RESTORE_DISJOINT")
    state, runtime, public = tmp_path / "state", tmp_path / "runtime", tmp_path / "public"
    state.mkdir()
    runtime.mkdir()
    public.mkdir()
    staging = type(
        "Staging",
        (),
        {"state_dir": state, "runtime": runtime, "hrh": None, "project": PROJECT},
    )()
    effects = []

    def reject_if_read(*_args, **_kwargs):
        effects.append("snapshot-read")
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "read_bounded_regular", reject_if_read)
    with pytest.raises(module.CapsuleError):
        module.prepare_published_restore(
            staging,
            public,
            state / "capsule.age",
            tmp_path / "trust.json",
            tmp_path / "age",
            "a" * 64,
            now=NOW,
        )
    assert effects == [], "overlapping restore paths reached the snapshot boundary"


def test_sealer_stdout_is_the_wrapper_opened_exclusive_file(tmp_path, monkeypatch):
    module = _api("B08_DIRECT_STDOUT")
    real_popen = subprocess.Popen
    observed = {}

    def capture_popen(*args, **kwargs):
        observed["stdout"] = kwargs.get("stdout")
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", capture_popen)
    output = tmp_path / "sealed"
    module.run_sealer(
        executable=Path(sys.executable),
        arguments=("-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"),
        stdin=b"synthetic private",
        output=output,
        timeout_seconds=5,
        environment=dict(os.environ),
    )
    assert observed["stdout"] != subprocess.PIPE
    assert callable(getattr(observed["stdout"], "fileno", None))
    assert output.read_bytes() == b"synthetic private"


@pytest.mark.skipif(os.name != "posix", reason="process-group and monotonic deadline witness is POSIX-only")
def test_sealer_kills_retained_grandchild_within_one_deadline(tmp_path):
    module = _api("B29_RETAINED_STDOUT")
    script, pidfile = tmp_path / "fork.py", tmp_path / "pids"
    script.write_text(
        "import os,sys,time\n"
        "child=os.fork()\n"
        "if child==0:\n"
        "    time.sleep(60)\n"
        "else:\n"
        "    open(sys.argv[1],'w').write(f'{os.getpgrp()} {child}')\n"
        "    os._exit(0)\n",
        encoding="utf-8",
    )
    timeout = 0.3
    started = time.monotonic()
    group = child = None
    alive = False
    try:
        with pytest.raises(module.CapsuleError, match="^RECOVERY_SEALER_UNAVAILABLE$"):
            module.run_sealer(
                executable=Path(sys.executable),
                arguments=(str(script), str(pidfile)),
                stdin=b"x" * (8 * 1024 * 1024),
                output=tmp_path / "sealed",
                timeout_seconds=timeout,
                environment=dict(os.environ),
            )
        elapsed = time.monotonic() - started
        group, child = map(int, pidfile.read_text(encoding="utf-8").split())
        try:
            os.kill(child, 0)
            alive = True
        except ProcessLookupError:
            pass
    finally:
        if alive and group is not None:
            os.killpg(group, signal.SIGKILL)
    assert not alive, "retained sealer process group survived wrapper failure"
    assert elapsed <= timeout + 0.2, "sealer used more than one monotonic timeout budget"


@pytest.mark.skipif(os.name != "posix", reason="exact trusted-parent mode witness is POSIX-only")
def test_publication_requires_exact_capsule_and_public_parent_modes(
    trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B11_EXACT_PARENT_MODES")
    attempts = ((0o755, 0o750), (0o700, 0o711))
    for index, (capsule_mode, public_mode) in enumerate(attempts):
        root = tmp_path / str(index)
        capsule_parent, public_parent = root / "capsule", root / "public"
        capsule_parent.mkdir(parents=True)
        public_parent.mkdir()
        capsule_parent.chmod(capsule_mode)
        public_parent.chmod(public_mode)
        effects = []
        monkeypatch.setattr(
            module,
            "snapshot_sealer",
            lambda *_args, **_kwargs: effects.append("sealer") or tmp_path / "age",
        )
        with pytest.raises(module.CapsuleError):
            module.publish_recovery_pair(
                public_dir=public_parent / "bundle",
                capsule_path=capsule_parent / "capsule.age",
                public_identity=public_identity,
                recovery_trust=_canonical(trust),
                private_plaintext=b"private",
                sealer=tmp_path / "age",
            )
        assert effects == [], "invalid parent mode reached the sealer boundary"


@pytest.mark.skipif(os.name != "posix", reason="parent rename-to-symlink witness is POSIX-only")
def test_parent_swap_cannot_redirect_private_staging(
    trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B11_PARENT_SWAP")
    capsule_parent, public_parent = tmp_path / "capsule", tmp_path / "public"
    capsule_parent.mkdir(mode=0o700)
    public_parent.mkdir(mode=0o700)
    redirected = []

    def swap_parent(_source, run_dir, *_args, **_kwargs):
        stage = run_dir.parent
        moved, attacker = tmp_path / "capsule-moved", tmp_path / "attacker"
        capsule_parent.rename(moved)
        attacker.mkdir(mode=0o700)
        (attacker / stage.name).mkdir(mode=0o700)
        capsule_parent.symlink_to(attacker, target_is_directory=True)
        return tmp_path / "age"

    def observe_private_output(**kwargs):
        kwargs["output"].write_bytes(b"redirected-private")
        redirected.append(kwargs["output"].resolve())
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "snapshot_sealer", swap_parent)
    monkeypatch.setattr(module, "encrypt_private_capsule", observe_private_output)
    with pytest.raises(module.CapsuleError):
        module.publish_recovery_pair(
            public_dir=public_parent / "bundle",
            capsule_path=capsule_parent / "capsule.age",
            public_identity=public_identity,
            recovery_trust=_canonical(trust),
            private_plaintext=b"private",
            sealer=tmp_path / "age",
        )
    assert redirected == [], "private bytes reached a substituted output parent"


@pytest.mark.skipif(os.name != "posix", reason="intermediate directory symlink witness is POSIX-only")
def test_restore_rejects_symlinked_public_root_before_snapshot(tmp_path, monkeypatch):
    module = _api("B13_INTERMEDIATE_SYMLINK")
    state, runtime, real_public = tmp_path / "state", tmp_path / "runtime", tmp_path / "real-public"
    state.mkdir()
    runtime.mkdir()
    real_public.mkdir()
    public = tmp_path / "public"
    public.symlink_to(real_public, target_is_directory=True)
    staging = type(
        "Staging",
        (),
        {"state_dir": state, "runtime": runtime, "hrh": None, "project": PROJECT},
    )()
    effects = []

    def reject_if_read(*_args, **_kwargs):
        effects.append("snapshot-read")
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "read_bounded_regular", reject_if_read)
    with pytest.raises(module.CapsuleError):
        module.prepare_published_restore(
            staging,
            public,
            tmp_path / "capsule.age",
            tmp_path / "trust.json",
            tmp_path / "age",
            "a" * 64,
            now=NOW,
        )
    assert effects == [], "symlinked public root reached snapshot reads"


@pytest.mark.skipif(os.name != "posix", reason="fsync fd ordering witness uses /proc/self/fd")
def test_owner_marker_durability_reaches_output_parent_before_sealing(
    trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B12_OUTPUT_PARENT_FSYNC")
    public_parent, capsule_parent = tmp_path / "public", tmp_path / "capsule"
    public_parent.mkdir(mode=0o700)
    capsule_parent.mkdir(mode=0o700)
    events = []
    real_fsync = os.fsync

    def observe_fsync(descriptor):
        try:
            events.append(Path(os.readlink(f"/proc/self/fd/{descriptor}")))
        except OSError:
            pass
        real_fsync(descriptor)

    durable = {"value": False}

    def stop_at_seal(**_kwargs):
        markers = [path for path in events if path.name == ".clinical-recovery-owner.json"]
        durable["value"] = len(markers) == 2 and all(
            marker.parent in events[events.index(marker) + 1 :]
            and marker.parent.parent in events[events.index(marker.parent) + 1 :]
            for marker in markers
        )
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module.os, "fsync", observe_fsync)
    monkeypatch.setattr(module, "snapshot_sealer", lambda source, *_args, **_kwargs: source)
    monkeypatch.setattr(module, "encrypt_private_capsule", stop_at_seal)
    with pytest.raises(module.CapsuleError):
        module.publish_recovery_pair(
            public_dir=public_parent / "bundle",
            capsule_path=capsule_parent / "capsule.age",
            public_identity=public_identity,
            recovery_trust=_canonical(trust),
            private_plaintext=b"private",
            sealer=tmp_path / "age",
        )
    assert durable["value"], "owner durability stopped at the stage instead of its output parent"


def test_destination_disappearance_is_not_misreported_as_missing_capsule(
    tmp_path, monkeypatch
):
    module = _api("B15_NARROW_MISSING")
    source = tmp_path / "capsule.age"
    destination = tmp_path / "run" / "capsule.age"
    source.write_bytes(b"ciphertext")
    real_fdopen = os.fdopen
    removed = {"value": False}

    def remove_destination_parent(descriptor, *args, **kwargs):
        handle = real_fdopen(descriptor, *args, **kwargs)
        if not removed["value"]:
            destination.parent.rmdir()
            removed["value"] = True
        return handle

    monkeypatch.setattr(module.os, "fdopen", remove_destination_parent)
    with pytest.raises(module.CapsuleError, match="^RECOVERY_CAPSULE_MISMATCH$"):
        module.snapshot_declared_member(
            source,
            destination,
            declared_size=10,
            declared_sha256=_digest(b"ciphertext"),
        )


@pytest.mark.skipif(os.name != "posix", reason="stdout-only descendant witness is POSIX-only")
def test_sealer_rejects_stdout_only_descendant_before_hash_and_publish(tmp_path):
    module = _api("B29_STDOUT_ONLY_DESCENDANT")
    script, ready, pidfile = tmp_path / "fork.py", tmp_path / "ready", tmp_path / "pids"
    script.write_text(
        "import os,sys,time\n"
        "child=os.fork()\n"
        "if child==0:\n"
        "    sys.stdin.buffer.read(); os.close(0)\n"
        "    open(sys.argv[2],'w').write('ready')\n"
        "    time.sleep(1); os.write(1,b'late')\n"
        "else:\n"
        "    while not os.path.exists(sys.argv[2]): time.sleep(.01)\n"
        "    open(sys.argv[1],'w').write(f'{os.getpgrp()} {child}')\n"
        "    os._exit(0)\n",
        encoding="utf-8",
    )
    group = child = None
    alive = False
    try:
        with pytest.raises(module.CapsuleError, match="^RECOVERY_SEALER_UNAVAILABLE$"):
            module.run_sealer(
                executable=Path(sys.executable),
                arguments=(str(script), str(pidfile), str(ready)),
                stdin=b"synthetic private",
                output=tmp_path / "sealed",
                timeout_seconds=0.4,
                environment=dict(os.environ),
            )
    finally:
        if pidfile.exists():
            group, child = map(int, pidfile.read_text(encoding="utf-8").split())
            try:
                os.kill(child, 0)
                alive = True
            except ProcessLookupError:
                pass
        if alive and group is not None:
            os.killpg(group, signal.SIGKILL)
    assert not alive
    assert not (tmp_path / "sealed").exists()


@pytest.mark.skipif(os.name != "posix", reason="inode-bound swap and input-symlink witness is POSIX-only")
def test_all_capsule_paths_remain_inode_bound_and_reject_input_parent_symlinks(
    age_material, trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B13_ALL_INODE_BOUND")
    violations = []
    swap_root = tmp_path / "swap"
    capsule_parent, public_parent = swap_root / "capsule", swap_root / "public"
    capsule_parent.mkdir(mode=0o700, parents=True)
    public_parent.mkdir(mode=0o700)
    real_require = module._require_trusted_parent

    def swap_after_last_recheck(path, **kwargs):
        token = real_require(path, **kwargs)
        if path == public_parent and not capsule_parent.is_symlink():
            moved, attacker = swap_root / "capsule-moved", swap_root / "attacker"
            capsule_parent.rename(moved)
            attacker.mkdir(mode=0o700)
            stage = next(moved.glob(".capsule-run-*"))
            (attacker / stage.name).mkdir(mode=0o700)
            capsule_parent.symlink_to(attacker, target_is_directory=True)
        return token

    def redirected_seal(**kwargs):
        violations.append(f"redirected:{kwargs['output'].resolve()}")
        kwargs["output"].write_bytes(b"redirected private")
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "_require_trusted_parent", swap_after_last_recheck)
    monkeypatch.setattr(module, "snapshot_sealer", lambda source, *_args, **_kwargs: source)
    monkeypatch.setattr(module, "encrypt_private_capsule", redirected_seal)
    with pytest.raises(module.CapsuleError):
        module.publish_recovery_pair(
            public_dir=public_parent / "bundle",
            capsule_path=capsule_parent / "capsule.age",
            public_identity=public_identity,
            recovery_trust=_canonical(trust),
            private_plaintext=b"private",
            sealer=tmp_path / "age",
        )
    moved = swap_root / "capsule-moved"
    if moved.exists() and list(moved.glob(".capsule-run-*")):
        violations.append("original-private-stage-survived-cleanup")

    monkeypatch.undo()
    for kind in ("capsule", "trust", "sealer"):
        case = tmp_path / f"input-{kind}"
        case.mkdir()
        bundle = _fixture_recovery_pair(case, public_identity, trust)
        bundle["public_dir"].chmod(0o700)
        runtime = case / "runtime"
        runtime.mkdir()
        real_inputs, alias = case / "real-inputs", case / "input-alias"
        real_inputs.mkdir(mode=0o700)
        alias.symlink_to(real_inputs, target_is_directory=True)
        (real_inputs / "capsule.age").write_bytes(bundle["capsule_bytes"])
        (real_inputs / "trust.json").write_bytes(_canonical(trust))
        shutil.copyfile(age_material["age"], real_inputs / "age")
        (real_inputs / "age").chmod(0o500)
        direct_capsule, direct_trust, direct_sealer = (
            case / "capsule.age",
            case / "trust.json",
            case / "age",
        )
        direct_capsule.write_bytes(bundle["capsule_bytes"])
        direct_trust.write_bytes(_canonical(trust))
        shutil.copyfile(age_material["age"], direct_sealer)
        direct_sealer.chmod(0o500)
        selected = {
            "capsule": alias / "capsule.age" if kind == "capsule" else direct_capsule,
            "trust": alias / "trust.json" if kind == "trust" else direct_trust,
            "sealer": alias / "age" if kind == "sealer" else direct_sealer,
        }
        staging = type(
            "Staging",
            (),
            {
                "state_dir": case / "state",
                "runtime": runtime,
                "hrh": None,
                "project": PROJECT,
            },
        )()
        try:
            prepared = module.prepare_published_restore(
                staging,
                bundle["public_dir"],
                selected["capsule"],
                selected["trust"],
                selected["sealer"],
                bundle["external_manifest_sha256"],
                now=NOW,
            )
        except module.CapsuleError:
            continue
        module.cleanup_prepared_restore(prepared)
        violations.append(f"accepted-{kind}-intermediate-symlink")
    assert violations == []


def test_timeout_joins_feeder_after_group_termination_before_cleanup(tmp_path, monkeypatch):
    module = _api("B29_JOIN_AFTER_KILL")

    class FakePipe:
        def write(self, _payload):
            return None

        def close(self):
            return None

    class FakeProcess:
        pid = 12345
        returncode = None
        stdin = FakePipe()

        def __init__(self):
            self.waits = 0
            self.killed = False

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("synthetic", timeout)
            self.returncode = -9
            return self.returncode

        def kill(self):
            self.killed = True

    class FakeThread:
        def __init__(self, *, target):
            self.target = target
            self.started = False
            self.joins = 0

        def start(self):
            self.started = True

        def join(self, _timeout=None):
            self.joins += 1
            self.started = False

        def is_alive(self):
            return self.started

    process = FakeProcess()
    threads = []

    def make_thread(*, target):
        thread = FakeThread(target=target)
        threads.append(thread)
        return thread

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(module.threading, "Thread", make_thread)
    with pytest.raises(module.CapsuleError, match="^RECOVERY_SEALER_UNAVAILABLE$"):
        module.run_sealer(
            executable=Path(sys.executable),
            arguments=(),
            stdin=b"private",
            output=tmp_path / "sealed",
            timeout_seconds=0.1,
            environment={},
        )
    assert process.killed
    assert len(threads) == 1 and threads[0].joins == 1
    assert not threads[0].is_alive()
    assert not list(tmp_path.glob("*.partial-*"))


@pytest.mark.skipif(os.name != "posix", reason="post-retention parent swap witness is POSIX-only")
def test_private_output_is_inode_bound_after_final_parent_retention_check(
    trust, public_identity, tmp_path, monkeypatch
):
    module = _api("B11_POST_RETENTION_SWAP")
    capsule_parent, public_parent = tmp_path / "capsule", tmp_path / "public"
    capsule_parent.mkdir(mode=0o700)
    public_parent.mkdir(mode=0o700)
    real_retained = module._retained_directory_is_current
    swapped = {"value": False}
    private_outputs = []

    def swap_after_last_check(path, descriptor, token, **kwargs):
        result = real_retained(path, descriptor, token, **kwargs)
        if path == public_parent and not swapped["value"]:
            moved, attacker = tmp_path / "capsule-moved", tmp_path / "attacker"
            capsule_parent.rename(moved)
            attacker.mkdir(mode=0o700)
            stage = next(moved.glob(".capsule-run-*"))
            (attacker / stage.name).mkdir(mode=0o700)
            capsule_parent.symlink_to(attacker, target_is_directory=True)
            swapped["value"] = True
        return result

    def record_output(**kwargs):
        kwargs["output"].write_bytes(b"redirected private")
        private_outputs.append(kwargs["output"].resolve())
        raise module.CapsuleError("synthetic stop")

    monkeypatch.setattr(module, "_retained_directory_is_current", swap_after_last_check)
    monkeypatch.setattr(module, "snapshot_sealer", lambda source, *_args, **_kwargs: source)
    monkeypatch.setattr(module, "encrypt_private_capsule", record_output)
    with pytest.raises(module.CapsuleError):
        module.publish_recovery_pair(
            public_dir=public_parent / "bundle",
            capsule_path=capsule_parent / "capsule.age",
            public_identity=public_identity,
            recovery_trust=_canonical(trust),
            private_plaintext=b"private",
            sealer=tmp_path / "age",
        )
    assert private_outputs == [], "private output followed a substituted pathname after retained-fd validation"
    moved = tmp_path / "capsule-moved"
    assert not moved.exists() or not list(moved.glob(".capsule-run-*"))


def test_feeder_that_survives_pre_kill_join_is_joined_again_after_kill(
    tmp_path, monkeypatch
):
    module = _api("B29_POST_KILL_REJOIN")

    class FakePipe:
        def write(self, _payload):
            return None

        def close(self):
            return None

    class FakeProcess:
        pid = 12345
        stdin = FakePipe()

        def __init__(self):
            self.returncode = 0
            self.killed = False

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    class FakeThread:
        def __init__(self, *, target):
            self.target = target
            self.alive = False
            self.joins = 0

        def start(self):
            self.alive = True

        def join(self, _timeout=None):
            self.joins += 1
            if self.joins >= 2:
                self.alive = False

        def is_alive(self):
            return self.alive

    process = FakeProcess()
    threads = []

    def make_thread(*, target):
        thread = FakeThread(target=target)
        threads.append(thread)
        return thread

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(module.threading, "Thread", make_thread)
    with pytest.raises(module.CapsuleError, match="^RECOVERY_SEALER_UNAVAILABLE$"):
        module.run_sealer(
            executable=Path(sys.executable),
            arguments=(),
            stdin=b"private",
            output=tmp_path / "sealed",
            timeout_seconds=0.1,
            environment={},
        )
    assert process.killed
    assert len(threads) == 1 and threads[0].joins == 2
    assert not threads[0].is_alive()
    assert not list(tmp_path.glob("*.partial-*"))
