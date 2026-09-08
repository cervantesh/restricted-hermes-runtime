"""U4R capsule RED contract for the frozen published-recovery v2 design.

Pinned base: d6a572f96b79e8f6383ffe9bef94da17c5ff841a
Contract: docs/design/durable-published-hrh-recovery-capsule.v2.md

This file deliberately contains no production stub.  Every RED row calls the
future ``clinical_recovery_capsule`` module through ``_api``.  While that
module is absent, each row reports ``PREREQUISITE RED``.  Once it exists, the
same row must prove its own observable predicate rather than treating import
success as implementation success.

This unit fully controls only pure parsing, binding and source-v1 compatibility
predicates.  B05-B11, B13-B18, B20-B21 and B26-B29 are executable RED or
PARTIAL integration contracts.  B12 proves only bounded reconciliation;
SIGKILL publication is NOT_VERIFIED.  B19 and B22-B25 remain NOT_VERIFIED
because they require integrated acquisition, restore, receipts and services.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
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
    return {"sha256": _digest(data), "size": len(data), "ownership_sha256": SHA}


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


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name in sorted(files):
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
    private = {"state.tar": b"private-state:" + PUBLIC_SECRET}
    private.update(
        {f"volumes/{name}.tar": f"private-volume:{name}".encode() for name in VOLUME_KEYS}
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
    (public / "backup-identity.json").write_bytes(identity_bytes)
    (public / "recovery-trust.json").write_bytes(trust_bytes)
    manifest = {
        "schema": PUBLIC_SCHEMA, "project": PROJECT, "state_id": STATE_ID,
        "backup_identity_sha256": _digest(identity_bytes),
        "recovery_trust_sha256": _digest(trust_bytes),
        "capsule_id": CAPSULE_ID,
    }
    manifest_bytes = _canonical(manifest)
    (public / "backup-manifest.json").write_bytes(manifest_bytes)
    return {
        "public_dir": public,
        "public_identity": public_identity,
        "manifest": manifest,
        "external_manifest_sha256": _digest(manifest_bytes),
    }


def _reseal_fixture_pair(bundle: dict[str, Any], changed_identity) -> dict[str, Any]:
    resealed = copy.deepcopy(bundle)
    public = bundle["public_dir"].parent / "resealed"
    public.mkdir()
    identity_bytes = _canonical(changed_identity)
    manifest = dict(bundle["manifest"], backup_identity_sha256=_digest(identity_bytes))
    (public / "backup-identity.json").write_bytes(identity_bytes)
    (public / "backup-manifest.json").write_bytes(_canonical(manifest))
    resealed.update(public_dir=public, public_identity=changed_identity, manifest=manifest)
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
    assert resealed["external_manifest_sha256"] == bundle["external_manifest_sha256"]


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


def test_b04_sealer_is_snapshotted_from_one_open_file_before_path_substitution(
    age_material, trust, tmp_path
):
    module = _api("B04")
    source = tmp_path / "age"
    source.write_bytes(age_material["age"].read_bytes())
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
    evidence_names = {*verifier.EVIDENCE_FILES, "SHA256SUMS.json", "trust.json", "verification.json"}
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
        assert {member.name for member in evidence_tar.getmembers()} == evidence_names
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
        plaintext=b"private:" + PUBLIC_SECRET,
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
    assert kwargs["input"] == b"private:" + PUBLIC_SECRET


def test_b09_b20_resealed_cross_generation_substitution_is_rejected(
    trust, public_identity, tmp_path
):
    module = _api("B09")
    bundle = _fixture_recovery_pair(tmp_path, public_identity, trust)
    changed = copy.deepcopy(public_identity)
    changed["hrh_candidate"]["receipt_sha256"] = "f" * 64
    resealed = _reseal_fixture_pair(bundle, changed)
    with pytest.raises(module.CapsuleError, match="RECOVERY_GENERATION_MISMATCH"):
        _fn(module, "B20", "validate_recovery_pair")(
            resealed,
            expected_manifest_sha256=bundle["external_manifest_sha256"],
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
    public, capsule = tmp_path / "public", tmp_path / "private" / "capsule.age"
    if PUBLICATION_STAGES.index(stage) < PUBLICATION_STAGES.index("PUBLIC_PUBLISHED"):
        assert not public.exists() and not capsule.exists()
    else:
        assert capsule.is_file() and (public / "COMPLETE").is_file()
        assert not list(public.glob("*receipt*"))


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
