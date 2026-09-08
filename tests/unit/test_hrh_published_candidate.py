from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "verify_hrh_published_candidate.py"
WEB = (
    "us-east4-docker.pkg.dev/health-record-hub-shared/containers/web@sha256:" + "1" * 64
)
MIGRATE = (
    "us-east4-docker.pkg.dev/health-record-hub-shared/containers/migrate@sha256:"
    + "2" * 64
)
EVIDENCE = (
    "us-east4-docker.pkg.dev/health-record-hub-shared/containers/evidence@sha256:"
    + "8" * 64
)
C = "a" * 40
H = "b" * 40
PUBLISHER = "forgejo-deployer@aali-forgejo.iam.gserviceaccount.com"
KMS = "projects/health-record-hub-shared/locations/us-east4/keyRings/hrh-shared/cryptoKeys/clinical/cryptoKeyVersions/1"
PRODUCER_EVIDENCE_FILES = (
    "candidate-receipt.json", "candidate-receipt.sig",
    "cleanup-policies.raw.json", "cleanup-policy-observation.json",
    "kms-public.pem", "migrate.attachment.manifest.json",
    "migrate.attestation-retention-evidence.json",
    "migrate.downloaded-attestations.json", "migrate.material-evidence.json",
    "migrate.provenance.json", "migrate.retention-evidence.json",
    "migrate.runtime-identity.json", "migrate.spdx.json",
    "migrate.subject.config.json", "migrate.subject.manifest.json",
    "web.attachment.manifest.json", "web.attestation-retention-evidence.json",
    "web.downloaded-attestations.json", "web.material-evidence.json",
    "web.provenance.json", "web.retention-evidence.json",
    "web.runtime-identity.json", "web.spdx.json", "web.subject.config.json",
    "web.subject.manifest.json",
)


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "verify_hrh_published_candidate", TOOL
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(tmp_path: Path):
    public_key = tmp_path / "synthetic-not-production.pem"
    public_key.write_text(
        "synthetic public key; cryptography is represented by the cosign boundary\n",
        encoding="utf-8",
    )
    key_hash = hashlib.sha256(public_key.read_bytes()).hexdigest()
    trust = {
        "schema_version": "restricted-runtime-hrh-trust.v2",
        "clinical_contract_revision": C,
        "build_source_revision": H,
        "platform": {"os": "linux", "architecture": "amd64"},
        "publisher_identity": PUBLISHER,
        "kms_key_version": KMS,
        "kms_public_key_sha256": key_hash,
        "subjects": {"web": WEB, "migrate": MIGRATE, "evidence": EVIDENCE},
    }
    subjects = []
    for role, image, identity in (
        ("web", WEB, "10001:10001"),
        ("migrate", MIGRATE, "10002:10002"),
    ):
        material = {"apk_inventory_sha256": "3" * 64}
        material.update(
            {"package_lock_sha256": "4" * 64, "npm_integrity_basis_sha256": "5" * 64}
            if role == "web"
            else {"migrations_tree_sha256": "6" * 64, "run_migrations_sha256": "7" * 64}
        )
        digest = image.split("@sha256:", 1)[1]
        retention = {
            "tag": image.split("@")[0] + f":keep-clinical-img-{digest}",
            "subject": image,
            "registry_resolution": image,
        }
        attachment_digest = ("8" if role == "web" else "9") * 64
        subjects.append(
            {
                "role": role,
                "image": image,
                "platform": {"os": "linux", "architecture": "amd64"},
                "runtime_identity": {
                    "declared_user": identity,
                    "effective_uid_gid": identity,
                },
                "material_evidence": material,
                "retention_evidence": retention,
                "attestation_retention_evidence": {
                    "role": role,
                    "subject": image,
                    "attachment_reference": image.split("@")[0]
                    + f":sha256-{digest}.att",
                    "attachment_subject": image.split("@")[0]
                    + f"@sha256:{attachment_digest}",
                    "attachment_manifest_digest": f"sha256:{attachment_digest}",
                    "tag": image.split("@")[0]
                    + f":keep-clinical-att-{attachment_digest}",
                    "registry_resolution": image.split("@")[0]
                    + f"@sha256:{attachment_digest}",
                },
                "retention_tag": f"keep-clinical-img-{digest}",
                "sbom": {
                    "subject": image,
                    "predicate_type": "https://spdx.dev/Document/v2.3",
                    "verification": "required",
                },
                "provenance": {
                    "subject": image,
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    "verification": "required",
                },
            }
        )
    receipt = {
        "schema_version": 1,
        "clinical_contract_revision": C,
        "build_source_revision": H,
        "signing": {
            "publisher_identity": PUBLISHER,
            "kms_key_version": KMS,
            "kms_public_key_sha256": key_hash,
            "workflow_run_url": "https://forgejo.aalinstitute.com/cervantes/Health-Record-Hub/actions/runs/123",
        },
        "phi_authorized": False,
        "deployment_conformant": False,
        "subjects": subjects,
    }
    return trust, receipt, public_key


def write_evidence_bundle(
    tool, directory: Path, receipt_bytes: bytes, signature_bytes: bytes,
    public_key_bytes: bytes,
) -> None:
    directory.mkdir()
    receipt = json.loads(receipt_bytes)
    by_role = {item["role"]: item for item in receipt["subjects"]}
    values = {
        "candidate-receipt.json": receipt_bytes,
        "candidate-receipt.sig": signature_bytes,
        "cleanup-policies.raw.json": b'{"cleanupPolicies":{}}\n',
        "cleanup-policy-observation.json": b'{"continuous_retention_proven":false}\n',
        "kms-public.pem": public_key_bytes,
    }
    for role in ("web", "migrate"):
        subject = by_role[role]
        role_values = {
            "attachment.manifest.json": {"schemaVersion": 2},
            "attestation-retention-evidence.json": subject[
                "attestation_retention_evidence"
            ],
            "downloaded-attestations.json": [],
            "material-evidence.json": subject["material_evidence"],
            "provenance.json": {"predicateType": "https://slsa.dev/provenance/v1"},
            "retention-evidence.json": subject["retention_evidence"],
            "runtime-identity.json": subject["runtime_identity"],
            "spdx.json": {"spdxVersion": "SPDX-2.3"},
            "subject.config.json": {"config": role},
            "subject.manifest.json": {"schemaVersion": 2},
        }
        for name, value in role_values.items():
            values[f"{role}.{name}"] = (
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
    assert set(values) == set(tool.EVIDENCE_FILES)
    for name, data in values.items():
        (directory / name).write_bytes(data)
    entries = [
        {"path": name, "sha256": hashlib.sha256(values[name]).hexdigest(), "size": len(values[name])}
        for name in tool.EVIDENCE_FILES
    ]
    (directory / "SHA256SUMS.json").write_text(
        json.dumps({"schema_version": 1, "files": entries}, indent=2) + "\n",
        encoding="utf-8",
    )


def format_exact_signed_fixture(tmp_path: Path):
    tool = load_tool()
    trust, receipt, _ = fixture(tmp_path)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_hash = hashlib.sha256(public_key_bytes).hexdigest()
    trust["kms_public_key_sha256"] = key_hash
    receipt["signing"]["kms_public_key_sha256"] = key_hash
    receipt_bytes = (
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    signature = private_key.sign(receipt_bytes, ec.ECDSA(hashes.SHA256()))
    signature_bytes = base64.b64encode(signature) + b"\n"
    evidence = tmp_path / "evidence"
    write_evidence_bundle(
        tool, evidence, receipt_bytes, signature_bytes, public_key_bytes
    )
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    docker = tmp_path / "docker"
    docker.mkdir(mode=0o700)
    credential = base64.b64encode(b"user:credential-leak-canary").decode()
    (docker / "config.json").write_text(
        json.dumps({"auths": {"us-east4-docker.pkg.dev": {"auth": credential}}}),
        encoding="utf-8",
    )
    if os.name != "nt":
        (docker / "config.json").chmod(0o600)
    return tool, trust_path, evidence, docker, private_key, receipt, credential


def signed_statement(receipt: dict, role: str, predicate_type: str) -> dict:
    subject = next(item for item in receipt["subjects"] if item["role"] == role)
    repository, digest = subject["image"].split("@sha256:")
    predicate = {"spdxVersion": "SPDX-2.3"}
    if predicate_type == "https://slsa.dev/provenance/v1":
        predicate = {
            "buildDefinition": {
                "externalParameters": {
                    "role": role,
                    "platform": "linux/amd64",
                    "clinical_contract_revision": C,
                    "build_source_revision": H,
                    "publisher_identity": PUBLISHER,
                    "kms_key_version": KMS,
                    "kms_public_key_sha256": receipt["signing"][
                        "kms_public_key_sha256"
                    ],
                    "runtime_identity": subject["runtime_identity"],
                    "material_evidence": subject["material_evidence"],
                    "retention_evidence": subject["retention_evidence"],
                },
                "resolvedDependencies": [
                    {
                        "uri": "https://forgejo.aalinstitute.com/cervantes/Health-Record-Hub.git",
                        "digest": {"gitCommit": H},
                    }
                ],
            },
            "runDetails": {
                "metadata": {"invocationId": receipt["signing"]["workflow_run_url"]}
            },
        }
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": predicate_type,
        "subject": [{"name": repository, "digest": {"sha256": digest}}],
        "predicate": predicate,
    }


def _mounted_host_path(args, container_path: str) -> Path:
    suffix = f":{container_path}:ro"
    mount = next(value for value in args if value.endswith(suffix))
    return Path(mount[: -len(suffix)])


def test_a96effc_bundle_signature_and_four_attestations_produce_canonical_identity(
    tmp_path,
):
    tool, trust_path, evidence, docker, _, receipt, credential = (
        format_exact_signed_fixture(tmp_path)
    )
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        if "verify-blob" in args:
            public_key = serialization.load_pem_public_key(
                _mounted_host_path(args, "/trust/public.pem").read_bytes()
            )
            receipt_bytes = _mounted_host_path(
                args, "/evidence/candidate-receipt.json"
            ).read_bytes()
            signature = base64.b64decode(
                _mounted_host_path(
                    args, "/evidence/candidate-receipt.sig"
                ).read_bytes().strip(),
                validate=True,
            )
            try:
                public_key.verify(signature, receipt_bytes, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                return subprocess.CompletedProcess(args, 1, "", "bad signature")
            return subprocess.CompletedProcess(args, 0, "Verified OK", "")
        role = "migrate" if MIGRATE in args else "web"
        predicate = (
            "https://spdx.dev/Document/v2.3"
            if "spdxjson" in args
            else "https://slsa.dev/provenance/v1"
        )
        payload = base64.b64encode(
            json.dumps(signed_statement(receipt, role, predicate)).encode()
        ).decode()
        return subprocess.CompletedProcess(
            args, 0, json.dumps([{"payload": payload}]), ""
        )

    result = tool.verify_files(trust_path, evidence, docker, runner=runner)
    expected_keys = {
        "schema_version", "trust_sha256", "receipt_sha256",
        "receipt_signature_sha256", "evidence_manifest_sha256",
        "kms_public_key_sha256", "subjects", "verified_predicates",
    }
    assert set(result) == expected_keys
    assert result["verified_predicates"] == [
        "migrate:provenance", "migrate:sbom", "web:provenance", "web:sbom"
    ]
    assert tool.canonical_verification_bytes(result) == tool.canonical_verification_bytes(
        json.loads(tool.canonical_verification_bytes(result))
    )
    assert len(calls) == 5
    rendered = json.dumps(calls, default=str)
    assert credential not in rendered
    assert "credential-leak-canary" not in rendered
    assert all(call[1]["env"] == tool.sealed_docker_environment() for call in calls)
    config_mounts = []
    for args, _ in calls:
        mount = next(
            value
            for value in args
            if value.endswith(":/run/docker:ro")
            or value.endswith(":/home/nonroot/.docker:ro")
        )
        config_mounts.append(mount.rsplit(":/", 1)[0])
    assert len(set(config_mounts)) == 1
    assert Path(config_mounts[0]) != docker.resolve()
    retained = b"".join(path.read_bytes() for path in evidence.iterdir())
    assert b"credential-leak-canary" not in retained


def test_a96effc_evidence_allowlist_is_exact_and_closed():
    tool = load_tool()
    assert tool.EVIDENCE_FILES == PRODUCER_EVIDENCE_FILES
    assert len(tool.EVIDENCE_FILES) == 25


@pytest.mark.parametrize("mutation", ["missing", "extra", "hash", "size"])
def test_evidence_bundle_is_an_exact_closed_hashed_allowlist(tmp_path, mutation):
    tool, _, evidence, _, _, _, _ = format_exact_signed_fixture(tmp_path)
    if mutation == "missing":
        (evidence / tool.EVIDENCE_FILES[0]).unlink()
    elif mutation == "extra":
        (evidence / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    else:
        manifest_path = evidence / "SHA256SUMS.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0][mutation] = "0" * 64 if mutation == "hash" else 999
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(tool.CandidateVerificationError):
        tool.read_evidence_snapshot(evidence)


@pytest.mark.skipif(os.name == "nt", reason="POSIX evidence symlink control")
def test_evidence_bundle_rejects_symlink_substitution(tmp_path):
    tool, _, evidence, _, _, _, _ = format_exact_signed_fixture(tmp_path)
    target = tmp_path / "substitute.json"
    target.write_text("{}", encoding="utf-8")
    selected = evidence / "web.runtime-identity.json"
    selected.unlink()
    selected.symlink_to(target)

    with pytest.raises(tool.CandidateVerificationError, match="regular file"):
        tool.read_evidence_snapshot(evidence)


def test_wrong_receipt_signature_fails_before_attestation_verification(
    tmp_path, monkeypatch
):
    tool, trust_path, evidence, docker, _, _, _ = format_exact_signed_fixture(
        tmp_path
    )
    (evidence / "candidate-receipt.sig").write_text(
        base64.b64encode(b"not-a-valid-signature").decode() + "\n",
        encoding="utf-8",
    )
    signature_bytes = (evidence / "candidate-receipt.sig").read_bytes()
    manifest_path = evidence / "SHA256SUMS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(
        item for item in manifest["files"] if item["path"] == "candidate-receipt.sig"
    )
    entry["sha256"] = hashlib.sha256(signature_bytes).hexdigest()
    entry["size"] = len(signature_bytes)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        tool,
        "verify_attestations",
        lambda *args, **kwargs: pytest.fail("attestations ran after bad receipt signature"),
    )

    def reject_signature(args, **kwargs):
        assert "verify-blob" in args
        return subprocess.CompletedProcess(args, 1, "", "invalid signature")

    with pytest.raises(tool.CandidateVerificationError, match="receipt signature"):
        tool.verify_files(trust_path, evidence, docker, runner=reject_signature)


def test_rehashed_retained_role_substitution_still_differs_from_receipt(
    tmp_path, monkeypatch
):
    tool, trust_path, evidence, docker, _, _, _ = format_exact_signed_fixture(
        tmp_path
    )
    selected = evidence / "web.runtime-identity.json"
    selected.write_text(
        json.dumps({"declared_user": "0:0", "effective_uid_gid": "0:0"}) + "\n",
        encoding="utf-8",
    )
    data = selected.read_bytes()
    manifest_path = evidence / "SHA256SUMS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(
        item for item in manifest["files"] if item["path"] == selected.name
    )
    entry["sha256"] = hashlib.sha256(data).hexdigest()
    entry["size"] = len(data)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        tool,
        "verify_receipt_signature",
        lambda *args, **kwargs: pytest.fail("crypto ran after retained mismatch"),
    )

    with pytest.raises(tool.CandidateVerificationError, match="differs from the exact receipt"):
        tool.verify_files(trust_path, evidence, docker)


def test_cli_exposes_only_three_published_input_paths():
    result = subprocess.run(
        [os.sys.executable, str(TOOL), "--help"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--trust" in result.stdout
    assert "--evidence" in result.stdout
    assert "--docker-config" in result.stdout
    assert "--receipt" not in result.stdout
    assert "--public-key" not in result.stdout
    assert "--docker-config-snapshot" not in result.stdout


def test_separate_trust_declaration_and_four_signed_statements_are_required(tmp_path):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    candidate = tool.validate_candidate(trust, receipt, key.read_bytes())
    calls = []
    mounted_key_bytes = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        mount_indexes = [index for index, value in enumerate(args) if value == "--volume"]
        key_mount = args[mount_indexes[1] + 1]
        mounted_key_bytes.append(
            Path(key_mount.rsplit(":/trust/public.pem:ro", 1)[0]).read_bytes()
        )
        role = "migrate" if MIGRATE in args else "web"
        predicate = (
            "https://spdx.dev/Document/v2.3"
            if "spdxjson" in args
            else "https://slsa.dev/provenance/v1"
        )
        payload = base64.b64encode(
            json.dumps(signed_statement(receipt, role, predicate)).encode()
        ).decode()
        return subprocess.CompletedProcess(
            args, 0, json.dumps([{"payload": payload}]), ""
        )

    docker_config = tmp_path / "docker"
    docker_config.mkdir(mode=0o700)
    config = docker_config / "config.json"
    credential = "oauth2:registry-secret-canary"
    encoded_credential = base64.b64encode(credential.encode()).decode()
    config.write_text(
        json.dumps(
            {"auths": {"us-east4-docker.pkg.dev": {"auth": encoded_credential}}}
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        config.chmod(0o600)
    expected_key = key.read_bytes()
    result = tool.verify_attestations(
        candidate, expected_key, docker_config, runner=runner
    )

    assert result["verified_predicates"] == [
        "migrate:provenance", "migrate:sbom", "web:provenance", "web:sbom"
    ]
    assert len(calls) == 4
    rendered = "\n".join(" ".join(call[0]) for call in calls)
    assert credential not in rendered
    assert encoded_credential not in rendered
    assert "--registry-token" not in rendered
    assert all(call[1].get("env") == tool.sealed_docker_environment() for call in calls)
    assert mounted_key_bytes == [expected_key] * 4


@pytest.mark.parametrize(
    "mutation",
    [
        "trust_extra",
        "wrong_c",
        "wrong_h",
        "wrong_platform",
        "wrong_publisher",
        "wrong_kms",
        "wrong_key_hash",
        "tag",
        "missing_subject",
        "swapped_role",
        "wrong_receipt_subject",
        "wrong_evidence_subject",
        "attestation_role",
        "attestation_subject",
        "attestation_digest",
        "attestation_tag",
    ],
)
def test_identity_and_trust_mismatches_fail_closed(tmp_path, mutation):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    if mutation == "trust_extra":
        trust["unapproved"] = True
    elif mutation == "wrong_c":
        receipt["clinical_contract_revision"] = "c" * 40
    elif mutation == "wrong_h":
        receipt["build_source_revision"] = "d" * 40
    elif mutation == "wrong_platform":
        receipt["subjects"][0]["platform"]["architecture"] = "arm64"
    elif mutation == "wrong_publisher":
        receipt["signing"]["publisher_identity"] = "other@example.invalid"
    elif mutation == "wrong_kms":
        receipt["signing"]["kms_key_version"] = KMS[:-1] + "2"
    elif mutation == "wrong_key_hash":
        trust["kms_public_key_sha256"] = "f" * 64
    elif mutation == "tag":
        trust["subjects"]["web"] = WEB.split("@")[0] + ":latest"
    elif mutation == "missing_subject":
        receipt["subjects"].pop()
    elif mutation == "swapped_role":
        receipt["subjects"][0]["role"] = "migrate"
    elif mutation == "wrong_receipt_subject":
        receipt["subjects"][0]["image"] = receipt["subjects"][1]["image"]
    elif mutation == "wrong_evidence_subject":
        trust["subjects"]["evidence"] = EVIDENCE.split("@", 1)[0] + ":latest"
    elif mutation == "attestation_role":
        receipt["subjects"][0]["attestation_retention_evidence"]["role"] = "migrate"
    elif mutation == "attestation_subject":
        receipt["subjects"][0]["attestation_retention_evidence"]["subject"] = MIGRATE
    elif mutation == "attestation_digest":
        receipt["subjects"][0]["attestation_retention_evidence"][
            "attachment_manifest_digest"
        ] = "sha256:" + "f" * 64
    elif mutation == "attestation_tag":
        receipt["subjects"][0]["attestation_retention_evidence"]["tag"] += "-wrong"
    with pytest.raises(tool.CandidateVerificationError):
        tool.validate_candidate(trust, receipt, key.read_bytes())


@pytest.mark.parametrize(
    "signed_mutation", ["role", "contract", "build", "run", "subject", "predicate"]
)
def test_valid_signature_for_wrong_purpose_or_contract_is_rejected(
    tmp_path, signed_mutation
):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    candidate = tool.validate_candidate(trust, receipt, key.read_bytes())
    docker_config = tmp_path / "docker"
    docker_config.mkdir(mode=0o700)
    (docker_config / "config.json").write_text(
        json.dumps(
            {
                "auths": {
                    "us-east4-docker.pkg.dev": {
                        "auth": base64.b64encode(b"user:placeholder").decode()
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        (docker_config / "config.json").chmod(0o600)

    def runner(args, **kwargs):
        role = "migrate" if MIGRATE in args else "web"
        predicate = (
            "https://spdx.dev/Document/v2.3"
            if "spdxjson" in args
            else "https://slsa.dev/provenance/v1"
        )
        statement = signed_statement(receipt, role, predicate)
        if predicate.endswith("provenance/v1") and role == "web":
            external = statement["predicate"]["buildDefinition"]["externalParameters"]
            if signed_mutation == "role":
                external["role"] = "migrate"
            elif signed_mutation == "contract":
                external["clinical_contract_revision"] = "c" * 40
            elif signed_mutation == "build":
                external["build_source_revision"] = "d" * 40
            elif signed_mutation == "run":
                statement["predicate"]["runDetails"]["metadata"]["invocationId"] += (
                    "/other"
                )
            elif signed_mutation == "subject":
                statement["subject"][0]["digest"]["sha256"] = "9" * 64
            elif signed_mutation == "predicate":
                statement["predicateType"] = "https://example.invalid/wrong-purpose"
        payload = base64.b64encode(json.dumps(statement).encode()).decode()
        return subprocess.CompletedProcess(args, 0, json.dumps([{"payload": payload}]), "")

    with pytest.raises(
        tool.CandidateVerificationError, match="signed candidate contract"
    ):
        tool.verify_attestations(candidate, key.read_bytes(), docker_config, runner=runner)


def test_forged_nested_matching_statement_cannot_replace_wrong_signed_outer_statement(
    tmp_path,
):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    candidate = tool.validate_candidate(trust, receipt, key.read_bytes())
    docker_config = tmp_path / "docker"
    docker_config.mkdir(mode=0o700)
    config = docker_config / "config.json"
    config.write_text(
        json.dumps(
            {
                "auths": {
                    "us-east4-docker.pkg.dev": {
                        "auth": base64.b64encode(b"user:placeholder").decode()
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        config.chmod(0o600)

    def runner(args, **kwargs):
        role = "migrate" if MIGRATE in args else "web"
        predicate = (
            "https://spdx.dev/Document/v2.3"
            if "spdxjson" in args
            else "https://slsa.dev/provenance/v1"
        )
        outer = signed_statement(receipt, role, predicate)
        if role == "web" and predicate.endswith("provenance/v1"):
            matching_nested = signed_statement(receipt, role, predicate)
            outer["predicate"]["buildDefinition"]["externalParameters"]["role"] = (
                "migrate"
            )
            outer["predicate"]["attacker_controlled_nested"] = matching_nested
        payload = base64.b64encode(json.dumps(outer).encode()).decode()
        return subprocess.CompletedProcess(
            args, 0, json.dumps([{"payload": payload}]), ""
        )

    with pytest.raises(
        tool.CandidateVerificationError, match="signed candidate contract"
    ):
        tool.verify_attestations(candidate, key.read_bytes(), docker_config, runner=runner)


def _attestation_docker_config(tmp_path: Path) -> Path:
    directory = tmp_path / "attestation-docker"
    directory.mkdir(mode=0o700)
    config = directory / "config.json"
    config.write_text(
        json.dumps(
            {
                "auths": {
                    "us-east4-docker.pkg.dev": {
                        "auth": base64.b64encode(b"user:placeholder").decode()
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        config.chmod(0o600)
    return directory


def test_one_matching_and_one_conflicting_signed_outer_statement_is_rejected(tmp_path):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    candidate = tool.validate_candidate(trust, receipt, key.read_bytes())
    docker_config = _attestation_docker_config(tmp_path)

    def runner(args, **kwargs):
        role = "migrate" if MIGRATE in args else "web"
        predicate = (
            "https://spdx.dev/Document/v2.3"
            if "spdxjson" in args
            else "https://slsa.dev/provenance/v1"
        )
        matching = signed_statement(receipt, role, predicate)
        statements = [matching]
        if role == "web" and predicate.endswith("provenance/v1"):
            conflicting = json.loads(json.dumps(matching))
            conflicting["predicate"]["buildDefinition"]["externalParameters"][
                "role"
            ] = "migrate"
            statements.append(conflicting)
        envelopes = [
            {
                "payload": base64.b64encode(json.dumps(statement).encode()).decode()
            }
            for statement in statements
        ]
        return subprocess.CompletedProcess(args, 0, json.dumps(envelopes), "")

    with pytest.raises(tool.CandidateVerificationError, match="signed candidate contract"):
        tool.verify_attestations(
            candidate, key.read_bytes(), docker_config, runner=runner
        )


def test_provenance_rejects_unrelated_decoy_dependency_carrying_trusted_h(tmp_path):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    candidate = tool.validate_candidate(trust, receipt, key.read_bytes())
    docker_config = _attestation_docker_config(tmp_path)

    def runner(args, **kwargs):
        role = "migrate" if MIGRATE in args else "web"
        predicate = (
            "https://spdx.dev/Document/v2.3"
            if "spdxjson" in args
            else "https://slsa.dev/provenance/v1"
        )
        statement = signed_statement(receipt, role, predicate)
        if role == "web" and predicate.endswith("provenance/v1"):
            statement["predicate"]["buildDefinition"]["resolvedDependencies"] = [
                {"uri": "git+https://attacker.invalid/wrong", "digest": {"gitCommit": "c" * 40}},
                {"digest": {"gitCommit": H}},
            ]
        payload = base64.b64encode(json.dumps(statement).encode()).decode()
        return subprocess.CompletedProcess(
            args, 0, json.dumps([{"payload": payload}]), ""
        )

    with pytest.raises(tool.CandidateVerificationError, match="signed candidate contract"):
        tool.verify_attestations(
            candidate, key.read_bytes(), docker_config, runner=runner
        )


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        "[]",
        "[{}]",
        json.dumps([{"payload": base64.b64encode(b"[]").decode()}]),
        json.dumps(
            [
                {
                    "payload": base64.b64encode(
                        b'{"_type":"https://in-toto.io/Statement/v1",'
                        b'"predicateType":"x","subject":[],"predicate":{},'
                        b'"predicate":{}}'
                    ).decode()
                }
            ]
        ),
    ],
)
def test_cosign_result_rejects_ambiguous_or_malformed_envelopes(raw):
    tool = load_tool()

    with pytest.raises(tool.CandidateVerificationError):
        tool._parse_cosign_envelopes(raw)


def test_verification_summary_contains_identity_hashes_but_no_credentials(
    tmp_path, monkeypatch
):
    tool, trust_path, evidence, docker_config, _, _, credential = (
        format_exact_signed_fixture(tmp_path)
    )
    monkeypatch.setattr(tool, "verify_receipt_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        tool,
        "verify_attestations",
        lambda *args, **kwargs: {
            "verified_predicates": [
                "migrate:provenance", "migrate:sbom",
                "web:provenance", "web:sbom",
            ]
        },
    )

    result = tool.verify_files(trust_path, evidence, docker_config)
    rendered = json.dumps(result, sort_keys=True)

    assert credential not in rendered
    assert "credential-leak-canary" not in rendered


def test_input_swaps_cannot_change_validated_key_or_emitted_snapshot_hashes(
    tmp_path, monkeypatch
):
    tool, trust_path, evidence, docker_config, _, _, _ = (
        format_exact_signed_fixture(tmp_path)
    )
    trust_bytes = trust_path.read_bytes()
    receipt_bytes = (evidence / "candidate-receipt.json").read_bytes()
    signature_bytes = (evidence / "candidate-receipt.sig").read_bytes()
    key_bytes = (evidence / "kms-public.pem").read_bytes()
    manifest_bytes = (evidence / "SHA256SUMS.json").read_bytes()

    def swap_after_snapshot(receipt, signature, public_key, _docker_config, **kwargs):
        assert receipt == receipt_bytes
        assert signature == signature_bytes
        assert public_key == key_bytes
        trust_path.write_text("{}", encoding="utf-8")
        (evidence / "candidate-receipt.json").write_text("{}", encoding="utf-8")
        (evidence / "candidate-receipt.sig").write_text("bad", encoding="utf-8")
        (evidence / "kms-public.pem").write_text("substituted key", encoding="utf-8")

    monkeypatch.setattr(tool, "verify_receipt_signature", swap_after_snapshot)
    monkeypatch.setattr(
        tool,
        "verify_attestations",
        lambda *args, **kwargs: {
            "verified_predicates": [
                "migrate:provenance", "migrate:sbom",
                "web:provenance", "web:sbom",
            ]
        },
    )
    snapshot = tmp_path / "docker-snapshot"
    result = tool.verify_files(
        trust_path,
        evidence,
        docker_config,
        docker_config_snapshot=snapshot,
    )

    assert result["trust_sha256"] == hashlib.sha256(trust_bytes).hexdigest()
    assert result["receipt_sha256"] == hashlib.sha256(receipt_bytes).hexdigest()
    assert result["receipt_signature_sha256"] == hashlib.sha256(signature_bytes).hexdigest()
    assert result["evidence_manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    assert result["kms_public_key_sha256"] == hashlib.sha256(key_bytes).hexdigest()
    assert "docker-snapshot" not in json.dumps(result)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink retarget regression")
def test_docker_config_symlink_retarget_cannot_change_cosign_snapshot(tmp_path, monkeypatch):
    tool, trust_path, evidence, source, _, _, _ = format_exact_signed_fixture(
        tmp_path
    )
    original = (source / "config.json").read_bytes()
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    (attacker / "config.json").write_text(
        json.dumps(
            {
                "auths": {
                    "us-east4-docker.pkg.dev": {
                        "auth": base64.b64encode(b"user:attacker").decode()
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (attacker / "config.json").chmod(0o600)
    snapshot = tmp_path / "docker-snapshot"

    def retarget_then_verify(receipt, signature, public_key, active_config, **kwargs):
        (source / "config.json").unlink()
        source.rmdir()
        source.symlink_to(attacker, target_is_directory=True)
        assert active_config == snapshot
        assert (active_config / "config.json").read_bytes() == original

    monkeypatch.setattr(tool, "verify_receipt_signature", retarget_then_verify)
    monkeypatch.setattr(
        tool,
        "verify_attestations",
        lambda *args, **kwargs: {
            "verified_predicates": [
                "migrate:provenance", "migrate:sbom",
                "web:provenance", "web:sbom",
            ]
        },
    )
    tool.verify_files(
        trust_path,
        evidence,
        source,
        docker_config_snapshot=snapshot,
    )


def test_registry_native_retention_resolution_can_bind_the_exact_digest(tmp_path):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    receipt["subjects"][0]["retention_evidence"]["registry_resolution"] = (
        "projects/example/locations/us-east4/repositories/containers/"
        "dockerImages/web/versions/sha256:" + "1" * 64
    )

    tool.validate_candidate(trust, receipt, key.read_bytes())


@pytest.mark.parametrize(
    "config",
    [
        {"credsStore": "desktop"},
        {"auths": {}, "HttpHeaders": {"User-Agent": "extra"}},
        {"auths": {"registry": {"identitytoken": "secret"}}},
    ],
)
def test_private_docker_config_has_a_closed_file_only_contract(tmp_path, config):
    tool = load_tool()
    directory = tmp_path / "docker"
    directory.mkdir(mode=0o700)
    path = directory / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    with pytest.raises(tool.CandidateVerificationError):
        tool.validate_docker_config(directory)
