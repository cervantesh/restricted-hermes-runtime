from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "verify_hrh_published_candidate.py"
WEB = (
    "us-east4-docker.pkg.dev/health-record-hub-shared/containers/web@sha256:" + "1" * 64
)
MIGRATE = (
    "us-east4-docker.pkg.dev/health-record-hub-shared/containers/migrate@sha256:"
    + "2" * 64
)
C = "a" * 40
H = "b" * 40
PUBLISHER = "forgejo-deployer@aali-forgejo.iam.gserviceaccount.com"
KMS = "projects/health-record-hub-shared/locations/us-east4/keyRings/hrh-shared/cryptoKeys/clinical/cryptoKeyVersions/1"


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
        "schema_version": "restricted-runtime-hrh-trust.v1",
        "clinical_contract_revision": C,
        "build_source_revision": H,
        "platform": {"os": "linux", "architecture": "amd64"},
        "publisher_identity": PUBLISHER,
        "kms_key_version": KMS,
        "kms_public_key_sha256": key_hash,
        "subjects": {"web": WEB, "migrate": MIGRATE},
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
        retention = {
            "tag": image.split("@")[0] + f":keep-clinical-{H}-{role}",
            "subject": image,
            "registry_resolution": image,
        }
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
                "retention_tag": f"keep-clinical-{H}-{role}",
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
                "resolvedDependencies": [{"digest": {"gitCommit": H}}],
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

    assert result["verified_predicates"] == 4
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
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    trust_path = tmp_path / "trust.json"
    receipt_path = tmp_path / "receipt.json"
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    docker_config = tmp_path / "docker"
    docker_config.mkdir(mode=0o700)
    credential = base64.b64encode(b"user:never-publish-this").decode()
    config = docker_config / "config.json"
    config.write_text(
        json.dumps({"auths": {"us-east4-docker.pkg.dev": {"auth": credential}}}),
        encoding="utf-8",
    )
    if os.name != "nt":
        config.chmod(0o600)
    monkeypatch.setattr(
        tool, "verify_attestations", lambda *args, **kwargs: {"verified_predicates": 4}
    )

    result = tool.verify_files(trust_path, receipt_path, key, docker_config)
    rendered = json.dumps(result, sort_keys=True)

    assert result["git_ancestry_recomputed"] is False
    assert result["phi_authorized"] is False
    assert credential not in rendered
    assert "never-publish-this" not in rendered


def test_input_swaps_cannot_change_validated_key_or_emitted_snapshot_hashes(
    tmp_path, monkeypatch
):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    trust_path = tmp_path / "trust.json"
    receipt_path = tmp_path / "receipt.json"
    trust_bytes = json.dumps(trust, sort_keys=True).encode()
    receipt_bytes = json.dumps(receipt, sort_keys=True).encode()
    key_bytes = key.read_bytes()
    trust_path.write_bytes(trust_bytes)
    receipt_path.write_bytes(receipt_bytes)
    docker_config = tmp_path / "docker"
    docker_config.mkdir(mode=0o700)
    config = docker_config / "config.json"
    config.write_text(
        json.dumps(
            {
                "auths": {
                    "us-east4-docker.pkg.dev": {
                        "auth": base64.b64encode(b"user:original").decode()
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        config.chmod(0o600)

    def swap_after_snapshot(candidate, mounted_key, _docker_config):
        assert mounted_key == key_bytes
        trust_path.write_text("{}", encoding="utf-8")
        receipt_path.write_text("{}", encoding="utf-8")
        key.write_text("substituted key", encoding="utf-8")
        return {"verified_predicates": 4}

    monkeypatch.setattr(tool, "verify_attestations", swap_after_snapshot)
    snapshot = tmp_path / "docker-snapshot"
    result = tool.verify_files(
        trust_path,
        receipt_path,
        key,
        docker_config,
        docker_config_snapshot=snapshot,
    )

    assert result["trust_declaration_sha256"] == hashlib.sha256(trust_bytes).hexdigest()
    assert result["receipt_sha256"] == hashlib.sha256(receipt_bytes).hexdigest()
    assert result["public_key_sha256"] == hashlib.sha256(key_bytes).hexdigest()
    assert result["subjects"] == trust["subjects"]
    assert "docker-snapshot" not in json.dumps(result)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink retarget regression")
def test_docker_config_symlink_retarget_cannot_change_cosign_snapshot(tmp_path, monkeypatch):
    tool = load_tool()
    trust, receipt, key = fixture(tmp_path)
    trust_path = tmp_path / "trust.json"
    receipt_path = tmp_path / "receipt.json"
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    source = tmp_path / "docker-source"
    source.mkdir(mode=0o700)
    original = json.dumps(
        {
            "auths": {
                "us-east4-docker.pkg.dev": {
                    "auth": base64.b64encode(b"user:original").decode()
                }
            }
        }
    ).encode()
    (source / "config.json").write_bytes(original)
    (source / "config.json").chmod(0o600)
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

    def retarget_then_verify(candidate, public_key, active_config):
        (source / "config.json").unlink()
        source.rmdir()
        source.symlink_to(attacker, target_is_directory=True)
        assert active_config == snapshot
        assert (active_config / "config.json").read_bytes() == original
        return {"verified_predicates": 4}

    monkeypatch.setattr(tool, "verify_attestations", retarget_then_verify)
    tool.verify_files(
        trust_path,
        receipt_path,
        key,
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
