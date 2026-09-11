#!/usr/bin/env python3
"""Verify an HRH candidate against an independently selected trust declaration.

This consumer deliberately has no Health-Record-Hub repository dependency. It
verifies the publisher's signed claims; it does not recompute Git ancestry.
Registry credentials are accepted only through a private Docker config mount.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


COSIGN_IMAGE = "gcr.io/projectsigstore/cosign:v2.5.3@sha256:920845e07017a9abe50a0e5a4b883cbc761228691ea80ebb16661b522e71a0bd"
TRUST_SCHEMA = "restricted-runtime-hrh-trust.v1"
TRUST_KEYS = {
    "schema_version", "clinical_contract_revision", "build_source_revision",
    "platform", "publisher_identity", "kms_key_version",
    "kms_public_key_sha256", "subjects",
}
SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"(?P<repository>[a-z0-9][a-z0-9._/-]*)@sha256:(?P<digest>[0-9a-f]{64})")
KMS_VERSION = re.compile(
    r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+"
)
PREDICATES = {
    "sbom": ("https://spdx.dev/Document/v2.3", "spdxjson"),
    "provenance": ("https://slsa.dev/provenance/v1", "slsaprovenance1"),
}
SAFE_DOCKER_ENV = (
    "PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
)


class CandidateVerificationError(RuntimeError):
    """The selected candidate cannot be proven from the closed inputs."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateVerificationError(message)


def _mapping(value: object, message: str) -> dict[str, Any]:
    _require(isinstance(value, dict), message)
    return value


def _closed(value: dict[str, Any], keys: set[str], name: str) -> None:
    _require(set(value) == keys, f"{name} fields must be exactly {sorted(keys)}")


def _image(value: object, role: str) -> re.Match[str]:
    _require(isinstance(value, str), f"{role} subject must be a string")
    match = IMAGE.fullmatch(value)
    _require(match is not None, f"{role} subject must be an exact sha256 reference")
    _require(match.group("repository").endswith("/" + role), f"{role} subject repository must end in /{role}")
    return match


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_candidate(trust_value: object, receipt_value: object, public_key: bytes) -> dict[str, Any]:
    """Validate closed identity metadata before any registry operation."""
    trust = _mapping(trust_value, "trust declaration must be an object")
    _closed(trust, TRUST_KEYS, "trust declaration")
    _require(trust["schema_version"] == TRUST_SCHEMA, "unsupported trust declaration schema")
    _require(isinstance(trust["clinical_contract_revision"], str) and SHA.fullmatch(trust["clinical_contract_revision"]), "trust C must be a full lowercase commit SHA")
    _require(isinstance(trust["build_source_revision"], str) and SHA.fullmatch(trust["build_source_revision"]), "trust H must be a full lowercase commit SHA")
    platform = _mapping(trust["platform"], "trust platform must be an object")
    _closed(platform, {"os", "architecture"}, "trust platform")
    _require(platform == {"os": "linux", "architecture": "amd64"}, "trust platform must be linux/amd64")
    _require(isinstance(trust["publisher_identity"], str) and 3 <= len(trust["publisher_identity"]) <= 254, "trust publisher identity is invalid")
    _require(isinstance(trust["kms_key_version"], str) and KMS_VERSION.fullmatch(trust["kms_key_version"]), "trust KMS key must be an exact version")
    _require(isinstance(trust["kms_public_key_sha256"], str) and SHA256.fullmatch(trust["kms_public_key_sha256"]), "trust public-key SHA-256 is invalid")
    subjects = _mapping(trust["subjects"], "trust subjects must be an object")
    _closed(subjects, {"web", "migrate"}, "trust subjects")
    for role in ("web", "migrate"):
        _image(subjects[role], role)
    _require(subjects["web"] != subjects["migrate"], "web and migrate subjects must be distinct")
    _require(_hash(public_key) == trust["kms_public_key_sha256"], "public key does not match the separate trust declaration")

    receipt = _mapping(receipt_value, "candidate receipt must be an object")
    _closed(receipt, {"schema_version", "clinical_contract_revision", "build_source_revision", "signing", "phi_authorized", "deployment_conformant", "subjects"}, "candidate receipt")
    _require(receipt.get("schema_version") == 1, "unsupported candidate receipt schema")
    _require(receipt.get("phi_authorized") is False, "candidate receipt must state phi_authorized=false")
    _require(receipt.get("deployment_conformant") is False, "candidate receipt must state deployment_conformant=false")
    _require(receipt.get("clinical_contract_revision") == trust["clinical_contract_revision"], "receipt C differs from trust declaration")
    _require(receipt.get("build_source_revision") == trust["build_source_revision"], "receipt H differs from trust declaration")
    signing = _mapping(receipt.get("signing"), "receipt signing metadata is required")
    _closed(signing, {"publisher_identity", "kms_key_version", "kms_public_key_sha256", "workflow_run_url"}, "receipt signing metadata")
    for field in ("publisher_identity", "kms_key_version", "kms_public_key_sha256"):
        _require(signing.get(field) == trust[field], f"receipt {field} differs from trust declaration")
    _require(isinstance(signing.get("workflow_run_url"), str) and signing["workflow_run_url"].startswith("https://"), "receipt workflow run URL must be HTTPS")

    receipt_subjects = receipt.get("subjects")
    _require(isinstance(receipt_subjects, list) and len(receipt_subjects) == 2, "receipt must contain exactly two subjects")
    by_role: dict[str, dict[str, Any]] = {}
    for value in receipt_subjects:
        item = _mapping(value, "receipt subject must be an object")
        _closed(item, {"role", "image", "platform", "runtime_identity", "material_evidence", "retention_evidence", "retention_tag", "sbom", "provenance"}, "receipt subject")
        role = item.get("role")
        _require(role in {"web", "migrate"} and role not in by_role, "receipt roles must be exactly web and migrate")
        by_role[role] = item
    _require(set(by_role) == {"web", "migrate"}, "receipt roles must be exactly web and migrate")
    for role, expected_identity in (("web", "10001:10001"), ("migrate", "10002:10002")):
        item = by_role[role]
        _image(item.get("image"), role)
        _require(item.get("image") == subjects[role], f"receipt {role} subject differs from trust declaration")
        _require(item.get("platform") == platform, f"receipt {role} platform differs from trust declaration")
        identity = _mapping(item.get("runtime_identity"), f"receipt {role} runtime identity is required")
        _closed(identity, {"declared_user", "effective_uid_gid"}, f"receipt {role} runtime identity")
        _require(identity.get("declared_user") == expected_identity and identity.get("effective_uid_gid") == expected_identity, f"receipt {role} runtime identity is invalid")
        material = _mapping(item.get("material_evidence"), f"receipt {role} material evidence is required")
        required_materials = {"apk_inventory_sha256"}
        required_materials |= {"package_lock_sha256", "npm_integrity_basis_sha256"} if role == "web" else {"migrations_tree_sha256", "run_migrations_sha256"}
        _closed(material, required_materials, f"receipt {role} material evidence")
        _require(all(isinstance(material.get(name), str) and SHA256.fullmatch(material[name]) for name in required_materials), f"receipt {role} material evidence is incomplete")
        retention = _mapping(item.get("retention_evidence"), f"receipt {role} retention evidence is required")
        _closed(retention, {"tag", "subject", "registry_resolution"}, f"receipt {role} retention evidence")
        expected_tag = item["image"].split("@", 1)[0] + f":keep-clinical-{trust['build_source_revision']}-{role}"
        expected_digest = item["image"].split("@", 1)[1]
        resolution = retention.get("registry_resolution")
        _require(
            retention.get("tag") == expected_tag
            and retention.get("subject") == item["image"]
            and isinstance(resolution, str)
            and resolution.endswith(expected_digest),
            f"receipt {role} retention evidence does not bind the exact subject",
        )
        _require(item.get("retention_tag") == expected_tag.rsplit(":", 1)[1], f"receipt {role} retention tag is invalid")
        for field, (predicate, _) in PREDICATES.items():
            attestation = _mapping(item.get(field), f"receipt {role} {field} is required")
            _closed(attestation, {"subject", "predicate_type", "verification"}, f"receipt {role} {field}")
            _require(attestation.get("subject") == item["image"] and attestation.get("predicate_type") == predicate, f"receipt {role} {field} does not bind the exact subject and purpose")
            _require(isinstance(attestation.get("verification"), str) and attestation["verification"], f"receipt {role} {field} verification marker is required")
    return {"trust": trust, "receipt": receipt, "subjects": by_role, "public_key_sha256": _hash(public_key)}


def validate_docker_config(directory: Path, *, registries: set[str] | None = None) -> bytes:
    _require(not directory.is_symlink(), "Docker config boundary must not be a symlink")
    directory = directory.resolve()
    _require(directory.is_dir(), "Docker config boundary must be a real directory")
    _require({path.name for path in directory.iterdir()} == {"config.json"}, "Docker config boundary must contain only config.json")
    config = directory / "config.json"
    _require(config.is_file() and not config.is_symlink(), "Docker config boundary requires a regular config.json")
    if os.name != "nt":
        _require(directory.stat().st_uid == os.getuid() and config.stat().st_uid == os.getuid(), "Docker config boundary must be owned by the current user")
        _require(stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0, "Docker config directory must not grant group/other access")
        _require(stat.S_IMODE(config.stat().st_mode) & 0o077 == 0, "Docker config file must not grant group/other access")
    try:
        config_bytes = _read_regular_snapshot(config, "Docker config")
        value = json.loads(config_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateVerificationError("Docker config is unreadable") from exc
    root = _mapping(value, "Docker config must be an object")
    _closed(root, {"auths"}, "Docker config")
    auths = _mapping(root["auths"], "Docker config auths must be an object")
    for registry, entry_value in auths.items():
        _require(isinstance(registry, str) and registry and "://" not in registry, "Docker registry name is invalid")
        entry = _mapping(entry_value, "Docker registry credentials must be an object")
        _closed(entry, {"auth"}, "Docker registry credential")
        _require(isinstance(entry["auth"], str) and entry["auth"], "Docker registry auth must be non-empty")
        try:
            decoded = base64.b64decode(entry["auth"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise CandidateVerificationError("Docker registry auth must be valid base64") from exc
        _require(b":" in decoded and len(decoded) > 2, "Docker registry auth must encode username:credential")
    if registries is not None:
        _require(registries == set(auths), "Docker config registries must exactly match approved subject registries")
    return config_bytes


def _materialize_docker_config(config_bytes: bytes, directory: Path) -> Path:
    _require(not directory.exists(), "private Docker config snapshot target already exists")
    directory.mkdir(mode=0o700, parents=False)
    if os.name != "nt":
        directory.chmod(0o700)
    config = directory / "config.json"
    with config.open("xb") as stream:
        stream.write(config_bytes)
    if os.name != "nt":
        config.chmod(0o600)
    return directory


def sealed_docker_environment() -> dict[str, str]:
    return {name: os.environ[name] for name in SAFE_DOCKER_ENV if name in os.environ}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateVerificationError("JSON contains duplicate keys")
        result[key] = value
    return result


def _parse_cosign_envelopes(raw: str) -> list[dict[str, Any]]:
    """Return only the once-decoded outer statement from each Cosign result."""
    try:
        output = json.loads(raw, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise CandidateVerificationError("Cosign verification did not return JSON") from exc
    _require(isinstance(output, list) and output, "Cosign verification must return a non-empty result list")
    statements: list[dict[str, Any]] = []
    for envelope in output:
        _require(isinstance(envelope, dict), "Cosign result envelope must be an object")
        payload = envelope.get("payload")
        _require(isinstance(payload, str) and payload, "Cosign result envelope requires one payload")
        try:
            decoded = base64.b64decode(payload, validate=True).decode("utf-8")
            statement = json.loads(decoded, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
            raise CandidateVerificationError("Cosign result payload is not one base64 JSON statement") from exc
        _require(isinstance(statement, dict), "Cosign payload must decode to one in-toto statement")
        _closed(statement, {"_type", "predicateType", "subject", "predicate"}, "in-toto statement")
        _require(statement["_type"] == "https://in-toto.io/Statement/v1", "Cosign payload has an unsupported statement type")
        _require(isinstance(statement["predicateType"], str), "Cosign statement predicate type is invalid")
        _require(isinstance(statement["subject"], list) and statement["subject"], "Cosign statement subjects are invalid")
        _require(isinstance(statement["predicate"], dict), "Cosign statement predicate is invalid")
        statements.append(statement)
    return statements


def _statement_matches(statement: dict[str, Any], candidate: dict[str, Any], role: str, field: str) -> bool:
    trust, receipt, subject = candidate["trust"], candidate["receipt"], candidate["subjects"][role]
    match = IMAGE.fullmatch(subject["image"])
    assert match is not None
    if statement.get("predicateType") != PREDICATES[field][0]:
        return False
    if not any(item.get("name") == match.group("repository") and item.get("digest", {}).get("sha256") == match.group("digest") for item in statement.get("subject", []) if isinstance(item, dict)):
        return False
    if field == "sbom":
        return True
    predicate = statement.get("predicate", {})
    build = predicate.get("buildDefinition", {})
    external = build.get("externalParameters", {})
    run = predicate.get("runDetails", {}).get("metadata", {}).get("invocationId")
    return (
        external.get("role") == role
        and external.get("platform") == "linux/amd64"
        and external.get("clinical_contract_revision") == trust["clinical_contract_revision"]
        and external.get("build_source_revision") == trust["build_source_revision"]
        and external.get("publisher_identity") == trust["publisher_identity"]
        and external.get("kms_key_version") == trust["kms_key_version"]
        and external.get("kms_public_key_sha256") == trust["kms_public_key_sha256"]
        and external.get("runtime_identity") == subject["runtime_identity"]
        and external.get("material_evidence") == subject["material_evidence"]
        and external.get("retention_evidence") == subject["retention_evidence"]
        and run == receipt["signing"]["workflow_run_url"]
        and any(item.get("digest", {}).get("gitCommit") == trust["build_source_revision"] for item in build.get("resolvedDependencies", []) if isinstance(item, dict))
    )


def verify_attestations(
    candidate: dict[str, Any],
    public_key: bytes,
    docker_config: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Use pinned Cosign and a mounted private Docker config; no token enters argv."""
    registries = {candidate["subjects"][role]["image"].split("/", 1)[0] for role in ("web", "migrate")}
    docker_config_bytes = validate_docker_config(docker_config, registries=registries)
    verified = 0
    with tempfile.TemporaryDirectory(prefix="hrh-candidate-key-") as key_directory_value:
        key_directory = Path(key_directory_value)
        if os.name != "nt":
            key_directory.chmod(0o700)
        key_path = key_directory / "public.pem"
        with key_path.open("xb") as stream:
            stream.write(public_key)
        if os.name != "nt":
            key_path.chmod(0o600)
        config_snapshot = _materialize_docker_config(
            docker_config_bytes, key_directory / "docker"
        )
        mount_config = f"{config_snapshot}:/home/nonroot/.docker:ro"
        mount_key = f"{key_path}:/trust/public.pem:ro"
        for role in ("web", "migrate"):
            subject = candidate["subjects"][role]["image"]
            for field, (_, cosign_type) in PREDICATES.items():
                args = ["docker", "run", "--rm"]
                if hasattr(os, "getuid"):
                    args.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
                args.extend(
                    [
                        "--env", "DOCKER_CONFIG=/home/nonroot/.docker",
                        "--volume", mount_config, "--volume", mount_key,
                        COSIGN_IMAGE, "verify-attestation", "--output", "json",
                        "--key", "/trust/public.pem", "--type", cosign_type,
                        "--check-claims=true", subject,
                    ]
                )
                result = runner(args, text=True, capture_output=True, check=False, timeout=300, env=sealed_docker_environment())
                _require(result.returncode == 0, f"{role} {field} cryptographic verification failed")
                statements = _parse_cosign_envelopes(result.stdout)
                _require(any(_statement_matches(statement, candidate, role, field) for statement in statements), f"{role} {field} verified payload does not bind the exact signed candidate contract")
                verified += 1
    return {"verified_predicates": verified}


def _read_regular_snapshot(path: Path, name: str) -> bytes:
    try:
        before = path.lstat()
        _require(stat.S_ISREG(before.st_mode), f"{name} must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            _require(stat.S_ISREG(opened.st_mode), f"{name} must be a regular file")
            _require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), f"{name} changed while opening")
            return stream.read()
    except OSError as exc:
        raise CandidateVerificationError(f"{name} is unreadable") from exc


def _parse_snapshot(data: bytes, name: str) -> object:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateVerificationError(f"{name} is unreadable") from exc


def verify_files(
    trust_path: Path,
    receipt_path: Path,
    public_key_path: Path,
    docker_config: Path,
    *,
    docker_config_snapshot: Path | None = None,
) -> dict[str, Any]:
    trust_bytes = _read_regular_snapshot(trust_path, "trust declaration")
    receipt_bytes = _read_regular_snapshot(receipt_path, "candidate receipt")
    public_key_bytes = _read_regular_snapshot(public_key_path, "public key")
    candidate = validate_candidate(
        _parse_snapshot(trust_bytes, "trust declaration"),
        _parse_snapshot(receipt_bytes, "candidate receipt"),
        public_key_bytes,
    )
    registries = {
        candidate["subjects"][role]["image"].split("/", 1)[0]
        for role in ("web", "migrate")
    }
    docker_config_bytes = validate_docker_config(docker_config, registries=registries)
    active_docker_config = docker_config
    if docker_config_snapshot is not None:
        active_docker_config = _materialize_docker_config(
            docker_config_bytes, docker_config_snapshot
        )
    result = verify_attestations(candidate, public_key_bytes, active_docker_config)
    return {
        "schema_version": "restricted-runtime-hrh-verification.v1",
        "mode": "published",
        "clinical_contract_revision": candidate["trust"]["clinical_contract_revision"],
        "build_source_revision": candidate["trust"]["build_source_revision"],
        "platform": candidate["trust"]["platform"],
        "publisher_identity": candidate["trust"]["publisher_identity"],
        "kms_key_version": candidate["trust"]["kms_key_version"],
        "public_key_sha256": candidate["public_key_sha256"],
        "subjects": candidate["trust"]["subjects"],
        "receipt_sha256": _hash(receipt_bytes),
        "trust_declaration_sha256": _hash(trust_bytes),
        **result,
        "git_ancestry_recomputed": False,
        "phi_authorized": False,
        "deployment_conformant": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--docker-config", type=Path, required=True)
    parser.add_argument("--docker-config-snapshot", type=Path)
    args = parser.parse_args()
    try:
        result = verify_files(
            args.trust,
            args.receipt,
            args.public_key,
            args.docker_config,
            docker_config_snapshot=args.docker_config_snapshot,
        )
    except (CandidateVerificationError, OSError) as exc:
        print(f"HRH published candidate: DENIED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
