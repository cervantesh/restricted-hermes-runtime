"""HRH mode planning and bounded published-candidate acquisition.

Planning consumes only HRH-related argv tokens and validated marker headers.
Published acquisition delegates evidence parsing and signature checks to the
closed U1 verifier, then owns the published marker and local image identity.
Backup authority remains separate. A plan is transient, never persisted.

Source delivery remains the default. Published acquisition is possible only
on explicit init/restore (including init-based incomplete-state resume).
Returning a plan neither verifies its paths nor authorizes PHI or deployment.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
from types import ModuleType
from typing import Any, Callable, Iterable, Mapping


SOURCE_MARKER_SCHEMA = "restricted-synthetic-clinical-staging.v1"
PUBLISHED_MARKER_SCHEMA = "restricted-synthetic-clinical-staging-published.v1"
CREATION_COMMANDS = frozenset({"init", "restore"})
ORDINARY_COMMANDS = frozenset({
    "up", "status", "stop", "backup", "destroy", "renew-tls", "refresh-policy", "reset",
})
PUBLISHED_FLAGS = ("--hrh-trust", "--hrh-evidence", "--hrh-docker-config")
_FLAGS = frozenset({"--hrh-root", "--hrh-mode", *PUBLISHED_FLAGS})
_MODES = frozenset({"source-build", "published"})
_RESUMABLE = frozenset({"initializing", "finalizing"})
_LIFECYCLES = _RESUMABLE | {"recovering", "ready", "stopped", "renewing_tls", "tls_prepared"}


class ModeError(ValueError):
    """Mode or input authority is missing, ambiguous, or forbidden."""


@dataclass(frozen=True)
class PublishedInputs:
    # Acquisition paths, especially the credential directory, are not evidence.
    trust: Path = field(repr=False)
    evidence: Path = field(repr=False)
    docker_config: Path = field(repr=False)


@dataclass(frozen=True)
class HRHModePlan:
    command: str
    mode: str
    source_root: Path | None = field(default=None, repr=False)
    published_inputs: PublishedInputs | None = field(default=None, repr=False)

    @property
    def overlay(self) -> str:
        return "compose.source-build.yaml" if self.mode == "source-build" else "compose.published-hrh.yaml"

    @property
    def build_hrh(self) -> bool:
        """Delivery policy, not an instruction to build on ordinary commands."""
        return self.mode == "source-build"

    @property
    def acquire_hrh(self) -> bool:
        return self.mode == "published" and self.command in CREATION_COMMANDS

    @property
    def compose_pull_policy(self) -> str | None:
        # None means preserve existing source behavior, not a new pull default.
        return "never" if self.mode == "published" else None


@dataclass(frozen=True)
class PublishedAcquisition:
    candidate: dict[str, Any]
    effective_images: dict[str, dict[str, Any]]
    verification: dict[str, Any]
    evidence_files: dict[str, bytes] = field(repr=False)
    trust_bytes: bytes = field(repr=False)


_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_PUBLISHED_MARKER_KEYS = {
    "schema", "synthetic_only", "project", "state_dir", "state_id",
    "compose_env_sha256", "lifecycle", "runtime_head", "runtime_tree",
    "volumes", "hrh_candidate", "effective_images",
}
_CANDIDATE_KEYS = {
    "clinical_contract_revision", "build_source_revision", "platform",
    "publisher_identity", "kms_key_version", "kms_public_key_sha256",
    "subjects", "trust_sha256", "receipt_sha256", "receipt_signature_sha256",
    "evidence_manifest_sha256", "verification_sha256",
}
_IMAGE_KEYS = {"subject", "image_id", "repo_digest", "platform"}


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"duplicate {option_string} is ambiguous")
        setattr(namespace, self.dest, values)


def add_creation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hrh-mode", choices=("source-build", "published"), action=Once)
    for flag in PUBLISHED_FLAGS:
        parser.add_argument(flag, type=Path, action=Once)


def add_root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hrh-root", type=Path, action=Once)


def mode_tokens(args: argparse.Namespace) -> list[str]:
    values = ["--hrh-root", str(args.hrh_root)] if args.hrh_root is not None else []
    if getattr(args, "hrh_mode", None) is not None:
        values += ["--hrh-mode", args.hrh_mode]
    for flag in PUBLISHED_FLAGS:
        value = getattr(args, flag[2:].replace("-", "_"), None)
        if value is not None:
            values += [flag, str(value)]
    return values


def persisted_plan(command: str, root: Path | None, marker: Mapping[str, Any], environment: Mapping[str, str]) -> HRHModePlan:
    arguments = ["--hrh-root", str(root)] if root is not None else ()
    return plan_hrh_mode(command, arguments, marker_schema=marker["schema"], marker_lifecycle=marker["lifecycle"], environment=environment)


def compose_arguments(plan: HRHModePlan, arguments: Iterable[str]) -> tuple[str, ...]:
    values = tuple(arguments)
    if plan.mode != "published" or not values or values[0] != "up":
        return values
    if "--pull" in values:
        index = values.index("--pull")
        if index + 1 >= len(values) or values[index + 1] != "never" or values.count("--pull") != 1:
            raise ModeError("published Compose start requires exactly --pull never")
        return values
    return ("up", "--pull", "never", *values[1:])


def _verifier(runtime: Path) -> ModuleType:
    path = runtime / "tools" / "verify_hrh_published_candidate.py"
    spec = importlib.util.spec_from_file_location("_clinical_hrh_candidate_verifier", path)
    if spec is None or spec.loader is None:
        raise ModeError("published verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_directory(parent: Path, prefix: str) -> Path:
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = parent / f"{prefix}{secrets.token_hex(8)}"
    value.mkdir(mode=0o700)
    if os.name != "nt":
        value.chmod(0o700)
    return value


def _reconcile_acquisition_orphans(parent: Path, prefix: str) -> None:
    expression = re.compile(rf"^{re.escape(prefix)}[a-f0-9]{{16}}$")
    candidates = [path for path in parent.iterdir() if expression.fullmatch(path.name)] if parent.exists() else []
    if len(candidates) > 8:
        raise ModeError("too many abandoned published-acquisition snapshots")
    for candidate in candidates:
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or (os.name != "nt" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700)):
            raise ModeError("abandoned published-acquisition snapshot is unsafe")
        for root, directories, files in os.walk(candidate, followlinks=False):
            for name in (*directories, *files):
                if (Path(root) / name).is_symlink():
                    raise ModeError("abandoned published-acquisition snapshot contains a symlink")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ModeError("platform cannot safely clean acquisition snapshots")
        shutil.rmtree(candidate)


def _write_snapshot(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    if os.name != "nt":
        path.chmod(0o600)


def _run(runner: Callable[..., subprocess.CompletedProcess[str]], args: list[str], *, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return runner(args, text=True, capture_output=True, check=False, timeout=1200, env=dict(env))


def _inspect_image(raw: str, subject: str) -> dict[str, Any]:
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ModeError("published image inspection is malformed") from exc
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise ModeError("published image inspection is ambiguous")
    item = values[0]
    image_id, repo_digests = item.get("Id"), item.get("RepoDigests")
    platform = {"os": item.get("Os"), "architecture": item.get("Architecture")}
    if (
        not isinstance(image_id, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id)
        or not isinstance(repo_digests, list) or subject not in repo_digests
        or platform != {"os": "linux", "architecture": "amd64"}
    ):
        raise ModeError("pulled image does not match the approved subject and platform")
    return {"subject": subject, "image_id": image_id, "repo_digest": subject, "platform": platform}


def verify_effective_containers(marker: Mapping[str, Any], containers: Mapping[str, Mapping[str, Any]],
                                *, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> None:
    for service in ("hrh", "hrh-migrate"):
        expected, container = marker["effective_images"][service], containers.get(service, {})
        if container.get("Image") != expected["image_id"] or container.get("Config", {}).get("Image") != expected["subject"]:
            raise ModeError("published HRH container identity differs from initialized receipt")
        safe = ("PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
        result = _run(runner, ["docker", "image", "inspect", expected["subject"]], env={key: os.environ[key] for key in safe if key in os.environ})
        if result.returncode or _inspect_image(result.stdout, expected["subject"]) != expected:
            raise ModeError("published HRH local image identity differs from initialized receipt")


def acquire_published_candidate(
    runtime: Path,
    inputs: PublishedInputs,
    snapshot_parent: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    verifier: ModuleType | None = None,
    snapshot_key: str = "candidate",
) -> PublishedAcquisition:
    """Verify and pull a candidate while one run-owned credential snapshot exists."""
    verifier = verifier or _verifier(runtime)
    if not re.fullmatch(r"[a-z0-9]{1,64}", snapshot_key):
        raise ModeError("published acquisition snapshot key is invalid")
    prefix = f".published-acquire-{snapshot_key}-"
    _reconcile_acquisition_orphans(snapshot_parent, prefix)
    run = _private_directory(snapshot_parent, prefix)
    try:
        trust_bytes = verifier._read_regular_snapshot(inputs.trust, "trust declaration")
        evidence_files = verifier.read_evidence_snapshot(inputs.evidence)
        trust = verifier._parse_snapshot(trust_bytes, "trust declaration")
        evidence = run / "evidence"
        _write_snapshot(run / "trust.json", trust_bytes)
        for name, data in evidence_files.items():
            _write_snapshot(evidence / name, data)
        docker_config = run / "docker"
        verification = verifier.verify_files(
            run / "trust.json", evidence, inputs.docker_config,
            docker_config_snapshot=docker_config, runner=runner,
        )
        candidate = verifier.validate_candidate(
            trust,
            verifier._parse_snapshot(evidence_files["candidate-receipt.json"], "candidate receipt"),
            evidence_files["kms-public.pem"],
        )
        verification_bytes = verifier.canonical_verification_bytes(verification)
        if verification["subjects"] != candidate["trust"]["subjects"]:
            raise ModeError("verification subjects differ from independent trust")
        env = verifier.sealed_docker_environment()
        env["DOCKER_CONFIG"] = str(docker_config)
        effective: dict[str, dict[str, Any]] = {}
        for role, service in (("web", "hrh"), ("migrate", "hrh-migrate")):
            subject = verification["subjects"][role]
            result = _run(runner, ["docker", "image", "pull", subject], env=env)
            if result.returncode:
                raise ModeError("published image pull failed")
            result = _run(runner, ["docker", "image", "inspect", subject], env=env)
            if result.returncode:
                raise ModeError("published image inspection failed")
            effective[service] = _inspect_image(result.stdout, subject)
        candidate_identity = {
            key: candidate["trust"][key]
            for key in (
                "clinical_contract_revision", "build_source_revision", "platform",
                "publisher_identity", "kms_key_version", "kms_public_key_sha256", "subjects",
            )
        }
        candidate_identity.update({
            key: verification[key]
            for key in (
                "trust_sha256", "receipt_sha256", "receipt_signature_sha256",
                "evidence_manifest_sha256",
            )
        })
        candidate_identity["verification_sha256"] = hashlib.sha256(
            verification_bytes
        ).hexdigest()
        return PublishedAcquisition(candidate_identity, effective, verification, evidence_files, trust_bytes)
    except ModeError:
        raise
    except Exception as exc:
        raise ModeError("published candidate acquisition failed") from exc
    finally:
        shutil.rmtree(run)


def new_published_marker(*, project: str, state_dir: Path, state_id: str, env_sha256: str,
                         runtime_head: str, runtime_tree: str, volumes: Mapping[str, str],
                         acquisition: PublishedAcquisition, lifecycle: str = "initializing") -> dict[str, Any]:
    return {
        "schema": PUBLISHED_MARKER_SCHEMA, "synthetic_only": True, "project": project,
        "state_dir": str(state_dir.resolve()), "state_id": state_id,
        "compose_env_sha256": env_sha256, "lifecycle": lifecycle,
        "runtime_head": runtime_head, "runtime_tree": runtime_tree,
        "volumes": dict(volumes), "hrh_candidate": acquisition.candidate,
        "effective_images": acquisition.effective_images,
    }


def validate_published_marker(value: object, *, project: str, state_dir: Path,
                              expected_volumes: Mapping[str, str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _PUBLISHED_MARKER_KEYS:
        raise ModeError("published staging marker has unknown or missing fields")
    candidate, images = value.get("hrh_candidate"), value.get("effective_images")
    valid_hashes = isinstance(candidate, dict) and set(candidate) == _CANDIDATE_KEYS and all(
        isinstance(candidate.get(key), str) and _SHA256.fullmatch(candidate[key])
        for key in ("kms_public_key_sha256", "trust_sha256", "receipt_sha256",
                    "receipt_signature_sha256", "evidence_manifest_sha256", "verification_sha256")
    )
    subjects = candidate.get("subjects") if isinstance(candidate, dict) else None
    valid_candidate = valid_hashes and (
        all(isinstance(candidate.get(key), str) and re.fullmatch(r"[a-f0-9]{40}", candidate[key])
            for key in ("clinical_contract_revision", "build_source_revision"))
        and candidate.get("platform") == {"os": "linux", "architecture": "amd64"}
        and isinstance(candidate.get("publisher_identity"), str)
        and 3 <= len(candidate["publisher_identity"]) <= 254
        and isinstance(candidate.get("kms_key_version"), str)
        and re.fullmatch(r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+", candidate["kms_key_version"])
        and isinstance(subjects, dict) and set(subjects) == {"web", "migrate", "evidence"}
        and all(isinstance(subject, str) and re.fullmatch(r"[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}", subject)
                for subject in subjects.values())
        and subjects["web"] != subjects["migrate"]
    )
    valid_images = isinstance(images, dict) and set(images) == {"hrh", "hrh-migrate"} and all(
        isinstance(item, dict) and set(item) == _IMAGE_KEYS
        and item.get("platform") == {"os": "linux", "architecture": "amd64"}
        and isinstance(item.get("subject"), str) and "@sha256:" in item["subject"]
        and item.get("repo_digest") == item.get("subject")
        and isinstance(item.get("image_id"), str) and re.fullmatch(r"sha256:[a-f0-9]{64}", item["image_id"])
        for item in images.values()
    )
    valid_images = valid_candidate and valid_images and images["hrh"]["subject"] == subjects["web"] and images["hrh-migrate"]["subject"] == subjects["migrate"]
    if not (
        value.get("schema") == PUBLISHED_MARKER_SCHEMA and value.get("synthetic_only") is True
        and value.get("project") == project and value.get("state_dir") == str(state_dir.resolve())
        and value.get("volumes") == dict(expected_volumes)
        and isinstance(value.get("state_id"), str) and re.fullmatch(r"[a-f0-9]{32}", value["state_id"])
        and isinstance(value.get("compose_env_sha256"), str) and _SHA256.fullmatch(value["compose_env_sha256"])
        and value.get("lifecycle") in _LIFECYCLES and valid_candidate and valid_images
    ):
        raise ModeError("published staging marker is invalid")
    return value


def verify_runtime_frame(runtime: Path, shell: Any, *, base_sha: str) -> dict[str, str]:
    runtime = runtime.resolve()
    head = shell.git(runtime, "rev-parse", "HEAD")
    tree = shell.git(runtime, "rev-parse", "HEAD^{tree}")
    try:
        shell.git(runtime, "merge-base", "--is-ancestor", base_sha, head)
    except Exception as exc:
        raise ModeError("runtime does not descend from the frozen staging base") from exc
    if shell.git(runtime, "status", "--porcelain=v1"):
        raise ModeError("runtime worktree must be clean")
    return {"runtime_head": head, "runtime_tree": tree}


def retain_published_evidence(root: Path, acquisition: PublishedAcquisition) -> None:
    target = root / "hrh-published"
    target.mkdir(mode=0o700)
    _write_snapshot(target / "trust.json", acquisition.trust_bytes)
    for name, data in acquisition.evidence_files.items():
        _write_snapshot(target / name, data)
    _write_snapshot(
        target / "verification.json",
        json.dumps(acquisition.verification, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def mode_from_marker_schema(schema: str | None) -> str:
    """Discriminate an already-validated marker, never infer from other fields."""
    if schema == SOURCE_MARKER_SCHEMA:
        return "source-build"
    if schema == PUBLISHED_MARKER_SCHEMA:
        return "published"
    raise ModeError("closed marker schema is missing or unsupported")


def _parse_options(command: str, arguments: Iterable[str]) -> dict[str, str]:
    tokens = list(arguments)
    options: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not isinstance(token, str):
            raise ModeError("HRH option must be a string")
        option, separator, value = token.partition("=")
        if option not in _FLAGS:
            raise ModeError("unsupported HRH option")
        if option in options:
            raise ModeError(f"duplicate {option} is ambiguous")
        if command in ORDINARY_COMMANDS and option != "--hrh-root":
            raise ModeError(f"ordinary command rejects {option}; marker is authoritative")
        if not separator:
            index += 1
            value = tokens[index] if index < len(tokens) else None
        if not isinstance(value, str) or not value.strip() or value.startswith("--") or "\x00" in value:
            raise ModeError(f"{option} requires one explicit value")
        options[option] = value
        index += 1
    return options


def plan_hrh_mode(
    command: str,
    arguments: Iterable[str] = (),
    *,
    marker_schema: str | None = None,
    marker_lifecycle: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> HRHModePlan:
    """Resolve a transient plan without consulting environment or filesystem.

    Published plans require an explicit ``environment`` mapping to reject a
    forbidden HRH source-root declaration. It supplies no defaults or inputs.
    The integrator must pass its actual environment and validated marker header;
    this pure helper deliberately does not discover either itself.
    """
    if not isinstance(command, str) or command not in CREATION_COMMANDS | ORDINARY_COMMANDS:
        raise ModeError("unsupported clinical command")
    options = _parse_options(command, arguments)
    persisted = mode_from_marker_schema(marker_schema) if marker_schema is not None else None
    if command in ORDINARY_COMMANDS:
        mode = mode_from_marker_schema(marker_schema)
    else:
        selected = options.get("--hrh-mode")
        if selected is not None and selected not in _MODES:
            raise ModeError("--hrh-mode must be exactly source-build or published")
        if persisted == "published" and selected != "published":
            raise ModeError("published resume requires explicit --hrh-mode published")
        mode = selected or "source-build"
        if persisted is not None and persisted != mode:
            raise ModeError("selected mode differs from the authoritative marker")

    root = options.get("--hrh-root")
    if mode == "source-build":
        if any(flag in options for flag in PUBLISHED_FLAGS):
            raise ModeError("source-build rejects published acquisition inputs")
        if root is None:
            raise ModeError("source-build requires --hrh-root")
        return HRHModePlan(command, mode, source_root=Path(root))

    if not isinstance(environment, Mapping):
        raise ModeError("published planning requires an explicit environment mapping")
    if root is not None or "CLINICAL_HRH_ROOT" in environment:
        raise ModeError("published mode rejects any HRH root argument or CLINICAL_HRH_ROOT")
    if command == "reset":
        raise ModeError("published reset is unsupported; destroy then use explicit published init/restore")
    if command == "up":
        if not isinstance(marker_lifecycle, str) or marker_lifecycle not in _LIFECYCLES:
            raise ModeError("published up requires a supplied validated marker lifecycle")
        if marker_lifecycle in _RESUMABLE:
            raise ModeError("published incomplete state requires explicit init-based resume with fresh inputs")
    if command == "init" and persisted == "published" and marker_lifecycle not in _RESUMABLE:
        raise ModeError("published init can resume only initializing or finalizing state")
    if command in CREATION_COMMANDS:
        for flag in PUBLISHED_FLAGS:
            if flag not in options:
                raise ModeError(f"published {command} requires {flag}")
        inputs = PublishedInputs(*(Path(options[flag]) for flag in PUBLISHED_FLAGS))
        return HRHModePlan(command, mode, published_inputs=inputs)
    return HRHModePlan(command, mode)
