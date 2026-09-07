#!/usr/bin/env python3
"""Synthetic-only operator lifecycle for the composed clinical witness."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


RUNTIME_BASE_SHA = "41464aee8748f857153ba2b47377515d4847d210"
REQUIRED_HRH_SHA = "e30a4f968de6727519f49c08369f561fdf269ec5"
REQUIRED_HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"
HRH_WEB_CANDIDATE_DOCKERFILE = "Dockerfile.web.clinical-candidate"
HRH_MIGRATE_CANDIDATE_DOCKERFILE = "Dockerfile.migrate.clinical-candidate"
HRH_NODE_BASE = "node:24-alpine@sha256:4caaaf42195bcd6f6f3559a413b20cb8f8ad089e231ee874cf7701643966689f"
HRH_MIGRATE_BASE = "alpine:3.21@sha256:f27cad9117495d32d067133afff942cb2dc745dfe9163e949f6bfe8a6a245339"
HRH_CANDIDATE_BASES = {
    HRH_WEB_CANDIDATE_DOCKERFILE: (HRH_NODE_BASE, HRH_NODE_BASE, HRH_NODE_BASE),
    HRH_MIGRATE_CANDIDATE_DOCKERFILE: (HRH_MIGRATE_BASE,),
}
SCHEMA = "restricted-synthetic-clinical-staging.v1"
MARKER_NAME = "staging-state.json"
PROJECT_LABEL = "io.cervantesh.restricted-runtime.project"
STATE_LABEL = "io.cervantesh.restricted-runtime.state-id"
SYNTHETIC_LABEL = "io.cervantesh.restricted-runtime.synthetic-clinical"
PROJECT_RE = re.compile(r"^clinicalstaging[a-z0-9]{1,32}$")
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)", re.MULTILINE | re.IGNORECASE)
COMPOSE_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SAFE_COMPOSE_PROCESS_ENV = (
    "PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
    "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR",
)
VOLUME_KEYS = (
    "mattermost_db", "mattermost_data", "mattermost_tls", "hrh_db",
    "hrh_tls", "hrh_secret", "clinical_config", "clinical_socket",
    "ingress_config", "ingress_outbox", "controller_state",
)
LONG_RUNNING_SERVICES = (
    "mattermost-postgres", "mattermost", "hrh-postgres", "hrh", "hrh-tls",
    "clinical-adapter", "ingress", "operator-proxy",
)
ONE_SHOT_SERVICES = ("hrh-migrate", "clinical-socket-init")
ALLOWED_SERVICES = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES) | {"controller"}
INTERNAL_NETWORK_KEYS = ("mattermost_edge", "mattermost_backend", "hrh_backend", "clinical_upstream")
NETWORK_KEYS = (*INTERNAL_NETWORK_KEYS, "operator_access")
EXPECTED_NETWORK_KEYS_BY_SERVICE = {
    "mattermost-postgres": {"mattermost_backend"},
    "mattermost": {"mattermost_edge", "mattermost_backend"},
    "hrh-postgres": {"hrh_backend"},
    "hrh": {"hrh_backend"},
    "hrh-tls": {"hrh_backend", "clinical_upstream"},
    "clinical-adapter": {"clinical_upstream"},
    "ingress": {"mattermost_edge"},
    "operator-proxy": {"operator_access", "mattermost_edge"},
}
RESTRICTED_CONTAINER_CONTROLS = {
    "clinical-adapter": {
        "user": "restricted-clinical-adapter",
        "uid": 10008,
        "gid": 20007,
        "read_only_mounts": {"/run/clinical-config", "/run/hrh-secret", "/run/hrh-tls"},
        "writable_mounts": {"/run/restricted-clinical"},
    },
    "ingress": {
        "user": "restricted-mattermost-ingress",
        "uid": 10007,
        "gid": 20005,
        "read_only_mounts": {"/run/ingress"},
        "writable_mounts": {
            "/run/restricted-clinical",
            "/var/lib/restricted-mattermost-outbox",
        },
    },
}


class SafetyError(RuntimeError):
    pass


class CommandError(RuntimeError):
    pass


class Shell:
    def run(
        self,
        *args: str,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        if check and result.returncode:
            detail = (result.stdout + result.stderr)[-1600:]
            raise CommandError(f"{args[0]} exited {result.returncode}: {detail}")
        return result

    def git(self, cwd: Path, *args: str) -> str:
        return self.run("git", *args, cwd=cwd).stdout.strip()


def validate_project(project: str) -> str:
    if not PROJECT_RE.fullmatch(project) or project == "clinicalstaging":
        raise SafetyError("project must match clinicalstaging[a-z0-9]{1,32}")
    return project


def validate_state_path(
    path: Path,
    project: str,
    *,
    forbidden_roots: Iterable[Path] = (),
) -> Path:
    validate_project(project)
    if not path.is_absolute():
        raise SafetyError("state path must be absolute")
    resolved = path.resolve()
    if resolved.name != f"{project}.synthetic-clinical-staging":
        raise SafetyError("state path basename must bind the exact project")
    repo = Path(__file__).resolve().parents[2]
    home = Path.home().resolve()
    if resolved in {resolved.anchor and Path(resolved.anchor), repo, home}:
        raise SafetyError("state path is too broad")
    for root in (repo, *(Path(item).resolve() for item in forbidden_roots)):
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise SafetyError("state path must remain outside every repository build context")
    return resolved


def volume_names(project: str) -> dict[str, str]:
    validate_project(project)
    return {key: f"{project}_{key}" for key in VOLUME_KEYS}


def new_marker(
    *,
    project: str,
    state_dir: Path,
    state_id: str,
    env_sha256: str,
    runtime_head: str,
    runtime_tree: str,
    hrh_head: str,
    hrh_tree: str,
    lifecycle: str = "initializing",
    expected_images: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    validate_state_path(state_dir, project)
    return {
        "schema": SCHEMA,
        "synthetic_only": True,
        "project": project,
        "state_dir": str(state_dir.resolve()),
        "state_id": state_id,
        "compose_env_sha256": env_sha256,
        "lifecycle": lifecycle,
        "runtime_head": runtime_head,
        "runtime_tree": runtime_tree,
        "hrh_head": hrh_head,
        "hrh_tree": hrh_tree,
        "volumes": volume_names(project),
        "expected_images": dict(expected_images or {}),
    }


def fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json_atomic(path: Path, value: Mapping[str, Any], *, mode: int) -> None:
    tmp = path.with_name(path.name + ".tmp")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fsync_directory(path.parent)
    finally:
        if tmp.exists():
            tmp.unlink()


def read_marker(state_dir: Path, project: str) -> dict[str, Any]:
    state_dir = validate_state_path(state_dir, project)
    path = state_dir / MARKER_NAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("closed staging marker is missing or invalid") from exc
    expected_keys = {
        "schema", "synthetic_only", "project", "state_dir", "state_id",
        "compose_env_sha256", "lifecycle", "runtime_head", "runtime_tree",
        "hrh_head", "hrh_tree", "volumes", "expected_images",
    }
    if set(value) != expected_keys:
        raise SafetyError("staging marker has unknown or missing fields")
    if (
        value["schema"] != SCHEMA
        or value["synthetic_only"] is not True
        or value["project"] != project
        or value["state_dir"] != str(state_dir)
        or value["hrh_head"] != REQUIRED_HRH_SHA
        or value["volumes"] != volume_names(project)
        or not re.fullmatch(r"[a-f0-9]{32}", value["state_id"])
        or not re.fullmatch(r"[a-f0-9]{64}", value["compose_env_sha256"])
        or value["lifecycle"] not in {"initializing", "ready", "stopped"}
        or not isinstance(value["expected_images"], dict)
    ):
        raise SafetyError("staging marker does not match the requested synthetic target")
    return value


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SafetyError(f"required file is unavailable: {path.name}") from exc


def verify_effective_env(state_dir: Path, marker: Mapping[str, Any]) -> None:
    if file_sha256(state_dir / "compose.env") != marker["compose_env_sha256"]:
        raise SafetyError("compose.env differs from the initialized exact content")


def verify_source_frame(runtime: Path, hrh: Path, shell: Any) -> dict[str, str]:
    runtime = runtime.resolve()
    hrh = hrh.resolve()
    runtime_head = shell.git(runtime, "rev-parse", "HEAD")
    runtime_tree = shell.git(runtime, "rev-parse", "HEAD^{tree}")
    hrh_head = shell.git(hrh, "rev-parse", "HEAD")
    hrh_tree = shell.git(hrh, "rev-parse", "HEAD^{tree}")
    try:
        shell.git(runtime, "merge-base", "--is-ancestor", RUNTIME_BASE_SHA, runtime_head)
    except CommandError as exc:
        raise SafetyError("runtime does not descend from the frozen staging base") from exc
    if shell.git(runtime, "status", "--porcelain=v1"):
        raise SafetyError("runtime worktree must be clean")
    if shell.git(hrh, "status", "--porcelain=v1"):
        raise SafetyError("HRH worktree must be clean")
    if hrh_head != REQUIRED_HRH_SHA:
        raise SafetyError("HRH worktree must be at the exact required head")
    if REQUIRED_HRH_TREE and hrh_tree != REQUIRED_HRH_TREE:
        raise SafetyError("HRH tree does not match the exact required tree")
    return {
        "runtime_head": runtime_head,
        "runtime_tree": runtime_tree,
        "hrh_head": hrh_head,
        "hrh_tree": hrh_tree,
    }


def verify_hrh_candidate_build_inputs(hrh: Path) -> None:
    """Fail before Compose when the frozen HRH build recipes are not closed."""
    for name, expected in HRH_CANDIDATE_BASES.items():
        try:
            images = tuple(match.group("image") for match in FROM_RE.finditer((hrh / name).read_text(encoding="utf-8")))
        except OSError as exc:
            raise SafetyError("candidate HRH Dockerfile is unavailable") from exc
        if not images or any("@sha256:" not in image for image in images):
            raise SafetyError("candidate HRH Dockerfile contains a mutable base")
        if images != expected:
            raise SafetyError("candidate HRH Dockerfile base digest differs from the frozen contract")


def verify_destructive_volumes(
    project: str,
    state_id: str,
    expected: set[str],
    discovered: Mapping[str, Mapping[str, str]],
    lifecycle: str,
) -> list[str]:
    unexpected = set(discovered) - expected
    if unexpected:
        raise SafetyError("unexpected project volumes: " + ", ".join(sorted(unexpected)))
    required = {PROJECT_LABEL: project, STATE_LABEL: state_id, SYNTHETIC_LABEL: "true"}
    for name in discovered:
        if any(discovered[name].get(key) != value for key, value in required.items()):
            raise SafetyError(f"volume label mismatch: {name}")
    if lifecycle in {"ready", "stopped"} and set(discovered) != expected:
        raise SafetyError("ready/stopped staging requires the exact volume set")
    if lifecycle not in {"initializing", "ready", "stopped"}:
        raise SafetyError("unknown lifecycle for destructive volume verification")
    return sorted(discovered)


def verify_destructive_resources(
    project: str,
    state_id: str,
    containers: Mapping[str, Mapping[str, str]],
    networks: Mapping[str, Mapping[str, str]],
    lifecycle: str,
) -> tuple[list[str], list[str]]:
    required = {PROJECT_LABEL: project, STATE_LABEL: state_id, SYNTHETIC_LABEL: "true"}
    allowed_networks = {f"{project}_{key}" for key in NETWORK_KEYS}
    unexpected_networks = set(networks) - allowed_networks
    if unexpected_networks:
        raise SafetyError("unexpected project network: " + ", ".join(sorted(unexpected_networks)))
    for name, labels in networks.items():
        if any(labels.get(key) != value for key, value in required.items()):
            raise SafetyError(f"network label mismatch: {name}")
    services: list[str] = []
    for name, labels in containers.items():
        service = labels.get("com.docker.compose.service")
        if service not in ALLOWED_SERVICES:
            raise SafetyError(f"unexpected project container: {name}")
        if any(labels.get(key) != value for key, value in required.items()):
            raise SafetyError(f"container label mismatch: {name}")
        services.append(service)
    duplicates = sorted({service for service in services if services.count(service) > 1})
    if duplicates:
        raise SafetyError("duplicate project service containers: " + ", ".join(duplicates))
    if lifecycle in {"ready", "stopped"}:
        if "controller" in services:
            raise SafetyError("controller must be absent from ready/stopped staging")
        expected_services = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(services) != expected_services:
            raise SafetyError("ready/stopped staging requires the exact service set")
        if set(networks) != allowed_networks:
            raise SafetyError("ready/stopped staging requires the exact network set")
    elif lifecycle != "initializing":
        raise SafetyError("unknown lifecycle for destructive resource verification")
    return sorted(containers), sorted(networks)


def verify_publishers(
    inspected: Mapping[str, Mapping[str, Any]], port: int,
) -> dict[str, dict[str, str]]:
    expected_raw = {"18444/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}
    expected_receipt = {
        "container_port": "18444/tcp",
        "host_ip": "127.0.0.1",
        "host_port": str(port),
    }
    if set(inspected) != set(LONG_RUNNING_SERVICES):
        raise SafetyError("container inspection does not cover the exact running service set")
    for service, info in inspected.items():
        requested = info.get("HostConfig", {}).get("PortBindings")
        effective = info.get("NetworkSettings", {}).get("Ports")
        if service == "operator-proxy":
            if requested != expected_raw:
                raise SafetyError("proxy requested publisher is not the exact loopback binding")
            effective_bindings = (
                {key: value for key, value in effective.items() if value}
                if isinstance(effective, dict)
                else None
            )
            if effective_bindings != expected_raw:
                raise SafetyError("proxy effective publisher is not the exact loopback binding")
        else:
            if requested:
                raise SafetyError(f"non-proxy service requests a host port: {service}")
            effective_bindings = (
                any(value for value in effective.values()) if isinstance(effective, dict) else bool(effective)
            )
            if effective_bindings:
                raise SafetyError(f"non-proxy service has an effective host port: {service}")
    return {"requested": dict(expected_receipt), "effective": dict(expected_receipt)}


def verify_compose_rows(rows: Iterable[Mapping[str, Any]]) -> None:
    records = list(rows)
    services = [record.get("Service") for record in records]
    if len(services) != len(set(services)):
        raise SafetyError("Compose service rows contain a duplicate")
    expected = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
    if set(services) != expected:
        raise SafetyError("status requires the exact Compose service set")
    by_service = {record["Service"]: record for record in records}
    for service in LONG_RUNNING_SERVICES:
        if by_service[service].get("State") != "running":
            raise SafetyError(f"required service is not running: {service}")
    for service in ONE_SHOT_SERVICES:
        row = by_service[service]
        if row.get("State") != "exited" or row.get("ExitCode") != 0:
            raise SafetyError(f"required one-shot did not exit successfully: {service}")


def verify_network_topology(
    project: str,
    inspected: Mapping[str, Mapping[str, Any]],
    networks: Mapping[str, Mapping[str, Any]],
) -> None:
    if set(inspected) != set(EXPECTED_NETWORK_KEYS_BY_SERVICE):
        raise SafetyError("network membership inspection does not cover the exact service set")
    expected_names = {f"{project}_{key}" for key in NETWORK_KEYS}
    if set(networks) != expected_names:
        raise SafetyError("network inspection does not cover the exact staging network set")
    for key in INTERNAL_NETWORK_KEYS:
        if networks[f"{project}_{key}"].get("Internal") is not True:
            raise SafetyError(f"core network is not internal: {key}")
    access_name = f"{project}_operator_access"
    if networks[access_name].get("Internal") is not False:
        raise SafetyError("operator_access must be the explicit non-internal network")
    proxy = inspected.get("operator-proxy")
    if not proxy or not proxy.get("Id"):
        raise SafetyError("operator proxy inspection is unavailable")
    access_members = set((networks[access_name].get("Containers") or {}).keys())
    if access_members != {proxy["Id"]}:
        raise SafetyError("operator_access must contain only the proxy")
    for service, expected_keys in EXPECTED_NETWORK_KEYS_BY_SERVICE.items():
        info = inspected[service]
        memberships = set(info.get("NetworkSettings", {}).get("Networks") or {})
        expected_memberships = {f"{project}_{key}" for key in expected_keys}
        if memberships != expected_memberships:
            raise SafetyError(f"{service} has unexpected network membership")


def _tmpfs_is_confined(value: Any, *, uid: int, gid: int) -> bool:
    if not isinstance(value, str):
        return False
    tokens = [item.strip() for item in value.split(",")]
    if not tokens or any(not item for item in tokens):
        return False
    flags: set[str] = set()
    values: dict[str, str] = {}
    allowed_flags = {"rw", "ro", "noexec", "exec", "nosuid", "suid"}
    allowed_values = {"size", "mode", "uid", "gid"}
    for token in tokens:
        if "=" in token:
            key, item = token.split("=", 1)
            if key not in allowed_values or not item or key in values:
                return False
            values[key] = item
        else:
            if token not in allowed_flags or token in flags:
                return False
            flags.add(token)
    if {"ro", "rw"} <= flags or {"exec", "noexec"} <= flags or {"suid", "nosuid"} <= flags:
        return False
    size_is_16m = values.get("size") in {"16m", "16384k", "16777216"}
    mode_is_0700 = values.get("mode") in {"0700", "700"}
    return (
        {"rw", "noexec", "nosuid"} <= flags
        and values.get("uid") == str(uid)
        and values.get("gid") == str(gid)
        and size_is_16m
        and mode_is_0700
    )


def verify_restricted_container_controls(
    inspected: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Reject effective runtime drift for the two restricted long-lived services."""
    evidence: dict[str, dict[str, Any]] = {}
    for service, expected in RESTRICTED_CONTAINER_CONTROLS.items():
        info = inspected.get(service)
        if not isinstance(info, Mapping):
            raise SafetyError(f"{service} container inspection is unavailable")
        config = info.get("Config") or {}
        host = info.get("HostConfig") or {}
        security = {
            str(value).replace(":", "=")
            for value in (host.get("SecurityOpt") or [])
        }
        tmpfs = host.get("Tmpfs") or {}
        mounts = info.get("Mounts") or []
        mount_modes: dict[str, bool] = {}
        for mount in mounts:
            if not isinstance(mount, Mapping) or not isinstance(mount.get("Destination"), str):
                raise SafetyError(f"{service} mount inspection is malformed")
            destination = str(mount["Destination"])
            if destination in mount_modes or not isinstance(mount.get("RW"), bool):
                raise SafetyError(f"{service} mount inspection is ambiguous")
            mount_modes[destination] = bool(mount["RW"])
        expected_modes = {
            **{path: False for path in expected["read_only_mounts"]},
            **{path: True for path in expected["writable_mounts"]},
        }
        if (
            config.get("User") != expected["user"]
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or {str(value).upper() for value in (host.get("CapDrop") or [])} != {"ALL"}
            or host.get("CapAdd") not in (None, [])
            or security != {"no-new-privileges=true"}
            or set(tmpfs) != {"/tmp"}
            or not _tmpfs_is_confined(
                tmpfs.get("/tmp"), uid=expected["uid"], gid=expected["gid"]
            )
            or mount_modes != expected_modes
        ):
            raise SafetyError(f"{service} effective container confinement rejected")
        evidence[service] = {
            "user": expected["user"],
            "privileged": False,
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "tmpfs": ["/tmp"],
            "read_only_mounts": sorted(expected["read_only_mounts"]),
            "writable_mounts": sorted(expected["writable_mounts"]),
        }
    return evidence


def _certificate_material(seed: Path) -> None:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic clinical staging CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def server(host: str, *, include_loopback_ip: bool = False) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        names: list[x509.GeneralName] = [x509.DNSName(host)]
        if include_loopback_ip:
            names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    material = {"ca.crt": ca.public_bytes(serialization.Encoding.PEM)}
    for host, prefix in (("mattermost", "mattermost"), ("hrh-tls", "hrh-tls")):
        material[f"{prefix}.crt"], material[f"{prefix}.key"] = server(
            host, include_loopback_ip=host == "mattermost"
        )
    for name, raw in material.items():
        path = seed / name
        path.write_bytes(raw)
        path.chmod(0o600)


class ClinicalStaging:
    def __init__(self, runtime: Path, hrh: Path, state_dir: Path, project: str, port: int, shell: Shell | None = None):
        self.runtime = runtime.resolve()
        self.hrh = hrh.resolve()
        self.project = validate_project(project)
        self.state_dir = validate_state_path(
            state_dir,
            project,
            forbidden_roots=(self.runtime, self.hrh),
        )
        if not 1024 <= port <= 65535:
            raise SafetyError("Mattermost loopback port must be 1024..65535")
        self.port = port
        self.shell = shell or Shell()
        self.base_compose = self.runtime / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"
        self.overlay = self.runtime / "deploy" / "clinical-staging" / "compose.yaml"
        self.harness = self.runtime / "tests" / "deployment" / "clinical-composed-e2e"
        self.env_file = self.state_dir / "compose.env"

    def _require_linux(self) -> None:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            raise SafetyError("operator staging lifecycle is supported only on local Linux")

    def _compose_args(self) -> tuple[str, ...]:
        return (
            "docker", "compose", "--env-file", str(self.env_file),
            "--project-name", self.project, "--file", str(self.base_compose),
            "--file", str(self.overlay),
        )

    def _sealed_compose_environment(self) -> dict[str, str]:
        try:
            lines = self.env_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise SafetyError("sealed compose environment is unavailable") from exc
        sealed: dict[str, str] = {}
        for line in lines:
            if not line or "=" not in line:
                raise SafetyError("sealed compose environment is malformed")
            key, value = line.split("=", 1)
            if not COMPOSE_ENV_RE.fullmatch(key) or key in sealed:
                raise SafetyError("sealed compose environment is malformed")
            sealed[key] = value
        if not sealed:
            raise SafetyError("sealed compose environment is empty")
        process = {key: os.environ[key] for key in SAFE_COMPOSE_PROCESS_ENV if key in os.environ}
        process.update(sealed)
        return process

    def compose(self, *args: str, check: bool = True, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
        return self.shell.run(*self._compose_args(), *args, cwd=self.runtime, env=self._sealed_compose_environment(), check=check, timeout=timeout)

    def control(self, *args: str, timeout: int = 600) -> str:
        result = self.compose(
            "--profile", "provision", "run", "--rm", "--no-deps", "controller", *args,
            timeout=timeout,
        )
        return result.stdout.strip()

    def _env_values(self, marker: Mapping[str, Any], *, seed_root: Path | None = None) -> dict[str, str]:
        material_seed = (seed_root or self.state_dir) / "seed"
        effective_seed = self.state_dir / "seed"
        private = serialization.load_pem_private_key(
            (material_seed / "policy-private.pem").read_bytes(), password=None
        )
        policy_public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
        values: dict[str, str] = {
            "CLINICAL_MM_DB_PASSWORD": secrets.token_hex(24),
            "CLINICAL_HRH_DB_PASSWORD": secrets.token_hex(24),
            "CLINICAL_HRH_SESSION_SECRET": secrets.token_hex(32),
            "CLINICAL_HRH_ENCRYPTION_KEY": secrets.token_hex(32),
            "CLINICAL_HRH_ROOT": self.hrh.as_posix(),
            "CLINICAL_HARNESS": self.harness.as_posix(),
            "CLINICAL_SEED": effective_seed.as_posix(),
            "CLINICAL_INGRESS_IMAGE": f"restricted-clinical-ingress:{self.project}",
            "CLINICAL_ADAPTER_IMAGE": f"restricted-clinical-adapter:{self.project}",
            "CLINICAL_POLICY_PUBLIC_KEY": policy_public,
            "CLINICAL_HRH_BUILD_SHA": marker["hrh_head"],
            "CLINICAL_STAGING_PROJECT": self.project,
            "CLINICAL_STAGING_STATE_ID": marker["state_id"],
            "CLINICAL_STAGING_PORT": str(self.port),
        }
        values.update({f"CLINICAL_VOLUME_{key.upper()}": name for key, name in marker["volumes"].items()})
        return values

    @staticmethod
    def _env_bytes(values: Mapping[str, str]) -> bytes:
        return "".join(f"{key}={value}\n" for key, value in values.items()).encode("utf-8")

    def _create_volumes(self, marker: Mapping[str, Any]) -> None:
        for name in marker["volumes"].values():
            self.shell.run(
                "docker", "volume", "create",
                "--label", f"{PROJECT_LABEL}={self.project}",
                "--label", f"{STATE_LABEL}={marker['state_id']}",
                "--label", f"{SYNTHETIC_LABEL}=true",
                name,
                cwd=self.runtime,
            )
        verify_destructive_volumes(
            self.project,
            marker["state_id"],
            set(marker["volumes"].values()),
            self._volume_labels(),
            marker["lifecycle"],
        )
        if set(self._volume_labels()) != set(marker["volumes"].values()):
            raise SafetyError("volume creation did not produce the exact initialized set")

    def _seed_material(self, root: Path) -> None:
        seed = root / "seed"
        seed.mkdir(mode=0o700)
        for name in ("admin_password", "actor_password", "denied_password", "hrh_api_key"):
            path = seed / name
            path.write_text("clinical_" + secrets.token_hex(24), encoding="ascii")
            path.chmod(0o600)
        _certificate_material(seed)
        policy_private = Ed25519PrivateKey.generate()
        policy_path = seed / "policy-private.pem"
        policy_path.write_bytes(
            policy_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        policy_path.chmod(0o600)

    def _prepare_new_state(self, frame: Mapping[str, str]) -> dict[str, Any]:
        if self.state_dir.exists():
            if any(self.state_dir.iterdir()):
                raise SafetyError("init requires a fresh target or a valid initializing marker")
            self.state_dir.rmdir()
        temporary = self.state_dir.parent / f".{self.state_dir.name}.init-{secrets.token_hex(8)}"
        temporary.mkdir(mode=0o700, parents=False)
        try:
            (temporary / "evidence").mkdir(mode=0o700)
            self._seed_material(temporary)
            marker = new_marker(
                project=self.project,
                state_dir=self.state_dir,
                state_id=secrets.token_hex(16),
                env_sha256="0" * 64,
                **frame,
            )
            values = self._env_values(marker, seed_root=temporary)
            env_raw = self._env_bytes(values)
            marker["compose_env_sha256"] = hashlib.sha256(env_raw).hexdigest()
            env_path = temporary / "compose.env"
            env_path.write_bytes(env_raw)
            env_path.chmod(0o600)
            write_json_atomic(temporary / MARKER_NAME, marker, mode=0o600)
            fsync_directory(temporary)
            os.replace(temporary, self.state_dir)
            fsync_directory(self.state_dir.parent)
            return marker
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _write_marker(self, marker: Mapping[str, Any]) -> None:
        write_json_atomic(self.state_dir / MARKER_NAME, marker, mode=0o600)

    def _build_images(self) -> None:
        # controller is FROM the locally tagged ingress image, so its build
        # cannot share a parallel Compose phase with ingress.
        self.compose("build", "ingress", "clinical-adapter", timeout=2400)
        self.compose("build", "controller", "hrh-migrate", "hrh", timeout=2400)

    def init(self) -> dict[str, Any]:
        self._require_linux()
        frame = verify_source_frame(self.runtime, self.hrh, self.shell)
        verify_hrh_candidate_build_inputs(self.hrh)
        if self.state_dir.exists() and (self.state_dir / MARKER_NAME).exists():
            marker = read_marker(self.state_dir, self.project)
            if marker["lifecycle"] != "initializing":
                raise SafetyError("staging target is already initialized")
            verify_effective_env(self.state_dir, marker)
            if any(marker[key] != value for key, value in frame.items()):
                raise SafetyError("initializing marker source frame changed")
        else:
            self.state_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            marker = self._prepare_new_state(frame)
        state_stat = self.state_dir.stat()
        if state_stat.st_uid != os.getuid() or stat.S_IMODE(state_stat.st_mode) != 0o700:
            raise SafetyError("state directory must be owned by the operator with mode 0700")
        self._create_volumes(marker)
        self.compose("config", "--quiet")
        self._build_images()
        self.control("seed-volumes")
        self.compose("up", "--detach", "mattermost-postgres", "hrh-postgres", "hrh-migrate", timeout=900)
        migrated = self.compose("wait", "hrh-migrate", check=False, timeout=900)
        if migrated.returncode:
            raise CommandError("HRH migration did not complete successfully")
        self.compose("up", "--detach", "mattermost", timeout=600)
        self.control("wait-mm")
        password = (self.state_dir / "seed" / "admin_password").read_text(encoding="ascii")
        created = self.compose(
            "exec", "--no-TTY", "mattermost", "/mattermost/bin/mmctl", "--local", "user", "create",
            "--email", "admin@clinical.invalid", "--username", "clinicaladmin", "--password", password,
            "--system-admin", "--email-verified", "--disable-welcome-email", "--quiet", check=False,
        )
        if created.returncode and "already exists" not in (created.stdout + created.stderr).lower():
            raise CommandError("synthetic Mattermost administrator bootstrap failed")
        self.control("bootstrap-mm")
        self.control("seed-hrh")
        self.control("policy", "clinical-e1", "3600")
        self.control("outbox-init")
        public_key = self.control("public-key")
        base64.b64decode(public_key, validate=True)
        env_public = next(
            line.split("=", 1)[1]
            for line in self.env_file.read_text(encoding="utf-8").splitlines()
            if line.startswith("CLINICAL_POLICY_PUBLIC_KEY=")
        )
        if public_key != env_public:
            raise SafetyError("provisioned policy public key differs from the sealed environment")
        self.compose("up", "--detach", *ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        marker["expected_images"] = self._built_images()
        marker["lifecycle"] = "ready"
        self._write_marker(marker)
        self.up()
        return self.status()

    def up(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "up", {"ready", "stopped"})
        self.compose("up", "--detach", *ONE_SHOT_SERVICES, *LONG_RUNNING_SERVICES, timeout=1200)
        self.control("wait-mm")
        self.control("wait-hrh")
        if marker["lifecycle"] == "stopped":
            marker["lifecycle"] = "ready"
            self._write_marker(marker)
        return self.status()

    def _verify_marker_and_source(self) -> dict[str, Any]:
        marker = read_marker(self.state_dir, self.project)
        verify_effective_env(self.state_dir, marker)
        frame = verify_source_frame(self.runtime, self.hrh, self.shell)
        for key, value in frame.items():
            if marker[key] != value:
                raise SafetyError(f"current source frame differs from initialized {key}")
        return marker

    @staticmethod
    def _require_lifecycle(marker: Mapping[str, Any], command: str, allowed: set[str]) -> None:
        lifecycle = marker.get("lifecycle")
        if lifecycle not in allowed:
            expected = ", ".join(sorted(allowed))
            raise SafetyError(
                f"{command} rejects marker lifecycle {lifecycle!r}; expected one of: {expected}"
            )

    def _containers(self, *, all_containers: bool = False) -> list[dict[str, Any]]:
        args = ["ps", "--format", "json"]
        if all_containers:
            args.insert(1, "--all")
        raw = self.compose(*args, check=False).stdout.strip()
        if not raw:
            return []
        try:
            value = json.loads(raw)
            return value if isinstance(value, list) else [value]
        except json.JSONDecodeError:
            return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def _built_images(self) -> dict[str, str]:
        result: dict[str, str] = {}
        records = {row.get("Service"): row for row in self._containers(all_containers=True)}
        for service in LONG_RUNNING_SERVICES:
            container_id = records.get(service, {}).get("ID")
            if not container_id:
                raise SafetyError(f"container unavailable for image evidence: {service}")
            info = json.loads(self.shell.run("docker", "container", "inspect", container_id).stdout)[0]
            result[service] = info["Image"]
        return result

    def _container_inspections(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for row in self._containers(all_containers=True):
            container_id = row.get("ID")
            service = row.get("Service")
            if container_id and service:
                result[str(service)] = json.loads(
                    self.shell.run("docker", "container", "inspect", str(container_id)).stdout
                )[0]
        return result

    def _network_inspections(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for key in NETWORK_KEYS:
            name = f"{self.project}_{key}"
            inspected = self.shell.run("docker", "network", "inspect", name)
            result[name] = json.loads(inspected.stdout)[0]
        return result

    def _probe_mattermost_tls(self) -> dict[str, Any]:
        ca_path = self.state_dir / "seed" / "ca.crt"
        try:
            context = ssl.create_default_context(cafile=str(ca_path))
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                    secured.settimeout(5)
                    secured.sendall(
                        b"GET /api/v4/system/ping HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
                    )
                    response = http.client.HTTPResponse(secured)
                    response.begin()
                    if response.status != 200:
                        raise SafetyError("Mattermost TLS probe did not return HTTP 200")
                    body = response.read(65537)
                    if len(body) > 65536:
                        raise SafetyError("Mattermost TLS probe response exceeded 64 KiB")
            payload = json.loads(body)
            if not isinstance(payload, dict) or payload.get("status") != "OK":
                raise SafetyError("Mattermost TLS probe returned an unexpected payload")
        except SafetyError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, json.JSONDecodeError, ValueError) as exc:
            raise SafetyError("Mattermost CA-verified TLS probe failed") from exc
        return {
            "verified": True,
            "hostname": "127.0.0.1",
            "path": "/api/v4/system/ping",
        }

    def _assert_no_controller(self) -> None:
        containers = self._labeled_resources("container")
        if any(labels.get("com.docker.compose.service") == "controller" for labels in containers.values()):
            raise SafetyError("privileged provisioner must not remain after initialization")

    def status(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "status", {"ready"})
        rows = self._containers(all_containers=True)
        verify_compose_rows(rows)
        self._assert_no_controller()
        all_inspected = self._container_inspections()
        expected_inspections = set(LONG_RUNNING_SERVICES) | set(ONE_SHOT_SERVICES)
        if set(all_inspected) != expected_inspections:
            raise SafetyError("container inspection does not cover the exact Compose service set")
        inspected = {service: all_inspected[service] for service in LONG_RUNNING_SERVICES}
        publisher = verify_publishers(inspected, self.port)
        verify_network_topology(self.project, inspected, self._network_inspections())
        restricted_controls = verify_restricted_container_controls(inspected)
        self.control("wait-mm")
        self.control("wait-hrh")
        tls_probe = self._probe_mattermost_tls()
        socket_raw = self.compose(
            "exec", "--no-TTY", "clinical-adapter", "python", "-c",
            "import json,os,stat; s=os.stat('/run/restricted-clinical/query.sock'); print(json.dumps({'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'socket':stat.S_ISSOCK(s.st_mode)}))",
        ).stdout
        socket_status = json.loads(socket_raw)
        if socket_status != {"uid": 10008, "gid": 20006, "mode": 0o660, "socket": True}:
            raise SafetyError("clinical socket metadata is not exact")
        ingress_started_at = all_inspected["ingress"].get("State", {}).get("StartedAt")
        if not isinstance(ingress_started_at, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z",
            ingress_started_at,
        ) or ingress_started_at.startswith("0001-"):
            raise SafetyError("current Mattermost ingress start time is unavailable")
        logs = self.compose(
            "logs",
            "--no-color",
            "--since",
            ingress_started_at,
            "ingress",
            check=False,
        ).stdout
        if "mattermost_ingress_outcome=authenticated_ready" not in logs:
            raise SafetyError("Mattermost ingress is not authenticated-ready")
        current_images = self._built_images()
        if not marker["expected_images"] or current_images != marker["expected_images"]:
            raise SafetyError("running service image identities differ from initialized receipt")
        evidence = {
            "schema": SCHEMA,
            "synthetic_only": True,
            "project": self.project,
            "state_id": marker["state_id"],
            "source": {key: marker[key] for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")},
            "built_images": current_images,
            "compose_env_sha256": marker["compose_env_sha256"],
            "policy_digest": self.control("policy-digest"),
            "lifecycle": "ready",
            "mattermost": f"https://127.0.0.1:{self.port}",
            "mattermost_publisher": publisher,
            "ingress_started_at": ingress_started_at,
            "tls_probe": tls_probe,
            "network_exception": "operator-proxy only: operator_access is non-internal",
            "restricted_container_controls": restricted_controls,
            "privileged_provisioner_running": False,
            "nonclaims": ["not HIPAA", "not PHI-authorized", "not production"],
            "observed_at": datetime.now(UTC).isoformat(),
        }
        self._assert_no_controller()
        write_json_atomic(self.state_dir / "evidence" / "status.json", evidence, mode=0o600)
        return evidence

    def refresh_policy(self, epoch: str) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "refresh-policy", {"ready"})
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", epoch):
            raise SafetyError("policy epoch has an invalid shape")
        self.compose("stop", "ingress")
        self.control("policy", epoch, "3600")
        installed_digest = self.control("policy-verify")
        if not re.fullmatch(r"[a-f0-9]{64}", installed_digest):
            raise SafetyError("installed policy pair did not verify")
        self.compose("up", "--detach", "ingress")
        return self.status()

    def stop(self) -> dict[str, Any]:
        self._require_linux()
        marker = self._verify_marker_and_source()
        self._require_lifecycle(marker, "stop", {"ready"})
        stopped = self.compose("stop", *LONG_RUNNING_SERVICES, check=False)
        if stopped.returncode:
            raise CommandError("Compose could not stop every required staging service")
        marker["lifecycle"] = "stopped"
        self._write_marker(marker)
        evidence = {"schema": SCHEMA, "project": self.project, "state_id": marker["state_id"], "lifecycle": "stopped", "observed_at": datetime.now(UTC).isoformat()}
        write_json_atomic(self.state_dir / "evidence" / "last-transition.json", evidence, mode=0o600)
        return evidence

    def _volume_labels(self) -> dict[str, dict[str, str]]:
        names: set[str] = set(volume_names(self.project).values())
        for key, value in ((PROJECT_LABEL, self.project), ("com.docker.compose.project", self.project)):
            raw = self.shell.run("docker", "volume", "ls", "--quiet", "--filter", f"label={key}={value}").stdout
            names.update(line.strip() for line in raw.splitlines() if line.strip())
        result: dict[str, dict[str, str]] = {}
        for name in names:
            inspected = self.shell.run("docker", "volume", "inspect", name, check=False)
            if inspected.returncode:
                continue
            item = json.loads(inspected.stdout)[0]
            result[name] = item.get("Labels") or {}
        return result

    def _labeled_resources(self, kind: str) -> dict[str, dict[str, str]]:
        command = "container" if kind == "container" else "network"
        ids: set[str] = set()
        for key, value in ((PROJECT_LABEL, self.project), ("com.docker.compose.project", self.project)):
            args = ["docker", command, "ls", "--quiet", "--filter", f"label={key}={value}"]
            if command == "container":
                args.insert(3, "--all")
            raw = self.shell.run(*args).stdout
            ids.update(line.strip() for line in raw.splitlines() if line.strip())
        result: dict[str, dict[str, str]] = {}
        for resource_id in ids:
            item = json.loads(self.shell.run("docker", command, "inspect", resource_id).stdout)[0]
            labels = item.get("Config", {}).get("Labels") if command == "container" else item.get("Labels")
            result[item["Name"].lstrip("/")] = labels or {}
        return result

    def _destroy_resources(self) -> None:
        marker = self._verify_marker_and_source()
        expected = set(marker["volumes"].values())
        volume_names_to_remove = verify_destructive_volumes(
            self.project, marker["state_id"], expected, self._volume_labels(), marker["lifecycle"],
        )
        containers = self._labeled_resources("container")
        networks = self._labeled_resources("network")
        verify_destructive_resources(
            self.project, marker["state_id"], containers, networks, marker["lifecycle"]
        )
        self.compose("down", timeout=600)
        remaining_containers = self._labeled_resources("container")
        remaining_networks = self._labeled_resources("network")
        if remaining_containers or remaining_networks:
            raise SafetyError("Compose resources remain after successful down")
        for name in volume_names_to_remove:
            self.shell.run("docker", "volume", "rm", name, cwd=self.runtime)

    def reset(self) -> dict[str, Any]:
        self._require_linux()
        self._destroy_resources()
        for name in ("seed", "evidence"):
            shutil.rmtree(self.state_dir / name, ignore_errors=False)
        for name in (MARKER_NAME, "compose.env"):
            (self.state_dir / name).unlink()
        return self.init()

    def destroy(self) -> dict[str, Any]:
        self._require_linux()
        marker = read_marker(self.state_dir, self.project)
        self._destroy_resources()
        result = {"schema": SCHEMA, "project": self.project, "state_id": marker["state_id"], "lifecycle": "destroyed"}
        shutil.rmtree(self.state_dir)
        return result


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--hrh-root", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", type=int, default=18443)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "up", "status", "stop", "reset", "destroy"):
        sub.add_parser(name)
    refresh = sub.add_parser("refresh-policy")
    refresh.add_argument("--epoch", required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    staging = ClinicalStaging(args.runtime_root, args.hrh_root, args.state_dir, args.project, args.port)
    try:
        if args.command == "refresh-policy":
            result = staging.refresh_policy(args.epoch)
        else:
            result = getattr(staging, args.command)()
    except (SafetyError, CommandError) as exc:
        print(f"clinical_staging outcome=denied reason={exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
