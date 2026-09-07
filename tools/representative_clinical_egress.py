#!/usr/bin/env python3
"""Collect a content-safe, candidate-bound clinical egress receipt."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "restricted-runtime-representative-clinical-egress-receipt.v1"
DENIED_CLASSES = (
    "controlled_ipv4", "controlled_ipv6", "controlled_dns", "synthetic_metadata_ipv4",
    "synthetic_metadata_ipv6", "synthetic_metadata_dns",
)
DNS_CLASSES = frozenset({"controlled_dns", "synthetic_metadata_dns"})
RED_SCHEMA = "restricted-runtime-representative-clinical-egress-red-proof.v1"
GREEN_SCHEMA = "restricted-runtime-representative-clinical-egress-green-proof.v1"
MARKER_PROOF_SCHEMA = "restricted-runtime-representative-clinical-egress-marker-proof.v1"
FIXED_PUBLIC_DNS = "example.com"
FIXED_METADATA = {"metadata_ipv4": ("169.254.169.254", 80, "ipv4"), "metadata_ipv6": ("fd00:ec2::254", 80, "ipv6")}
STAGING_HRH_HEAD = "e30a4f968de6727519f49c08369f561fdf269ec5"
STAGING_HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"
CONNECT_CLASSES = frozenset({"connected", "refused", "network-unreachable", "host-unreachable", "timeout", "other"})
METADATA_DENIED_CLASSES = frozenset({"network-unreachable", "host-unreachable"})
POLICIES = {
    "ingress": {
        "networks": ("mattermost_edge",),
        "permitted_internal": {"mattermost": 8065},
        "denied_internal": {"hrh-tls": 8443},
    },
    "clinical-adapter": {
        "networks": ("clinical_upstream",),
        "permitted_internal": {"hrh-tls": 8443},
        "denied_internal": {"mattermost": 8065},
    },
}
CONTROL_DESTINATIONS = {
    "ingress": {"/run/ingress", "/run/restricted-clinical", "/var/lib/restricted-mattermost-outbox"},
    "clinical-adapter": {"/run/clinical-config", "/run/hrh-secret", "/run/hrh-tls", "/run/restricted-clinical"},
}
SAFE_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,80}$")
SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
DOCKER_RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ReceiptError(RuntimeError):
    """A deliberately content-free collection failure."""


def collector_error_class(exc: BaseException) -> str:
    """Return a bounded diagnostic class without serializing exception content."""
    message = str(exc)
    if any(token in message for token in ("state, candidate", "output target", "request is incomplete")):
        return "input"
    if any(token in message for token in ("candidate source", "canonical staging")):
        return "source-binding"
    if "marker" in message or "initialized staging" in message:
        return "marker-binding"
    if "proof" in message or "retained" in message:
        return "proof-binding"
    if any(token in message for token in ("container image", "container inspection", "restricted service")):
        return "image-binding"
    if any(token in message for token in ("network probe", "controlled", "fixed probe", "live controlled")):
        return "network-probe"
    if "cleanup" in message:
        return "cleanup"
    if "command" in message:
        return "local-command"
    if "required" in message:
        return "input"
    return "receipt-policy"


def canonical_receipt(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


RED_NETWORK_SHAPE_SHA256 = hashlib.sha256(canonical_receipt({"driver": "bridge", "internal": False, "ipv6": True, "members": 2}).encode()).hexdigest()


def build_receipt(*, head: str, tree: str, kernel: str, architecture: str,
                  docker_version: str, compose_version: str,
                  observations: dict[str, dict[str, Any]], marker: dict[str, Any], marker_proof_sha256: str,
                  proof_sha256: dict[str, str], green: dict[str, dict[str, bool]], cleanup: dict[str, bool],
                  green_proof_sha256: str, fixed: dict[str, dict[str, str | bool]],
                  fixed_control: dict[str, dict[str, str | bool]], metadata_ipv6_attribution: dict[str, str]) -> dict[str, Any]:
    initialized_images = marker["expected_images"]
    for service in POLICIES:
        if observations.get(service, {}).get("image_id") != initialized_images.get(service):
            raise ReceiptError("container image differs from initialized image")
    return {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "runtime": {"head": head, "tree": tree},
        "staging": {"marker": marker, "marker_proof_sha256": marker_proof_sha256},
        "host": {"kernel": kernel, "architecture": architecture},
        "docker": {"server_version": docker_version, "compose_version": compose_version},
        "services": observations,
        "red_witness": {
            "proof_sha256": proof_sha256, "green_proof_sha256": green_proof_sha256, "green": green, "cleanup": cleanup,
            "fixed": fixed, "fixed_control": fixed_control, "metadata_ipv6_attribution": metadata_ipv6_attribution,
            "metadata_scope": "fixed-classes-content-free",
        },
    }


def verify_receipt(value: object, *, expected_head: str, expected_tree: str, evidence_dir: Path | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["receipt is not an object"]
    if set(value) != {"schema", "synthetic_non_phi_only", "runtime", "staging", "host", "docker", "services", "red_witness"}:
        errors.append("receipt fields are not exact")
    if value.get("schema") != SCHEMA or value.get("synthetic_non_phi_only") is not True:
        errors.append("receipt schema or synthetic marker is invalid")
    runtime = value.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("head") != expected_head:
        errors.append("runtime head does not bind the candidate")
    if not isinstance(runtime, dict) or runtime.get("tree") != expected_tree:
        errors.append("runtime tree does not bind the candidate")
    staging = value.get("staging")
    initialized_images: dict[str, Any] = {}
    marker: dict[str, Any] = {}
    if not isinstance(staging, dict) or set(staging) != {"marker", "marker_proof_sha256"} or not isinstance(staging.get("marker_proof_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", staging["marker_proof_sha256"]):
        errors.append("staging marker binding is invalid")
    else:
        try:
            _validate_marker_projection(staging["marker"], expected_head, expected_tree)
            marker = staging["marker"]
            initialized_images = marker["expected_images"]
        except ReceiptError:
            errors.append("staging marker binding is invalid")
    for group, fields in (("host", ("kernel", "architecture")), ("docker", ("server_version", "compose_version"))):
        item = value.get(group)
        if not isinstance(item, dict) or set(item) != set(fields) or any(not isinstance(item.get(field), str) or not SAFE_VERSION.fullmatch(item[field]) for field in fields):
            errors.append(f"{group} versions are invalid")
    services = value.get("services")
    if not isinstance(services, dict) or set(services) != set(POLICIES):
        return errors + ["service classes are not exact"]
    for service, policy in POLICIES.items():
        item = services.get(service)
        if not isinstance(item, dict):
            errors.append(f"{service} observation is invalid")
            continue
        required = {"image_id", "networks", "proxy_environment_absent", "controls", "denied", "permitted_internal", "denied_internal"}
        if set(item) != required or not isinstance(item.get("image_id"), str) or not SHA256.fullmatch(item["image_id"]):
            errors.append(f"{service} image is invalid")
        elif item["image_id"] != initialized_images.get(service):
            errors.append(f"{service} image differs from initialized image")
        if item.get("networks") != list(policy["networks"]):
            errors.append(f"{service} networks are unexpected")
        if item.get("proxy_environment_absent") is not True:
            errors.append(f"{service} proxy environment is present")
        controls = item.get("controls")
        if not isinstance(controls, dict) or set(controls) != {"read_only_rootfs", "capabilities_restricted", "mount_destinations_exact"} or any(result is not True for result in controls.values()):
            errors.append(f"{service} mounts or capabilities are unexpected")
        denied = item.get("denied")
        if not isinstance(denied, dict) or set(denied) != set(DENIED_CLASSES):
            errors.append(f"{service} denied classes are incomplete")
        elif any(denied[name] is not True for name in DENIED_CLASSES):
            errors.append(f"{service} denied probe succeeded")
        for key, expected in (("permitted_internal", set(policy["permitted_internal"])), ("denied_internal", set(policy["denied_internal"]))):
            got = item.get(key)
            if not isinstance(got, dict) or set(got) != expected or any(result is not True for result in got.values()):
                errors.append(f"{service} {key} is invalid")
    witness = value.get("red_witness")
    if not isinstance(witness, dict) or set(witness) != {"proof_sha256", "green_proof_sha256", "green", "cleanup", "fixed", "fixed_control", "metadata_ipv6_attribution", "metadata_scope"}:
        return errors + ["red witness fields are invalid"]
    proofs = witness["proof_sha256"]
    if not isinstance(proofs, dict) or set(proofs) != set(POLICIES) or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{64}", item) for item in proofs.values()):
        errors.append("red witness proof is invalid")
    if not isinstance(witness.get("green_proof_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", witness["green_proof_sha256"]):
        errors.append("green witness proof is invalid")
    green = witness["green"]
    if not isinstance(green, dict) or set(green) != set(POLICIES) or any(not isinstance(green.get(service), dict) or set(green[service]) != set(DENIED_CLASSES) or any(result is not True for result in green[service].values()) for service in POLICIES):
        errors.append("green controlled probes are incomplete")
    if witness.get("metadata_scope") != "fixed-classes-content-free":
        errors.append("metadata scope is invalid")
    fixed = witness.get("fixed")
    fixed_control = witness.get("fixed_control")
    attribution = witness.get("metadata_ipv6_attribution")
    if not _fixed_evidence_valid(fixed, fixed_control, attribution):
        errors.append("fixed probe evidence is invalid")
    cleanup = witness["cleanup"]
    if not isinstance(cleanup, dict) or cleanup != {"network_absent": True, "sink_absent": True}:
        errors.append("red witness cleanup is incomplete")
    if evidence_dir is not None and not errors:
        try:
            marker_hash = _read_marker_proof(evidence_dir / "marker.json", expected_head, expected_tree)
            if marker_hash != staging["marker_proof_sha256"] or _read_json(evidence_dir / "marker.json") != marker:
                raise ReceiptError("retained marker proof does not match receipt")
            green_hash, proven_green, proven_fixed, proven_control, proven_attribution, endpoints = _read_green_proof(
                evidence_dir / "green.json", expected_head, expected_tree, initialized_images, marker_hash,
            )
            if (green_hash != witness["green_proof_sha256"] or proven_green != green or proven_fixed != fixed
                    or proven_control != fixed_control or proven_attribution != attribution):
                raise ReceiptError("retained green proof does not match receipt")
            for service in POLICIES:
                red_hash = _read_red_proof(evidence_dir / f"red-{service}.json", service, expected_head, expected_tree,
                                           initialized_images[service], endpoints, marker_hash)
                if red_hash != proofs[service]:
                    raise ReceiptError("retained red proof does not match receipt")
        except ReceiptError:
            errors.append("retained proof semantics are invalid")
    return errors


def _run(*args: str, cwd: Path | None = None, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, cwd=cwd, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReceiptError("required local command did not complete") from exc


def _stdout(*args: str, cwd: Path | None = None, timeout: int = 20) -> str:
    result = _run(*args, cwd=cwd, timeout=timeout)
    if result.returncode:
        raise ReceiptError("required local command was rejected")
    return result.stdout.strip()


def _exact_name_absent(resource: str, name: str) -> bool:
    """Prove absence only from a successful, parseable exact-name enumeration."""
    if not DOCKER_RESOURCE_NAME.fullmatch(name):
        raise ReceiptError("cleanup resource name was invalid")
    if resource == "network":
        command = ("docker", "network", "ls", "--format", "{{.Name}}")
    elif resource == "container":
        command = ("docker", "container", "ls", "--all", "--format", "{{.Names}}")
    else:
        raise ReceiptError("cleanup resource type was invalid")
    result = _run(*command)
    if result.returncode != 0:
        return False
    output = result.stdout
    if output == "":
        return True
    names = output.splitlines()
    if not names or any(not DOCKER_RESOURCE_NAME.fullmatch(item) for item in names):
        return False
    return name not in names


def _git(runtime: Path, revision: str) -> str:
    return _stdout("git", "rev-parse", revision, cwd=runtime)


def _compose(runtime: Path, state_dir: Path, project: str, *args: str) -> tuple[str, ...]:
    return (
        "docker", "compose", "--env-file", str(state_dir / "compose.env"), "--project-name", project,
        "--file", str(runtime / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"),
        "--file", str(runtime / "deploy" / "clinical-staging" / "compose.yaml"), *args,
    )


def _inspect_container(container_id: str) -> dict[str, Any]:
    try:
        raw = json.loads(_stdout("docker", "inspect", container_id))
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise ReceiptError("container inspection was invalid") from exc
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
        raise ReceiptError("container inspection was invalid")
    return raw[0]


def _load_staging_module(runtime: Path) -> Any:
    path = runtime / "deploy" / "clinical-staging" / "clinical_staging.py"
    spec = importlib.util.spec_from_file_location("representative_clinical_staging", path)
    if spec is None or spec.loader is None:
        raise ReceiptError("canonical staging validation is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ReceiptError("canonical staging validation is unavailable") from exc
    return module


def _validate_marker_projection(value: object, head: str, tree: str) -> None:
    if not isinstance(value, dict) or set(value) != {"schema", "marker_sha256", "source", "lifecycle", "compose_env_sha256", "expected_images", "volume_keys"}:
        raise ReceiptError("marker proof shape is invalid")
    source = value.get("source")
    images = value.get("expected_images")
    if (value.get("schema") != MARKER_PROOF_SCHEMA or value.get("lifecycle") != "ready"
            or not isinstance(value.get("marker_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", value["marker_sha256"])
            or not isinstance(value.get("compose_env_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", value["compose_env_sha256"])
            or source != {"runtime_head": head, "runtime_tree": tree, "hrh_head": STAGING_HRH_HEAD, "hrh_tree": STAGING_HRH_TREE}
            or not isinstance(source, dict) or any(not isinstance(source[key], str) or not GIT_SHA.fullmatch(source[key]) for key in source)
            or not isinstance(images, dict) or set(images) != {"mattermost-postgres", "mattermost", "hrh-postgres", "hrh", "hrh-tls", "clinical-adapter", "ingress", "operator-proxy"}
            or any(not isinstance(image, str) or not SHA256.fullmatch(image) for image in images.values())
            or not isinstance(value.get("volume_keys"), list) or value["volume_keys"] != ["clinical_config", "clinical_socket", "controller_state", "hrh_db", "hrh_secret", "hrh_tls", "ingress_config", "ingress_outbox", "mattermost_data", "mattermost_db", "mattermost_tls"]):
        raise ReceiptError("marker proof does not retain the exact staging frame")


def _marker(state_dir: Path, project: str, head: str, tree: str, runtime: Path) -> dict[str, Any]:
    path = state_dir / "staging-state.json"
    try:
        raw = path.read_bytes()
        canonical = _load_staging_module(runtime)
        value = canonical.read_marker(state_dir, project)
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        raise ReceiptError("initialized staging marker is unavailable") from exc
    if value.get("lifecycle") != "ready" or value.get("runtime_head") != head or value.get("runtime_tree") != tree:
        raise ReceiptError("initialized staging marker does not bind candidate")
    projection = {
        "schema": MARKER_PROOF_SCHEMA, "marker_sha256": hashlib.sha256(raw).hexdigest(),
        "source": {key: value[key] for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")},
        "lifecycle": value["lifecycle"], "compose_env_sha256": value["compose_env_sha256"],
        "expected_images": value["expected_images"], "volume_keys": sorted(value["volumes"]),
    }
    _validate_marker_projection(projection, head, tree)
    return projection


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError("retained proof is unavailable") from exc
    if not isinstance(value, dict):
        raise ReceiptError("retained proof is not an object")
    return value


def _read_marker_proof(path: Path, head: str, tree: str) -> str:
    value = _read_json(path)
    _validate_marker_projection(value, head, tree)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixed_evidence_valid(fixed: object, control: object, attribution: object) -> bool:
    if not isinstance(fixed, dict) or not isinstance(control, dict) or not isinstance(attribution, dict) or set(fixed) != set(POLICIES) or set(control) != set(POLICIES) or set(attribution) != set(POLICIES):
        return False
    for service in POLICIES:
        target, independent = fixed[service], control[service]
        if (not isinstance(target, dict) or not isinstance(independent, dict)
                or set(target) != {"public_dns_example_com", "metadata_ipv4", "metadata_ipv6"}
                or set(independent) != {"public_dns_example_com", "metadata_ipv4", "metadata_ipv6"}
                or target["public_dns_example_com"] is not False or independent["public_dns_example_com"] is not True
                or target["metadata_ipv4"] not in METADATA_DENIED_CLASSES or target["metadata_ipv6"] not in METADATA_DENIED_CLASSES
                or independent["metadata_ipv4"] not in CONNECT_CLASSES or independent["metadata_ipv6"] not in CONNECT_CLASSES
                or target["metadata_ipv4"] == independent["metadata_ipv4"]):
            return False
        expected = "host-bound-control-unreachable" if independent["metadata_ipv6"] in METADATA_DENIED_CLASSES else "target-only-denied"
        if attribution[service] != expected:
            return False
    return True


def _proxy_absent(inspected: dict[str, Any]) -> bool:
    environment = inspected.get("Config", {}).get("Env")
    if not isinstance(environment, list):
        raise ReceiptError("container environment shape was invalid")
    names = {entry.split("=", 1)[0].upper() for entry in environment if isinstance(entry, str)}
    return not names.intersection({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"})


def _network_classes(inspected: dict[str, Any], project: str, expected: tuple[str, ...]) -> list[str]:
    networks = inspected.get("NetworkSettings", {}).get("Networks")
    if not isinstance(networks, dict):
        raise ReceiptError("container network shape was invalid")
    actual = set(networks)
    wanted = {f"{project}_{name}" for name in expected}
    if actual != wanted:
        raise ReceiptError("container networks did not match policy")
    return list(expected)


def _controls(service: str, inspected: dict[str, Any]) -> dict[str, bool]:
    host = inspected.get("HostConfig", {})
    mounts = inspected.get("Mounts")
    if not isinstance(host, dict) or not isinstance(mounts, list):
        raise ReceiptError("container controls shape was invalid")
    destinations = {mount.get("Destination") for mount in mounts if isinstance(mount, dict)}
    return {
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "capabilities_restricted": set(host.get("CapDrop") or ()) == {"ALL"} and not host.get("CapAdd") and "no-new-privileges:true" in (host.get("SecurityOpt") or ()),
        "mount_destinations_exact": destinations == CONTROL_DESTINATIONS[service],
    }


def _probe(image_id: str, container_id: str, host: str, port: int, *, resolve_only: bool = False) -> bool:
    operation = "socket.getaddrinfo(" + repr(host) + "," + str(port) + ")" if resolve_only else "socket.create_connection((" + repr(host) + "," + str(port) + "), 2).close()"
    program = "import socket,sys\ntry:\n " + operation + "\nexcept OSError:\n print('denied'); sys.exit(73)\nprint('reachable')"
    result = _run("docker", "run", "--rm", "--network", f"container:{container_id}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--entrypoint", "python", image_id, "-c", program, timeout=15)
    output = result.stdout.strip()
    if result.returncode == 0 and output == "reachable":
        return True
    if result.returncode == 73 and output == "denied":
        return False
    raise ReceiptError("network probe did not produce an expected outcome")


def _endpoints(ipv4: str, ipv6: str, dns_name: str, metadata_name: str, port: int) -> dict[str, tuple[str, int]]:
    if not ipv4 or not ipv6 or not dns_name or not metadata_name or not 0 < port < 65536:
        raise ReceiptError("controlled probe target is incomplete")
    return {
        "controlled_ipv4": (ipv4, port), "controlled_ipv6": (ipv6, port),
        "controlled_dns": (dns_name, port), "synthetic_metadata_ipv4": (ipv4, port),
        "synthetic_metadata_ipv6": (ipv6, port), "synthetic_metadata_dns": (metadata_name, port),
    }


def _probe_results(image_id: str, container_id: str, endpoints: dict[str, tuple[str, int]], *, reachable: bool) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name, (host, port) in endpoints.items():
        tcp = _probe(image_id, container_id, host, port)
        dns = _probe(image_id, container_id, host, port, resolve_only=True) if name in DNS_CLASSES else True
        result[name] = tcp and dns if reachable else not tcp and (not dns if name in DNS_CLASSES else True)
    return result


def _network_control(image_id: str, network: str, endpoints: dict[str, tuple[str, int]]) -> bool:
    checks = "\n".join(f"socket.getaddrinfo({host!r},{port}); socket.create_connection(({host!r},{port}),2).close()" for host, port in endpoints.values())
    program = "import socket,sys\ntry:\n " + checks.replace("\n", "\n ") + "\nexcept OSError:\n sys.exit(1)"
    return _run("docker", "run", "--rm", "--network", network, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--entrypoint", "python", image_id, "-c", program, timeout=30).returncode == 0


def _control_resolves_public_dns(image_id: str, network: str) -> bool:
    return _run("docker", "run", "--rm", "--network", network, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--entrypoint", "python", image_id, "-c", "import socket; socket.getaddrinfo('example.com',443)", timeout=15).returncode == 0


def _fixed_outcomes(image_id: str, network: str) -> dict[str, str | bool]:
    program = """import errno,socket
def outcome(address,family):
 s=socket.socket(family,socket.SOCK_STREAM); s.settimeout(2)
 try: code=s.connect_ex(address)
 finally: s.close()
 return {0:'connected',errno.ECONNREFUSED:'refused',errno.ENETUNREACH:'network-unreachable',errno.EHOSTUNREACH:'host-unreachable',errno.ETIMEDOUT:'timeout'}.get(code,'other')
try: socket.getaddrinfo('example.com',443); dns=True
except OSError: dns=False
print(('1' if dns else '0')+'|'+outcome(('169.254.169.254',80),socket.AF_INET)+'|'+outcome(('fd00:ec2::254',80,0,0),socket.AF_INET6))"""
    raw = _run("docker", "run", "--rm", "--network", network, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--entrypoint", "python", image_id, "-c", program, timeout=15).stdout.strip().split("|")
    if len(raw) != 3 or raw[0] not in {"0", "1"} or raw[1] not in CONNECT_CLASSES or raw[2] not in CONNECT_CLASSES:
        raise ReceiptError("fixed probe outcome was invalid")
    return {"public_dns_example_com": raw[0] == "1", "metadata_ipv4": raw[1], "metadata_ipv6": raw[2]}


def _red_network_shape(network: str, sink: str, target: str) -> str:
    try:
        item = json.loads(_stdout("docker", "network", "inspect", network))[0]
        sink_id = _inspect_container(sink).get("Id")
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise ReceiptError("controlled red network is unavailable") from exc
    members = item.get("Containers") if isinstance(item, dict) else None
    if (not isinstance(sink_id, str) or not isinstance(members, dict) or set(members) != {sink_id, target}
            or item.get("Driver") != "bridge" or item.get("Internal") is not False or item.get("EnableIPv6") is not True):
        raise ReceiptError("controlled red network shape is invalid")
    return RED_NETWORK_SHAPE_SHA256


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or not path.parent.is_dir():
        raise ReceiptError("receipt output target is unsafe")
    raw = (canonical_receipt(value) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_red_proof(path: Path, service: str, head: str, tree: str, image_id: str,
                    endpoint_sha256: dict[str, str], marker_proof_sha256: str) -> str:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError("red proof is unavailable") from exc
    expected = {
        "schema": RED_SCHEMA, "service": service, "runtime": {"head": head, "tree": tree}, "image_id": image_id,
        "endpoint_sha256": endpoint_sha256, "marker_proof_sha256": marker_proof_sha256,
        "probes": {name: True for name in DENIED_CLASSES},
    }
    if not isinstance(value, dict) or set(value) != {"schema", "service", "runtime", "image_id", "endpoint_sha256", "marker_proof_sha256", "network_shape_sha256", "probes"} or any(value.get(key) != expected[key] for key in expected) or value.get("network_shape_sha256") != RED_NETWORK_SHAPE_SHA256:
        raise ReceiptError("red proof does not bind the controlled endpoint")
    return hashlib.sha256(raw).hexdigest()


def _service_observation(service: str, container_id: str, inspected: dict[str, Any], project: str,
                         denied: dict[str, bool], initialized_image: str) -> dict[str, Any]:
    policy = POLICIES[service]
    image_id = inspected.get("Image")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id) or image_id != initialized_image:
        raise ReceiptError("container image identity was invalid")
    permitted = {name: _probe(image_id, container_id, name, port) for name, port in policy["permitted_internal"].items()}
    blocked = {name: not _probe(image_id, container_id, name, port) for name, port in policy["denied_internal"].items()}
    return {
        "image_id": image_id, "networks": _network_classes(inspected, project, policy["networks"]),
        "proxy_environment_absent": _proxy_absent(inspected), "controls": _controls(service, inspected), "denied": denied,
        "permitted_internal": permitted, "denied_internal": blocked,
    }


def _source_marker(runtime: Path, state_dir: Path, project: str, head: str, tree: str) -> dict[str, Any]:
    if not GIT_SHA.fullmatch(head) or not GIT_SHA.fullmatch(tree):
        raise ReceiptError("candidate source shape was invalid")
    if _stdout("git", "status", "--porcelain", cwd=runtime):
        raise ReceiptError("candidate source is not frozen")
    if _git(runtime, "HEAD") != head or _git(runtime, "HEAD^{tree}") != tree:
        raise ReceiptError("candidate source did not match expected frame")
    return _marker(state_dir, project, head, tree, runtime)


def _service_id(runtime: Path, state_dir: Path, project: str, service: str) -> str:
    container_id = _stdout(*_compose(runtime, state_dir, project, "ps", "--quiet", service), cwd=runtime)
    if not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
        raise ReceiptError("restricted service was not uniquely running")
    return container_id


def collect_red(*, runtime: Path, state_dir: Path, project: str, expected_head: str, expected_tree: str,
                service: str, network: str, sink: str, endpoints: dict[str, tuple[str, int]], output: Path,
                marker_proof: Path) -> str:
    marker = _source_marker(runtime, state_dir, project, expected_head, expected_tree)
    marker_hash = _read_marker_proof(marker_proof, expected_head, expected_tree)
    if _read_json(marker_proof) != marker:
        raise ReceiptError("red marker proof does not match initialized staging")
    initialized = marker["expected_images"]
    container_id = _service_id(runtime, state_dir, project, service)
    inspected = _inspect_container(container_id)
    image_id = inspected.get("Image")
    if image_id != initialized[service]:
        raise ReceiptError("red service image differs from initialized image")
    probes = _probe_results(image_id, container_id, endpoints, reachable=True)
    if not all(probes.values()):
        raise ReceiptError("controlled red endpoint was not reachable")
    proof = {
        "schema": RED_SCHEMA, "service": service, "runtime": {"head": expected_head, "tree": expected_tree},
        "image_id": image_id,
        "endpoint_sha256": {name: hashlib.sha256(f"{host}:{port}".encode()).hexdigest() for name, (host, port) in endpoints.items()}, "marker_proof_sha256": marker_hash,
        "network_shape_sha256": _red_network_shape(network, sink, container_id), "probes": probes,
    }
    _write_atomic(output, proof)
    return hashlib.sha256((canonical_receipt(proof) + "\n").encode()).hexdigest()


def collect_green(*, runtime: Path, state_dir: Path, project: str, expected_head: str, expected_tree: str,
                  network: str, endpoints: dict[str, tuple[str, int]], output: Path, marker_proof: Path) -> str:
    marker = _source_marker(runtime, state_dir, project, expected_head, expected_tree)
    marker_hash = _read_marker_proof(marker_proof, expected_head, expected_tree)
    if _read_json(marker_proof) != marker:
        raise ReceiptError("green marker proof does not match initialized staging")
    initialized = marker["expected_images"]
    target: dict[str, dict[str, bool]] = {}
    fixed: dict[str, dict[str, str | bool]] = {}
    fixed_control: dict[str, dict[str, str | bool]] = {}
    attribution: dict[str, str] = {}
    for service in POLICIES:
        container_id = _service_id(runtime, state_dir, project, service)
        image_id = _inspect_container(container_id).get("Image")
        if image_id != initialized[service]:
            raise ReceiptError("green service image differs from initialized image")
        target[service] = _probe_results(image_id, container_id, endpoints, reachable=False)
        fixed[service] = _fixed_outcomes(image_id, f"container:{container_id}")
        fixed_control[service] = _fixed_outcomes(image_id, network)
        attribution[service] = "host-bound-control-unreachable" if fixed_control[service]["metadata_ipv6"] in METADATA_DENIED_CLASSES else "target-only-denied"
    public_dns_control = _control_resolves_public_dns(initialized["ingress"], network)
    if (not all(all(results.values()) for results in target.values()) or not _network_control(initialized["ingress"], network, endpoints)
            or not public_dns_control or not _fixed_evidence_valid(fixed, fixed_control, attribution)):
        raise ReceiptError("live controlled green proof was not discriminating")
    proof = {"schema": GREEN_SCHEMA, "runtime": {"head": expected_head, "tree": expected_tree}, "images": initialized,
             "target": target, "control_reachable": True, "public_dns_control": public_dns_control, "fixed": fixed, "fixed_control": fixed_control,
             "metadata_ipv6_attribution": attribution, "marker_proof_sha256": marker_hash,
             "endpoint_sha256": {name: hashlib.sha256(f"{host}:{port}".encode()).hexdigest() for name, (host, port) in endpoints.items()},
             "fixed_definitions_sha256": hashlib.sha256(canonical_receipt({"public_dns": FIXED_PUBLIC_DNS, "metadata": FIXED_METADATA}).encode()).hexdigest()}
    _write_atomic(output, proof)
    return hashlib.sha256((canonical_receipt(proof) + "\n").encode()).hexdigest()


def _read_green_proof(path: Path, head: str, tree: str, images: dict[str, str], marker_proof_sha256: str) -> tuple[str, dict[str, dict[str, bool]], dict[str, dict[str, str | bool]], dict[str, dict[str, str | bool]], dict[str, str], dict[str, str]]:
    try: raw = path.read_bytes(); value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc: raise ReceiptError("green proof is unavailable") from exc
    expected_hash = hashlib.sha256(canonical_receipt({"public_dns": FIXED_PUBLIC_DNS, "metadata": FIXED_METADATA}).encode()).hexdigest()
    if (not isinstance(value, dict) or set(value) != {"schema", "runtime", "images", "target", "control_reachable", "public_dns_control", "fixed", "fixed_control", "metadata_ipv6_attribution", "marker_proof_sha256", "endpoint_sha256", "fixed_definitions_sha256"}
            or value.get("schema") != GREEN_SCHEMA or value.get("runtime") != {"head": head, "tree": tree}
            or value.get("images") != images or value.get("control_reachable") is not True or value.get("public_dns_control") is not True or value.get("fixed_definitions_sha256") != expected_hash):
        raise ReceiptError("green proof does not bind candidate")
    target, fixed, fixed_control, attribution, endpoints = value.get("target"), value.get("fixed"), value.get("fixed_control"), value.get("metadata_ipv6_attribution"), value.get("endpoint_sha256")
    if (not isinstance(target, dict) or set(target) != set(POLICIES) or any(results != {name: True for name in DENIED_CLASSES} for results in target.values())
            or not _fixed_evidence_valid(fixed, fixed_control, attribution) or value.get("marker_proof_sha256") != marker_proof_sha256):
        raise ReceiptError("green proof results are invalid")
    if not isinstance(endpoints, dict) or set(endpoints) != set(DENIED_CLASSES) or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{64}", item) for item in endpoints.values()):
        raise ReceiptError("green controlled endpoint binding is invalid")
    return hashlib.sha256(raw).hexdigest(), target, fixed, fixed_control, attribution, endpoints


def collect(*, runtime: Path, state_dir: Path, project: str, expected_head: str, expected_tree: str,
            proof_paths: dict[str, Path], green_path: Path, marker_proof: Path,
            cleanup_network: str, cleanup_sink: str) -> dict[str, Any]:
    marker = _source_marker(runtime, state_dir, project, expected_head, expected_tree)
    marker_sha256 = _read_marker_proof(marker_proof, expected_head, expected_tree)
    if _read_json(marker_proof) != marker:
        raise ReceiptError("receipt marker proof does not match initialized staging")
    initialized = marker["expected_images"]
    if not GIT_SHA.fullmatch(expected_head) or not GIT_SHA.fullmatch(expected_tree):
        raise ReceiptError("candidate source shape was invalid")
    observations: dict[str, dict[str, Any]] = {}
    proof_sha256: dict[str, str] = {}
    green_sha256, green, fixed, fixed_control, attribution, endpoint_sha256 = _read_green_proof(green_path, expected_head, expected_tree, initialized, marker_sha256)
    for service in POLICIES:
        container_id = _service_id(runtime, state_dir, project, service)
        inspected = _inspect_container(container_id)
        observations[service] = _service_observation(service, container_id, inspected, project, green[service], initialized[service])
        proof_sha256[service] = _read_red_proof(proof_paths[service], service, expected_head, expected_tree, initialized[service], endpoint_sha256, marker_sha256)
    cleanup = {"network_absent": _exact_name_absent("network", cleanup_network),
               "sink_absent": _exact_name_absent("container", cleanup_sink)}
    if cleanup != {"network_absent": True, "sink_absent": True}:
        raise ReceiptError("red cleanup was not proven")
    return build_receipt(head=expected_head, tree=expected_tree, kernel=platform.release(), architecture=platform.machine(),
                         docker_version=_stdout("docker", "version", "--format", "{{.Server.Version}}"),
                         compose_version=_stdout("docker", "compose", "version", "--short"), observations=observations,
                          marker=marker, marker_proof_sha256=marker_sha256, proof_sha256=proof_sha256,
                          green={service: observations[service]["denied"] for service in POLICIES}, cleanup=cleanup,
                          green_proof_sha256=green_sha256, fixed=fixed, fixed_control=fixed_control,
                          metadata_ipv6_attribution=attribution)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--project")
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-tree")
    parser.add_argument("--red-service", choices=tuple(POLICIES))
    parser.add_argument("--red-network")
    parser.add_argument("--red-sink")
    parser.add_argument("--marker-proof", type=Path)
    parser.add_argument("--red-proof", type=Path)
    parser.add_argument("--green-proof", type=Path)
    parser.add_argument("--red-ingress-proof", type=Path)
    parser.add_argument("--red-clinical-adapter-proof", type=Path)
    parser.add_argument("--cleanup-network")
    parser.add_argument("--cleanup-sink")
    parser.add_argument("--control-network")
    parser.add_argument("--controlled-ipv4")
    parser.add_argument("--controlled-ipv6")
    parser.add_argument("--controlled-dns")
    parser.add_argument("--synthetic-metadata-dns")
    parser.add_argument("--controlled-port", type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if not args.expected_head or not args.expected_tree or not args.evidence_dir:
                raise ReceiptError("candidate source is required for verification")
            errors = verify_receipt(json.loads(args.verify.read_text(encoding="utf-8")), expected_head=args.expected_head, expected_tree=args.expected_tree, evidence_dir=args.evidence_dir)
            if errors:
                raise ReceiptError("receipt verification failed")
            print("representative-clinical-egress: PASS")
            return 0
        if not all((args.state_dir, args.project, args.expected_head, args.expected_tree, args.controlled_ipv4, args.controlled_ipv6, args.controlled_dns, args.synthetic_metadata_dns, args.controlled_port)):
            raise ReceiptError("state, candidate source and controlled endpoints are required")
        endpoints = _endpoints(args.controlled_ipv4, args.controlled_ipv6, args.controlled_dns, args.synthetic_metadata_dns, args.controlled_port)
        frame = {"runtime": args.runtime_root.resolve(), "state_dir": args.state_dir.resolve(), "project": args.project,
                 "expected_head": args.expected_head, "expected_tree": args.expected_tree}
        if args.marker_proof and not any((args.red_proof, args.green_proof, args.output)):
            marker = _source_marker(frame["runtime"], frame["state_dir"], frame["project"], frame["expected_head"], frame["expected_tree"])
            _write_atomic(args.marker_proof, marker)
            print("representative-clinical-egress: MARKER-PROVED proof_sha256=" + hashlib.sha256((canonical_receipt(marker) + "\n").encode()).hexdigest())
            return 5
        if args.red_proof:
            if not all((args.red_service, args.red_network, args.red_sink, args.marker_proof)) or args.output:
                raise ReceiptError("red proof request is incomplete")
            proof = collect_red(**frame, service=args.red_service, network=args.red_network, sink=args.red_sink, endpoints=endpoints, output=args.red_proof, marker_proof=args.marker_proof)
            print("representative-clinical-egress: RED-DETECTED proof_sha256=" + proof)
            return 3
        if args.green_proof and not args.output:
            if not args.control_network or not args.marker_proof:
                raise ReceiptError("green control network is required")
            proof = collect_green(**frame, network=args.control_network, endpoints=endpoints, output=args.green_proof, marker_proof=args.marker_proof)
            print("representative-clinical-egress: GREEN-PROVED proof_sha256=" + proof)
            return 4
        if not all((args.output, args.cleanup_network, args.cleanup_sink, args.red_ingress_proof, args.red_clinical_adapter_proof, args.green_proof, args.marker_proof)):
            raise ReceiptError("green receipt request is incomplete")
        receipt = collect(**frame, proof_paths={"ingress": args.red_ingress_proof, "clinical-adapter": args.red_clinical_adapter_proof}, green_path=args.green_proof, marker_proof=args.marker_proof, cleanup_network=args.cleanup_network, cleanup_sink=args.cleanup_sink)
        errors = verify_receipt(receipt, expected_head=args.expected_head, expected_tree=args.expected_tree)
        if errors:
            raise ReceiptError("collection did not meet receipt policy")
        _write_atomic(args.output, receipt)
        print("representative-clinical-egress: PASS sha256=" + hashlib.sha256(canonical_receipt(receipt).encode()).hexdigest())
        return 0
    except (ReceiptError, json.JSONDecodeError, OSError) as exc:
        print("representative-clinical-egress: DENIED class=" + collector_error_class(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
