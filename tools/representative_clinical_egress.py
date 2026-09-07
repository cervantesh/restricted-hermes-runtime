#!/usr/bin/env python3
"""Collect a content-safe, candidate-bound clinical egress receipt."""
from __future__ import annotations

import argparse
import hashlib
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


class ReceiptError(RuntimeError):
    """A deliberately content-free collection failure."""


def canonical_receipt(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def build_receipt(*, head: str, tree: str, kernel: str, architecture: str,
                  docker_version: str, compose_version: str,
                  observations: dict[str, dict[str, Any]], marker_sha256: str,
                  initialized_images: dict[str, str], proof_sha256: dict[str, str],
                  green: dict[str, dict[str, bool]], cleanup: dict[str, bool]) -> dict[str, Any]:
    for service in POLICIES:
        if observations.get(service, {}).get("image_id") != initialized_images.get(service):
            raise ReceiptError("container image differs from initialized image")
    return {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "runtime": {"head": head, "tree": tree},
        "staging": {"marker_sha256": marker_sha256, "initialized_images": initialized_images},
        "host": {"kernel": kernel, "architecture": architecture},
        "docker": {"server_version": docker_version, "compose_version": compose_version},
        "services": observations,
        "red_witness": {
            "proof_sha256": proof_sha256, "green": green, "cleanup": cleanup,
            "metadata_scope": "synthetic-controlled-only",
        },
    }


def verify_receipt(value: object, *, expected_head: str, expected_tree: str) -> list[str]:
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
    if not isinstance(staging, dict) or set(staging) != {"marker_sha256", "initialized_images"} or not isinstance(staging.get("marker_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", staging["marker_sha256"]):
        errors.append("staging marker binding is invalid")
        initialized_images: dict[str, Any] = {}
    else:
        initialized_images = staging["initialized_images"] if isinstance(staging["initialized_images"], dict) else {}
        if set(initialized_images) != set(POLICIES) or any(not isinstance(image, str) or not SHA256.fullmatch(image) for image in initialized_images.values()):
            errors.append("initialized images are invalid")
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
    if not isinstance(witness, dict) or set(witness) != {"proof_sha256", "green", "cleanup", "metadata_scope"}:
        return errors + ["red witness fields are invalid"]
    proofs = witness["proof_sha256"]
    if not isinstance(proofs, dict) or set(proofs) != set(POLICIES) or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{64}", item) for item in proofs.values()):
        errors.append("red witness proof is invalid")
    green = witness["green"]
    if not isinstance(green, dict) or set(green) != set(POLICIES) or any(not isinstance(green.get(service), dict) or set(green[service]) != set(DENIED_CLASSES) or any(result is not True for result in green[service].values()) for service in POLICIES):
        errors.append("green controlled probes are incomplete")
    if witness.get("metadata_scope") != "synthetic-controlled-only":
        errors.append("metadata scope is invalid")
    cleanup = witness["cleanup"]
    if not isinstance(cleanup, dict) or cleanup != {"network_absent": True, "sink_absent": True}:
        errors.append("red witness cleanup is incomplete")
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


def _marker(state_dir: Path, project: str, head: str, tree: str) -> tuple[str, dict[str, str]]:
    path = state_dir / "staging-state.json"
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError("initialized staging marker is unavailable") from exc
    images = value.get("expected_images") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get("synthetic_only") is not True or value.get("project") != project
            or value.get("lifecycle") != "ready" or value.get("runtime_head") != head or value.get("runtime_tree") != tree
            or not isinstance(images, dict)):
        raise ReceiptError("initialized staging marker does not bind candidate")
    selected = {service: images.get(service) for service in POLICIES}
    if any(not isinstance(image, str) or not SHA256.fullmatch(image) for image in selected.values()):
        raise ReceiptError("initialized staging images are invalid")
    return hashlib.sha256(raw).hexdigest(), selected


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
    program = "import socket,sys\ntry:\n " + operation + "\nexcept OSError:\n sys.exit(1)"
    result = _run("docker", "run", "--rm", "--network", f"container:{container_id}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--entrypoint", "python", image_id, "-c", program, timeout=15)
    return result.returncode == 0


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
    return hashlib.sha256(canonical_receipt({"driver": "bridge", "internal": False, "ipv6": True, "members": 2}).encode()).hexdigest()


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


def _read_red_proof(path: Path, service: str, head: str, tree: str, image_id: str, endpoints: dict[str, tuple[str, int]]) -> str:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError("red proof is unavailable") from exc
    expected = {
        "schema": RED_SCHEMA, "service": service, "runtime": {"head": head, "tree": tree}, "image_id": image_id,
        "endpoint_sha256": {name: hashlib.sha256(f"{host}:{port}".encode()).hexdigest() for name, (host, port) in endpoints.items()},
        "probes": {name: True for name in DENIED_CLASSES},
    }
    if not isinstance(value, dict) or set(value) != {"schema", "service", "runtime", "image_id", "endpoint_sha256", "network_shape_sha256", "probes"} or any(value.get(key) != expected[key] for key in expected) or not isinstance(value.get("network_shape_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", value["network_shape_sha256"]):
        raise ReceiptError("red proof does not bind the controlled endpoint")
    return hashlib.sha256(raw).hexdigest()


def _service_observation(service: str, container_id: str, inspected: dict[str, Any], project: str,
                         endpoints: dict[str, tuple[str, int]], initialized_image: str) -> dict[str, Any]:
    policy = POLICIES[service]
    image_id = inspected.get("Image")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id) or image_id != initialized_image:
        raise ReceiptError("container image identity was invalid")
    denied = _probe_results(image_id, container_id, endpoints, reachable=False)
    permitted = {name: _probe(image_id, container_id, name, port) for name, port in policy["permitted_internal"].items()}
    blocked = {name: not _probe(image_id, container_id, name, port) for name, port in policy["denied_internal"].items()}
    return {
        "image_id": image_id, "networks": _network_classes(inspected, project, policy["networks"]),
        "proxy_environment_absent": _proxy_absent(inspected), "controls": _controls(service, inspected), "denied": denied,
        "permitted_internal": permitted, "denied_internal": blocked,
    }


def _source_marker(runtime: Path, state_dir: Path, project: str, head: str, tree: str) -> tuple[str, dict[str, str]]:
    if not GIT_SHA.fullmatch(head) or not GIT_SHA.fullmatch(tree):
        raise ReceiptError("candidate source shape was invalid")
    if _stdout("git", "status", "--porcelain", cwd=runtime):
        raise ReceiptError("candidate source is not frozen")
    if _git(runtime, "HEAD") != head or _git(runtime, "HEAD^{tree}") != tree:
        raise ReceiptError("candidate source did not match expected frame")
    return _marker(state_dir, project, head, tree)


def _service_id(runtime: Path, state_dir: Path, project: str, service: str) -> str:
    container_id = _stdout(*_compose(runtime, state_dir, project, "ps", "--quiet", service), cwd=runtime)
    if not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
        raise ReceiptError("restricted service was not uniquely running")
    return container_id


def collect_red(*, runtime: Path, state_dir: Path, project: str, expected_head: str, expected_tree: str,
                service: str, network: str, sink: str, endpoints: dict[str, tuple[str, int]], output: Path) -> str:
    _, initialized = _source_marker(runtime, state_dir, project, expected_head, expected_tree)
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
        "endpoint_sha256": {name: hashlib.sha256(f"{host}:{port}".encode()).hexdigest() for name, (host, port) in endpoints.items()},
        "network_shape_sha256": _red_network_shape(network, sink, container_id), "probes": probes,
    }
    _write_atomic(output, proof)
    return hashlib.sha256((canonical_receipt(proof) + "\n").encode()).hexdigest()


def collect(*, runtime: Path, state_dir: Path, project: str, expected_head: str, expected_tree: str,
            endpoints: dict[str, tuple[str, int]], proof_paths: dict[str, Path], cleanup_network: str, cleanup_sink: str) -> dict[str, Any]:
    marker_sha256, initialized = _source_marker(runtime, state_dir, project, expected_head, expected_tree)
    if not GIT_SHA.fullmatch(expected_head) or not GIT_SHA.fullmatch(expected_tree):
        raise ReceiptError("candidate source shape was invalid")
    observations: dict[str, dict[str, Any]] = {}
    proof_sha256: dict[str, str] = {}
    for service in POLICIES:
        container_id = _service_id(runtime, state_dir, project, service)
        inspected = _inspect_container(container_id)
        observations[service] = _service_observation(service, container_id, inspected, project, endpoints, initialized[service])
        proof_sha256[service] = _read_red_proof(proof_paths[service], service, expected_head, expected_tree, initialized[service], endpoints)
    cleanup = {"network_absent": _run("docker", "network", "inspect", cleanup_network).returncode != 0,
               "sink_absent": _run("docker", "container", "inspect", cleanup_sink).returncode != 0}
    if cleanup != {"network_absent": True, "sink_absent": True}:
        raise ReceiptError("red cleanup was not proven")
    return build_receipt(head=expected_head, tree=expected_tree, kernel=platform.release(), architecture=platform.machine(),
                         docker_version=_stdout("docker", "version", "--format", "{{.Server.Version}}"),
                         compose_version=_stdout("docker", "compose", "version", "--short"), observations=observations,
                         marker_sha256=marker_sha256, initialized_images=initialized, proof_sha256=proof_sha256,
                         green={service: observations[service]["denied"] for service in POLICIES}, cleanup=cleanup)


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
    parser.add_argument("--red-proof", type=Path)
    parser.add_argument("--red-ingress-proof", type=Path)
    parser.add_argument("--red-clinical-adapter-proof", type=Path)
    parser.add_argument("--cleanup-network")
    parser.add_argument("--cleanup-sink")
    parser.add_argument("--controlled-ipv4")
    parser.add_argument("--controlled-ipv6")
    parser.add_argument("--controlled-dns")
    parser.add_argument("--synthetic-metadata-dns")
    parser.add_argument("--controlled-port", type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if not args.expected_head or not args.expected_tree:
                raise ReceiptError("candidate source is required for verification")
            errors = verify_receipt(json.loads(args.verify.read_text(encoding="utf-8")), expected_head=args.expected_head, expected_tree=args.expected_tree)
            if errors:
                raise ReceiptError("receipt verification failed")
            print("representative-clinical-egress: PASS")
            return 0
        if not all((args.state_dir, args.project, args.expected_head, args.expected_tree, args.controlled_ipv4, args.controlled_ipv6, args.controlled_dns, args.synthetic_metadata_dns, args.controlled_port)):
            raise ReceiptError("state, candidate source and controlled endpoints are required")
        endpoints = _endpoints(args.controlled_ipv4, args.controlled_ipv6, args.controlled_dns, args.synthetic_metadata_dns, args.controlled_port)
        frame = {"runtime": args.runtime_root.resolve(), "state_dir": args.state_dir.resolve(), "project": args.project,
                 "expected_head": args.expected_head, "expected_tree": args.expected_tree}
        if args.red_proof:
            if not all((args.red_service, args.red_network, args.red_sink)) or args.output:
                raise ReceiptError("red proof request is incomplete")
            proof = collect_red(**frame, service=args.red_service, network=args.red_network, sink=args.red_sink, endpoints=endpoints, output=args.red_proof)
            print("representative-clinical-egress: RED-DETECTED proof_sha256=" + proof)
            return 3
        if not all((args.output, args.cleanup_network, args.cleanup_sink, args.red_ingress_proof, args.red_clinical_adapter_proof)):
            raise ReceiptError("green receipt request is incomplete")
        receipt = collect(**frame, endpoints=endpoints, proof_paths={"ingress": args.red_ingress_proof, "clinical-adapter": args.red_clinical_adapter_proof}, cleanup_network=args.cleanup_network, cleanup_sink=args.cleanup_sink)
        errors = verify_receipt(receipt, expected_head=args.expected_head, expected_tree=args.expected_tree)
        if errors:
            raise ReceiptError("collection did not meet receipt policy")
        _write_atomic(args.output, receipt)
        print("representative-clinical-egress: PASS sha256=" + hashlib.sha256(canonical_receipt(receipt).encode()).hexdigest())
        return 0
    except (ReceiptError, json.JSONDecodeError, OSError):
        print("representative-clinical-egress: DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
