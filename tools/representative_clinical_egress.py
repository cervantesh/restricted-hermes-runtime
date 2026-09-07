#!/usr/bin/env python3
"""Collect a content-safe, candidate-bound clinical egress receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "restricted-runtime-representative-clinical-egress-receipt.v1"
DENIED_CLASSES = (
    "direct_ipv4", "direct_ipv6", "public_dns", "metadata_ipv4",
    "metadata_ipv6", "metadata_dns",
)
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
                  observations: dict[str, dict[str, Any]], red_detected: bool,
                  cleanup_complete: bool) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "runtime": {"head": head, "tree": tree},
        "host": {"kernel": kernel, "architecture": architecture},
        "docker": {"server_version": docker_version, "compose_version": compose_version},
        "services": observations,
        "red_witness": {"detected": red_detected, "cleanup_complete": cleanup_complete},
    }


def verify_receipt(value: object, *, expected_head: str, expected_tree: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["receipt is not an object"]
    if set(value) != {"schema", "synthetic_non_phi_only", "runtime", "host", "docker", "services", "red_witness"}:
        errors.append("receipt fields are not exact")
    if value.get("schema") != SCHEMA or value.get("synthetic_non_phi_only") is not True:
        errors.append("receipt schema or synthetic marker is invalid")
    runtime = value.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("head") != expected_head:
        errors.append("runtime head does not bind the candidate")
    if not isinstance(runtime, dict) or runtime.get("tree") != expected_tree:
        errors.append("runtime tree does not bind the candidate")
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
    if not isinstance(witness, dict) or set(witness) != {"detected", "cleanup_complete"} or witness.get("detected") is not True:
        errors.append("red witness is missing")
    if not isinstance(witness, dict) or witness.get("cleanup_complete") is not True:
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


def _probe(image_id: str, container_id: str, host: str, port: int) -> bool:
    program = "import socket,sys\ntry:\n socket.create_connection((" + repr(host) + "," + str(port) + "), 2).close()\nexcept OSError:\n sys.exit(1)"
    result = _run("docker", "run", "--rm", "--network", f"container:{container_id}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--entrypoint", "python", image_id, "-c", program, timeout=15)
    return result.returncode == 0


def _cleanup_absent(network: str, sink: str) -> bool:
    return _run("docker", "network", "inspect", network).returncode != 0 and _run("docker", "container", "inspect", sink).returncode != 0


def _service_observation(service: str, container_id: str, inspected: dict[str, Any], project: str, red_host: str | None, red_port: int | None) -> dict[str, Any]:
    policy = POLICIES[service]
    image_id = inspected.get("Image")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id):
        raise ReceiptError("container image identity was invalid")
    sources = {
        "direct_ipv4": ("198.18.0.1", 443), "direct_ipv6": ("2001:db8::1", 443),
        "public_dns": ("example.invalid", 443), "metadata_ipv4": ("169.254.169.254", 80),
        "metadata_ipv6": ("fd00:ec2::254", 80), "metadata_dns": ("metadata.google.internal", 80),
    }
    denied = {name: not _probe(image_id, container_id, host, port) for name, (host, port) in sources.items()}
    if red_host is not None and red_port is not None and not _probe(image_id, container_id, red_host, red_port):
        raise ReceiptError("red mutation was not detected")
    permitted = {name: _probe(image_id, container_id, name, port) for name, port in policy["permitted_internal"].items()}
    blocked = {name: not _probe(image_id, container_id, name, port) for name, port in policy["denied_internal"].items()}
    return {
        "image_id": image_id, "networks": _network_classes(inspected, project, policy["networks"]),
        "proxy_environment_absent": _proxy_absent(inspected), "controls": _controls(service, inspected), "denied": denied,
        "permitted_internal": permitted, "denied_internal": blocked,
    }


def collect(*, runtime: Path, state_dir: Path, project: str, expected_head: str, expected_tree: str,
            red_host: str | None, red_port: int | None, red_detected: bool, cleanup_complete: bool,
            cleanup_network: str | None, cleanup_sink: str | None, red_service: str | None) -> dict[str, Any]:
    if not GIT_SHA.fullmatch(expected_head) or not GIT_SHA.fullmatch(expected_tree):
        raise ReceiptError("candidate source shape was invalid")
    if _stdout("git", "status", "--porcelain", cwd=runtime):
        raise ReceiptError("candidate source is not frozen")
    if _git(runtime, "HEAD") != expected_head or _git(runtime, "HEAD^{tree}") != expected_tree:
        raise ReceiptError("candidate source did not match expected frame")
    observations: dict[str, dict[str, Any]] = {}
    for service in POLICIES:
        container_id = _stdout(*_compose(runtime, state_dir, project, "ps", "--quiet", service), cwd=runtime)
        if not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
            raise ReceiptError("restricted service was not uniquely running")
        observations[service] = _service_observation(service, container_id, _inspect_container(container_id), project,
                                                     red_host if service == red_service else None,
                                                     red_port if service == red_service else None)
    if cleanup_complete and (cleanup_network is None or cleanup_sink is None or not _cleanup_absent(cleanup_network, cleanup_sink)):
        raise ReceiptError("red cleanup was not proven")
    return build_receipt(head=expected_head, tree=expected_tree, kernel=platform.release(), architecture=platform.machine(),
                         docker_version=_stdout("docker", "version", "--format", "{{.Server.Version}}"),
                         compose_version=_stdout("docker", "compose", "version", "--short"), observations=observations,
                         red_detected=red_detected, cleanup_complete=cleanup_complete)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--project")
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-tree")
    parser.add_argument("--red-host")
    parser.add_argument("--red-port", type=int)
    parser.add_argument("--red-service", choices=tuple(POLICIES))
    parser.add_argument("--red-detected", action="store_true")
    parser.add_argument("--cleanup-complete", action="store_true")
    parser.add_argument("--cleanup-network")
    parser.add_argument("--cleanup-sink")
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
        if not all((args.state_dir, args.project, args.expected_head, args.expected_tree, args.output)):
            raise ReceiptError("state, project, candidate source and output are required")
        if (args.red_host is None) != (args.red_port is None):
            raise ReceiptError("red mutation target is incomplete")
        if (args.red_host is None) != (args.red_service is None):
            raise ReceiptError("red mutation service is incomplete")
        if (args.cleanup_network is None) != (args.cleanup_sink is None):
            raise ReceiptError("cleanup proof target is incomplete")
        receipt = collect(runtime=args.runtime_root.resolve(), state_dir=args.state_dir.resolve(), project=args.project,
                          expected_head=args.expected_head, expected_tree=args.expected_tree, red_host=args.red_host,
                          red_port=args.red_port, red_detected=args.red_detected, cleanup_complete=args.cleanup_complete,
                          cleanup_network=args.cleanup_network, cleanup_sink=args.cleanup_sink, red_service=args.red_service)
        errors = verify_receipt(receipt, expected_head=args.expected_head, expected_tree=args.expected_tree)
        if errors:
            raise ReceiptError("collection did not meet receipt policy")
        args.output.write_text(canonical_receipt(receipt) + "\n", encoding="utf-8")
        print("representative-clinical-egress: PASS sha256=" + hashlib.sha256(canonical_receipt(receipt).encode()).hexdigest())
        return 0
    except (ReceiptError, json.JSONDecodeError, OSError):
        print("representative-clinical-egress: DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
