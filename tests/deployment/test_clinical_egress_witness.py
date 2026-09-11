#!/usr/bin/env python3
"""Real Linux RED-to-GREEN egress witness for clinical staging.

The runner deliberately retains only the final canonical receipt.  Transient
Docker/Compose output and the staging status object may include local details,
so they remain in a mode-0700 scratch directory and are deleted at exit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STAGING = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
WITNESS = ROOT / "tools" / "clinical_egress_witness.py"
SINK_IMAGE = "nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284"
SERVICES = ("ingress", "clinical-adapter")


def command(*args: str, check: bool = True, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, encoding="utf-8", errors="replace", check=False, timeout=timeout)
    if check and result.returncode:
        name = Path(args[0]).name if args else "child"
        raise RuntimeError(f"clinical egress witness failed: {name} exit={result.returncode}")
    return result


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)


def exact_absent(kind: str, name: str) -> bool:
    args = ("docker", kind, "ls", "--format", "{{.Names}}")
    if kind == "container":
        args = ("docker", kind, "ls", "--all", "--format", "{{.Names}}")
    output = command(*args, check=False).stdout.splitlines()
    return name not in output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hrh-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        print("clinical-egress-witness: SKIP linux-required")
        return 77
    if args.output.exists() or not args.output.parent.is_dir() or not args.output.is_absolute():
        return 2
    if command("docker", "info", check=False).returncode:
        print("clinical-egress-witness: SKIP docker-unavailable")
        return 77
    scratch = Path(tempfile.mkdtemp(prefix="clinical-egress-witness-"))
    scratch.chmod(0o700)
    project = "clinicalstagingegress" + secrets.token_hex(6)
    state = scratch / f"{project}.synthetic-clinical-staging"
    network = project + "-red"
    sink = project + "-sink"
    created_network = created_sink = initialized = False
    phase = "preflight"

    def staging(command_name: str) -> dict[str, Any]:
        result = command(sys.executable, str(STAGING), "--runtime-root", str(ROOT), "--hrh-root", str(args.hrh_root), "--state-dir", str(state), "--project", project, command_name, timeout=2400)
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise RuntimeError("clinical egress witness failed: staging output")
        return value

    def compose(*parts: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return command("docker", "compose", "--env-file", str(state / "compose.env"), "--project-name", project, "--file", str(ROOT / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"), "--file", str(ROOT / "deploy" / "clinical-staging" / "compose.yaml"), *parts, check=check, timeout=300)

    try:
        phase = "initialize"
        staging("init")
        initialized = True
        phase = "create-controlled-network"
        if command("docker", "network", "create", "--ipv6", network, check=False).returncode:
            print("clinical-egress-witness: SKIP controlled-ipv6-network-unavailable")
            return 77
        created_network = True
        phase = "create-controlled-sink"
        command("docker", "run", "--detach", "--name", sink, "--network", network, "--network-alias", "controlled-probe", "--network-alias", "synthetic-metadata-probe", SINK_IMAGE)
        created_sink = True
        inspect = json.loads(command("docker", "inspect", sink).stdout)[0]["NetworkSettings"]["Networks"][network]
        controlled_v4, controlled_v6 = inspect["IPAddress"], inspect["GlobalIPv6Address"]
        if not controlled_v4 or not controlled_v6:
            print("clinical-egress-witness: SKIP controlled-ipv6-address-unavailable")
            return 77
        probe = """import json,os,socket
def v4(host, port):
 try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1);s.connect((host,port));s.close();return True
 except OSError:return False
def v6(host, port):
 try:
  s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.settimeout(1);s.connect((host,port,0,0));s.close();return True
 except OSError:return False
def dns(host):
 try: socket.getaddrinfo(host,443);return True
 except OSError:return False
print(json.dumps({'public_ipv4':v4('198.51.100.1',443),'public_ipv6':v6('2001:db8::1',443),'public_dns':dns('example.com'),'metadata_ipv4':v4('169.254.169.254',80),'metadata_ipv6':v6('fd00:ec2::254',80),'metadata_dns':dns('metadata.google.internal'),'proxy_environment':any(os.getenv(k) is not None for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'))}))"""

        def service_probe(service: str, *, red: bool = False) -> dict[str, bool]:
            code = probe if not red else "import json,socket\ns=socket.create_connection(('" + controlled_v4 + "',80),timeout=2);s.close();print(json.dumps({'reachable':True}))"
            result = compose("exec", "--no-TTY", service, "python", "-c", code, check=False)
            if result.returncode:
                return {"reachable": False} if red else {}
            value = json.loads(result.stdout)
            return value if isinstance(value, dict) and all(isinstance(item, bool) for item in value.values()) else {}

        red: dict[str, bool] = {}
        for service in SERVICES:
            phase = "red-" + service
            target = compose("ps", "--quiet", service).stdout.strip()
            if not target:
                raise RuntimeError("clinical egress witness failed: service lookup")
            command("docker", "network", "connect", network, target)
            try:
                red[service] = service_probe(service, red=True) == {"reachable": True}
            finally:
                command("docker", "network", "disconnect", network, target)
            if not red[service]:
                raise RuntimeError("clinical egress witness failed: controlled RED was not reachable")
        phase = "green-status"
        status = staging("status")
        observations: dict[str, dict[str, dict[str, bool]]] = {}
        allowed = {"ingress": ("mattermost", 8065, "mattermost"), "clinical-adapter": ("hrh-tls", 8443, "hrh_tls")}
        for service in SERVICES:
            phase = "green-" + service
            result = service_probe(service)
            if set(result) != {"public_ipv4", "public_ipv6", "public_dns", "metadata_ipv4", "metadata_ipv6", "metadata_dns", "proxy_environment"}:
                raise RuntimeError("clinical egress witness failed: denied probe output")
            host, port, name = allowed[service]
            permitted = compose("exec", "--no-TTY", service, "python", "-c", f"import json,socket;s=socket.create_connection(('{host}',{port}),timeout=2);s.close();print(json.dumps({{'{name}':True}}))", check=False)
            allowed_value = json.loads(permitted.stdout) if permitted.returncode == 0 else {}
            observations[service] = {"denied": {key: not value for key, value in result.items()}, "allowed": allowed_value}
        expected_networks = {"ingress": ["mattermost_edge"], "clinical-adapter": ["clinical_upstream"]}
        networks: dict[str, list[str]] = {}
        for service in SERVICES:
            target = compose("ps", "--quiet", service).stdout.strip()
            inspected = json.loads(command("docker", "inspect", target).stdout)[0]
            names = sorted(inspected["NetworkSettings"]["Networks"])
            prefix = project + "_"
            if not all(name.startswith(prefix) for name in names):
                raise RuntimeError("clinical egress witness failed: unexpected network membership")
            networks[service] = [name.removeprefix(prefix) for name in names]
        if networks != expected_networks:
            raise RuntimeError("clinical egress witness failed: topology was not restored")
        environment = {"system": platform.system(), "kernel": platform.release(), "architecture": platform.machine(), "docker": command("docker", "version", "--format", "{{.Server.Version}}").stdout.strip(), "compose": command("docker", "compose", "version", "--short").stdout.strip()}
        phase = "cleanup-controlled-resources"
        command("docker", "container", "rm", "--force", sink)
        created_sink = False
        command("docker", "network", "rm", network)
        created_network = False
        if not exact_absent("container", sink) or not exact_absent("network", network):
            raise RuntimeError("clinical egress witness failed: cleanup")
        phase = "receipt"
        inputs = {"status": status, "observations": observations, "environment": environment, "networks": networks, "red": red, "cleanup": {"network_absent": True, "sink_absent": True}}
        for name, value in inputs.items():
            write_json(scratch / f"{name}.json", value)
        command(sys.executable, str(WITNESS), "build", *(item for name in inputs for item in (f"--{name}", str(scratch / f"{name}.json"))), "--output", str(args.output))
        command(sys.executable, str(WITNESS), "verify", "--receipt", str(args.output), "--status", str(scratch / "status.json"))
        print("clinical-egress-witness: PASS receipt_sha256=" + hashlib.sha256(args.output.read_bytes()).hexdigest())
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, KeyError, json.JSONDecodeError):
        args.output.unlink(missing_ok=True)
        print(f"clinical-egress-witness: DENIED phase={phase}", file=sys.stderr)
        return 2
    finally:
        if created_sink:
            command("docker", "container", "rm", "--force", sink, check=False)
        if created_network:
            command("docker", "network", "rm", network, check=False)
        if initialized and (state / "staging-state.json").exists():
            command(sys.executable, str(STAGING), "--runtime-root", str(ROOT), "--hrh-root", str(args.hrh_root), "--state-dir", str(state), "--project", project, "destroy", check=False, timeout=900)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
