#!/usr/bin/env python3
"""Exact-digest, synthetic-only Mattermost ESR staging conformance harness."""
from __future__ import annotations

import atexit
import base64
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "deployment" / "mattermost-esr-staging"
COMPOSE_FILE = HARNESS / "compose.yaml"
MM_IMAGE = "mattermost/mattermost-team-edition:11.7.10@sha256:84a041d836bf6fbf6a9a78ab699fa5ebe5437bfb6a514b5afad4121fa3800696"
PG_IMAGE = "postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f"
PROJECT = f"mmesr{os.getpid()}_{int(time.time())}"
if re.fullmatch(r"[a-z0-9_]+", PROJECT) is None:
    raise SystemExit("invalid Compose project identity")

STATE = Path(tempfile.mkdtemp(prefix="mattermost-esr-"))
SEED = STATE / "seed"
EVIDENCE = SEED / "evidence"
ENV_FILE = STATE / "compose.env"
INGRESS_IMAGE = f"restricted-mattermost-esr:{PROJECT}"
MUTANT_IMAGE = f"restricted-mattermost-esr-mutant:{PROJECT}"
CREATED = False


def run(*args: str, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args), cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False,
        encoding="utf-8", errors="replace",
    )
    if check and result.returncode:
        raise RuntimeError(f"command failed ({args[0]}): exit={result.returncode}")
    return result


def compose(*args: str, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return run(
        "docker", "compose", "--env-file", str(ENV_FILE), "--project-name", PROJECT,
        "--file", str(COMPOSE_FILE), *args, check=check, timeout=timeout,
    )


def phase(name: str) -> None:
    print(f"Mattermost ESR phase={name}", flush=True)


def no_resources() -> bool:
    commands = (("ps", "-aq"), ("network", "ls", "-q"), ("volume", "ls", "-q"))
    for command in commands:
        result = run("docker", *command, "--filter", f"label=com.docker.compose.project={PROJECT}")
        if result.stdout.strip():
            return False
    return True


def no_run_images() -> bool:
    return all(run("docker", "image", "inspect", image, check=False).returncode != 0 for image in (INGRESS_IMAGE, MUTANT_IMAGE))


def cleanup() -> None:
    global CREATED
    try:
        if CREATED:
            compose("down", "--volumes", "--remove-orphans", check=False, timeout=180)
        run("docker", "image", "rm", "-f", INGRESS_IMAGE, MUTANT_IMAGE, check=False, timeout=120)
    finally:
        if not no_resources() or not no_run_images():
            print("Mattermost ESR cleanup=FAILED", file=sys.stderr)
        shutil.rmtree(STATE, ignore_errors=True)


atexit.register(cleanup)


def write_secret(name: str, value: str) -> None:
    path = SEED / name
    path.write_text(value, encoding="ascii")
    os.chmod(path, 0o600)


def certificate_material() -> None:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mattermost ESR test CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    wrong_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong ESR test CA")])
    wrong_ca = (
        x509.CertificateBuilder().subject_name(wrong_ca_name).issuer_name(wrong_ca_name)
        .public_key(wrong_ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(wrong_ca_key, hashes.SHA256())
    )

    def server(host: str) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        )

    good_cert, good_key = server("mattermost")
    wrong_cert, wrong_key = server("wrong.invalid")
    values = {
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM), "wrong-ca.crt": wrong_ca.public_bytes(serialization.Encoding.PEM),
        "server-good.crt": good_cert, "server-good.key": good_key,
        "server-wrong.crt": wrong_cert, "server-wrong.key": wrong_key,
    }
    for name, value in values.items():
        path = SEED / name
        path.write_bytes(value)
        os.chmod(path, 0o600)


def prepare() -> None:
    SEED.mkdir()
    EVIDENCE.mkdir()
    for name in ("admin_password", "actor_password", "denied_password", "run_salt", "wrong_token"):
        write_secret(name, secrets.token_hex(32))
    write_secret("postgres_password", secrets.token_hex(32))  # URI-safe DSN interpolation.
    certificate_material()
    env = {
        "MM_ESR_HARNESS": HARNESS.as_posix(), "MM_ESR_SEED": SEED.as_posix(),
        "MM_ESR_INGRESS_IMAGE": INGRESS_IMAGE,
        "MM_ESR_POSTGRES_PASSWORD": (SEED / "postgres_password").read_text(encoding="ascii"),
        "MM_ESR_POLICY_PUBLIC_KEY": "placeholder",
        "MM_ESR_POSTGRES_IP": "192.0.2.2",
    }
    ENV_FILE.write_text("".join(f"{key}={value}\n" for key, value in env.items()), encoding="utf-8")
    os.chmod(ENV_FILE, 0o600)


def set_env(name: str, value: str) -> None:
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    ENV_FILE.write_text("\n".join(f"{name}={value}" if line.startswith(name + "=") else line for line in lines) + "\n", encoding="utf-8")


def exec_controller(*args: str, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = compose("exec", "--no-TTY", "controller", "python", "/harness/control.py", *args, timeout=timeout, check=False)
    if result.returncode:
        diagnostic = re.sub(r"\b[a-z0-9]{26}\b", "[id]", result.stderr[-2000:])
        for secret_path in SEED.glob("*_password"):
            diagnostic = diagnostic.replace(secret_path.read_text(encoding="ascii"), "[secret]")
        raise RuntimeError("controller command failed: " + args[0] + "; " + diagnostic.replace("\n", " | "))
    return result


def wait_mattermost_local(deadline: int = 180) -> None:
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        status = compose(
            "exec", "--no-TTY", "mattermost", "/mattermost/bin/mmctl", "--local", "system", "status",
            check=False,
        )
        if status.returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError("Mattermost local readiness deadline exceeded")


def wait_ingress(*, ready: bool, deadline: int = 45, after_ready_count: int = 0) -> str:
    end = time.monotonic() + deadline
    logs = ""
    while time.monotonic() < end:
        logs = compose("logs", "--no-color", "ingress", check=False).stdout
        if logs.count("mattermost_ingress_outcome=authenticated_ready") > after_ready_count:
            if not ready:
                raise RuntimeError("negative ingress unexpectedly became authenticated-ready")
            return logs
        status = compose("ps", "--all", "--format", "json", "ingress", check=False).stdout.lower()
        if not ready and ("mattermost_ingress_outcome=terminal" in logs or '"state":"exited"' in status or '"state": "exited"' in status):
            return logs
        time.sleep(0.25)
    outcome = "authenticated-ready deadline exceeded" if ready else "negative ingress did not fail terminally"
    raise RuntimeError(outcome + "; content-free logs=" + logs[-500:].replace("\n", " | "))


def replace_ingress(*, image: str = INGRESS_IMAGE) -> None:
    set_env("MM_ESR_INGRESS_IMAGE", image)
    compose("up", "--detach", "--no-deps", "--force-recreate", "ingress", timeout=120)


def negative(origin: str, ca: str, token: str, *, verify_replies: bool = True) -> None:
    exec_controller("policy", origin, ca, token)
    replace_ingress()
    wait_ingress(ready=False)
    if verify_replies:
        exec_controller("assert-zero")


def image_evidence() -> None:
    receipt: dict[str, object] = {"host": {"os": platform.system(), "architecture": platform.machine()}, "images": {}}
    for reference, service in ((MM_IMAGE, "mattermost"), (PG_IMAGE, "postgres")):
        inspect = json.loads(run("docker", "image", "inspect", reference).stdout)[0]
        digest = reference.split("@", 1)[1]
        if inspect.get("Os") != "linux" or inspect.get("Architecture") != "amd64":
            raise RuntimeError("pinned image platform mismatch")
        if not any(item.endswith("@" + digest) for item in inspect.get("RepoDigests", [])):
            raise RuntimeError("pinned image digest mismatch")
        container = json.loads(compose("ps", "--format", "json", service).stdout.splitlines()[0])
        runtime = run("docker", "inspect", "--format", "{{.Image}}", container["ID"]).stdout.strip()
        if runtime != inspect["Id"]:
            raise RuntimeError("running container does not use the inspected pinned image")
        receipt["images"][service] = {"reference": reference, "image_id": inspect["Id"], "os": "linux", "architecture": "amd64"}
    (EVIDENCE / "images.json").write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def main() -> None:
    global CREATED
    if not no_resources():
        raise RuntimeError("refusing pre-existing project resources")
    phase("prepare")
    prepare()
    phase("build")
    compose("build", "ingress", timeout=600)
    phase("seed")
    compose("up", "--detach", "controller")
    CREATED = True
    exec_controller("seed")
    phase("start")
    compose("up", "--detach", "postgres", "mattermost", "uds", timeout=300)
    image_evidence()
    exec_controller("wait-ready", timeout=240)
    admin_password = (SEED / "admin_password").read_text(encoding="ascii")
    created = compose(
        "exec", "--no-TTY", "mattermost", "/mattermost/bin/mmctl", "--local", "user", "create",
        "--email", "admin@esr.invalid", "--username", "esradmin", "--password", admin_password,
        "--system-admin", "--email-verified", "--disable-welcome-email", "--quiet", check=False,
    )
    if created.returncode and "already exists" not in (created.stdout + created.stderr).lower():
        raise RuntimeError("local temporary administrator bootstrap failed")
    phase("bootstrap")
    exec_controller("bootstrap")
    exec_controller("bootstrap")
    exec_controller("policy", "https://mattermost:8065", "correct", "correct")
    public_key = exec_controller("public-key").stdout.strip()
    if not public_key or not base64.b64decode(public_key, validate=True):
        raise RuntimeError("policy public key unavailable")
    set_env("MM_ESR_POLICY_PUBLIC_KEY", public_key)
    exec_controller("pending-probe")

    phase("tls-negatives")
    negative("https://mattermost:8065", "wrong", "correct")
    exec_controller("tls", "wrong")
    compose("restart", "mattermost")
    wait_mattermost_local()
    negative("https://mattermost:8065", "correct", "correct", verify_replies=False)
    exec_controller("tls", "good")
    compose("restart", "mattermost")
    exec_controller("wait-ready", timeout=240)
    exec_controller("assert-zero")
    negative("https://mattermost-alternate:8065", "correct", "correct")
    negative("http://mattermost:8065", "correct", "correct")

    phase("authenticated-ready")
    exec_controller("policy", "https://mattermost:8065", "correct", "correct")
    replace_ingress()
    ingress_logs = wait_ingress(ready=True)
    (EVIDENCE / "ingress.log").write_text(ingress_logs, encoding="utf-8")

    phase("real-server-scenarios")
    phase("scenario-root")
    exec_controller("scenario", "root")
    phase("cold-ingress-cycle")
    replace_ingress()
    wait_ingress(ready=True)
    for scenario in (
        "continuation", "denied-user", "denied-channel", "public", "dm", "gm", "file",
        "edited-and-unmentioned", "removed-membership",
    ):
        phase("scenario-" + scenario)
        exec_controller("scenario", scenario)

    phase("network-negatives")
    postgres_container = json.loads(compose("ps", "--format", "json", "postgres").stdout.splitlines()[0])["ID"]
    networks = json.loads(run("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", postgres_container).stdout)
    postgres_ips = [value.get("IPAddress") for value in networks.values() if value.get("IPAddress")]
    if len(postgres_ips) != 1:
        raise RuntimeError("PostgreSQL network identity changed")
    set_env("MM_ESR_POSTGRES_IP", postgres_ips[0])
    probe = compose("run", "--rm", "--no-deps", "probe", timeout=120, check=False)
    if probe.returncode:
        raise RuntimeError("ingress-equivalent network isolation probe failed: " + (probe.stdout + probe.stderr)[-500:].replace("\n", " | "))
    (EVIDENCE / "network.json").write_text(probe.stdout.strip(), encoding="utf-8")

    phase("recreate-mattermost")
    ready_count = compose("logs", "--no-color", "ingress").stdout.count("mattermost_ingress_outcome=authenticated_ready")
    compose("up", "--detach", "--no-deps", "--force-recreate", "mattermost", timeout=180)
    exec_controller("wait-ready", timeout=240)
    wait_ingress(ready=True, after_ready_count=ready_count)
    exec_controller("scenario", "restart-reply")

    phase("authorization-mutation")
    run(
        "docker", "build", "--build-arg", f"BASE_IMAGE={INGRESS_IMAGE}", "--tag", MUTANT_IMAGE,
        "--file", str(HARNESS / "Dockerfile.authorization-mutation"), str(HARNESS), timeout=300,
    )
    replace_ingress(image=MUTANT_IMAGE)
    wait_ingress(ready=True)
    exec_controller("scenario", "mutation-denied-channel")

    phase("authentication-negative")
    before_wrong_token = json.loads(exec_controller("effect-counters").stdout)
    exec_controller("websocket-wrong-token")
    after_wrong_token = json.loads(exec_controller("effect-counters").stdout)
    if after_wrong_token != before_wrong_token:
        raise RuntimeError("wrong-token WebSocket changed processing counters")
    exec_controller("policy", "https://mattermost:8065", "correct", "wrong")
    replace_ingress(image=INGRESS_IMAGE)
    wait_ingress(ready=False)
    if json.loads(exec_controller("effect-counters").stdout) != before_wrong_token:
        raise RuntimeError("wrong-token production ingress changed processing counters")

    phase("evidence")
    report = exec_controller("report").stdout.strip()
    json.loads(report)
    (EVIDENCE / "report.json").write_text(report, encoding="utf-8")
    exec_controller("secret-scan", "/seed/evidence/ingress.log", "/seed/evidence/network.json", "/seed/evidence/report.json", "/seed/evidence/images.json")
    print(report)
    phase("cleanup")
    compose("down", "--volumes", "--remove-orphans", timeout=180)
    run("docker", "image", "rm", "-f", INGRESS_IMAGE, MUTANT_IMAGE, timeout=120)
    if not no_resources() or not no_run_images():
        raise RuntimeError("bounded cleanup left Compose resources or test images")
    CREATED = False
    shutil.rmtree(STATE)
    if STATE.exists():
        raise RuntimeError("bounded cleanup left staging state")
    atexit.unregister(cleanup)
    print("Mattermost ESR exact-digest staging conformance: PASS", flush=True)


if __name__ == "__main__":
    main()
