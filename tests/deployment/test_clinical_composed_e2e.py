#!/usr/bin/env python3
"""Real synthetic Mattermost -> restricted runtime -> HRH composed E2E."""
from __future__ import annotations

import atexit
import base64
import importlib.util
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
HRH_MODE = os.environ.get("CLINICAL_E2E_HRH_MODE", "source-build")
HRH_ROOT_VALUE = os.environ.get("CLINICAL_E2E_HRH_ROOT")
HRH_ROOT = Path(HRH_ROOT_VALUE).resolve() if HRH_ROOT_VALUE else None
HARNESS = ROOT / "tests" / "deployment" / "clinical-composed-e2e"
COMPOSE_FILE = HARNESS / "compose.yaml"
SOURCE_BUILD_COMPOSE_FILE = HARNESS / "compose.source-build.yaml"
PUBLISHED_HRH_COMPOSE_FILE = HARNESS / "compose.published-hrh.yaml"
MM_IMAGE = "mattermost/mattermost-team-edition:11.7.10@sha256:84a041d836bf6fbf6a9a78ab699fa5ebe5437bfb6a514b5afad4121fa3800696"
PG_IMAGE = "postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f"
NGINX_IMAGE = "nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284"
RUNTIME_PRODUCT_SHA = "8049dd7612176b33e65ef19f61f5699aef7e0a28"
HRH_SHA = "e30a4f968de6727519f49c08369f561fdf269ec5"
HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"
COMPOSE_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SAFE_COMPOSE_PROCESS_ENV = (
    "PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
)
PROJECT = f"clinicale2e{os.getpid()}_{int(time.time())}"
STATE = Path(tempfile.mkdtemp(prefix="clinical-composed-e2e-"))
SEED = STATE / "seed"
EVIDENCE = STATE / "evidence"
ENV_FILE = STATE / "compose.env"
CANDIDATE_MANIFEST = os.environ.get("RESTRICTED_IMMUTABLE_CANDIDATE_MANIFEST")
PUBLISHED_HRH_INPUTS = {
    "trust": os.environ.get("CLINICAL_E2E_HRH_TRUST_DECLARATION"),
    "receipt": os.environ.get("CLINICAL_E2E_HRH_RECEIPT"),
    "public_key": os.environ.get("CLINICAL_E2E_HRH_PUBLIC_KEY"),
    "docker_config": os.environ.get("CLINICAL_E2E_HRH_DOCKER_CONFIG"),
}


def candidate_subject_image(name: str) -> str | None:
    if not CANDIDATE_MANIFEST:
        return None
    try:
        manifest = json.loads(Path(CANDIDATE_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("immutable candidate manifest is unreadable") from exc
    for subject in manifest.get("subjects", []):
        if isinstance(subject, dict) and subject.get("name") == name:
            image = subject.get("image")
            if not isinstance(image, str) or "@sha256:" not in image:
                raise RuntimeError("published subject requires an immutable digest")
            return image
    raise RuntimeError(f"immutable candidate subject is missing: {name}")


INGRESS_IMAGE = candidate_subject_image("restricted-mattermost-ingress") or f"restricted-clinical-ingress:{PROJECT}"
ADAPTER_IMAGE = candidate_subject_image("restricted-clinical-adapter") or f"restricted-clinical-adapter:{PROJECT}"
PUBLISHED_SUBJECTS = CANDIDATE_MANIFEST is not None
CREATED = False
SOURCE_FRAME: dict[str, str] = {}
PUBLISHED_HRH_VERIFICATION: dict[str, object] | None = None


def selected_compose_files() -> tuple[Path, Path]:
    if HRH_MODE == "source-build":
        return COMPOSE_FILE, SOURCE_BUILD_COMPOSE_FILE
    if HRH_MODE == "published":
        return COMPOSE_FILE, PUBLISHED_HRH_COMPOSE_FILE
    raise RuntimeError("CLINICAL_E2E_HRH_MODE must be source-build or published")


def run(
    *args: str,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout,
        check=False, encoding="utf-8", errors="replace",
    )
    if check and result.returncode:
        command = Path(args[0]).name if args and Path(args[0]).name in {"docker", "git"} else "child"
        raise RuntimeError(f"command failed: {command} exit={result.returncode}")
    return result


def sealed_compose_environment() -> dict[str, str]:
    """Return only Docker transport variables plus the generated E2E contract.

    Docker Compose resolves shell variables before values from ``--env-file``.
    Passing the inherited process environment would therefore let a caller's
    ``CLINICAL_*`` setting silently replace this run's pinned HRH frame.
    """
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError("clinical composed E2E environment is unavailable") from exc
    sealed: dict[str, str] = {}
    for line in lines:
        key, delimiter, value = line.partition("=")
        if not delimiter or not COMPOSE_ENV_RE.fullmatch(key) or key in sealed:
            raise RuntimeError("clinical composed E2E environment is malformed")
        sealed[key] = value
    if not sealed:
        raise RuntimeError("clinical composed E2E environment is empty")
    process = {key: os.environ[key] for key in SAFE_COMPOSE_PROCESS_ENV if key in os.environ}
    process.update(sealed)
    return process


def compose(*args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    compose_files: list[str] = []
    for path in selected_compose_files():
        compose_files.extend(("--file", str(path)))
    compose_args = list(args)
    if HRH_MODE == "published" and compose_args and compose_args[0] == "up":
        compose_args[1:1] = ["--pull", "never"]
    return run(
        "docker", "compose", "--env-file", str(ENV_FILE), "--project-name", PROJECT,
        *compose_files, *compose_args, env=sealed_compose_environment(),
        check=check, timeout=timeout,
    )


def cleanup() -> None:
    global CREATED
    if CREATED:
        compose("down", "--volumes", "--remove-orphans", check=False, timeout=240)
    run("docker", "image", "rm", "-f", INGRESS_IMAGE, ADAPTER_IMAGE, check=False, timeout=180)
    shutil.rmtree(STATE, ignore_errors=True)


atexit.register(cleanup)


def phase(name: str) -> None:
    print(f"clinical_composed_e2e phase={name}", flush=True)


def require_success(result: subprocess.CompletedProcess[str], operation: str) -> None:
    """Raise a public, content-free failure for a failed child operation."""
    if result.returncode:
        raise RuntimeError(f"clinical composed E2E failed: {operation} exit={result.returncode}")


def emit_public_debug(label: str, *_discarded: subprocess.CompletedProcess[str]) -> None:
    """Keep public CI diagnostics useful without copying child output.

    Compose and controller children can read the synthetic seed.  Their raw
    stdout, stderr, and logs are therefore intentionally not diagnostic
    material for a public test stream.
    """
    print(f"clinical_composed_e2e debug={label} details=omitted", file=sys.stderr)


def make_certificates() -> None:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic clinical E2E CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))

    def server(host: str) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False).sign(ca_key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    values = {"ca.crt": ca.public_bytes(serialization.Encoding.PEM)}
    for host, prefix in (("mattermost", "mattermost"), ("hrh-tls", "hrh-tls")):
        values[f"{prefix}.crt"], values[f"{prefix}.key"] = server(host)
    for name, value in values.items():
        (SEED / name).write_bytes(value)


def prepare() -> None:
    global PUBLISHED_HRH_VERIFICATION
    if HRH_MODE not in {"source-build", "published"}:
        raise RuntimeError("CLINICAL_E2E_HRH_MODE must be source-build or published")
    if HRH_MODE == "source-build" and HRH_ROOT is None:
        raise RuntimeError("CLINICAL_E2E_HRH_ROOT must name a clean HRH checkout")
    if HRH_MODE == "published" and "CLINICAL_E2E_HRH_ROOT" in os.environ:
        raise RuntimeError("published HRH mode forbids CLINICAL_E2E_HRH_ROOT")
    runtime_head = run("git", "rev-parse", "HEAD").stdout.strip()
    runtime_tree = run("git", "rev-parse", "HEAD^{tree}").stdout.strip()
    if run("git", "merge-base", "--is-ancestor", RUNTIME_PRODUCT_SHA, runtime_head, check=False).returncode:
        raise RuntimeError("runtime E2E checkout does not descend from the frozen product commit")
    if run("git", "status", "--porcelain=v1").stdout:
        raise RuntimeError("runtime E2E checkout must be clean before build")
    SOURCE_FRAME.update(runtime_head=runtime_head, runtime_tree=runtime_tree, hrh_mode=HRH_MODE)
    if HRH_MODE == "source-build":
        assert HRH_ROOT is not None
        hrh_head = run("git", "-C", str(HRH_ROOT), "rev-parse", "HEAD").stdout.strip()
        hrh_tree = run("git", "-C", str(HRH_ROOT), "rev-parse", "HEAD^{tree}").stdout.strip()
        if run("git", "-C", str(HRH_ROOT), "status", "--porcelain=v1").stdout:
            raise RuntimeError("HRH E2E checkout must be clean before build")
        if hrh_head != HRH_SHA:
            raise RuntimeError("HRH E2E checkout is not at the frozen SHA")
        if hrh_tree != HRH_TREE:
            raise RuntimeError("HRH E2E checkout tree does not match the frozen source")
        SOURCE_FRAME.update(hrh_head=hrh_head, hrh_tree=hrh_tree)
    else:
        missing = sorted(name for name, value in PUBLISHED_HRH_INPUTS.items() if not value)
        if missing:
            raise RuntimeError("published HRH inputs are incomplete: " + ",".join(missing))
        verify = run(
            sys.executable, str(ROOT / "tools" / "verify_hrh_published_candidate.py"),
            "--trust", str(PUBLISHED_HRH_INPUTS["trust"]),
            "--receipt", str(PUBLISHED_HRH_INPUTS["receipt"]),
            "--public-key", str(PUBLISHED_HRH_INPUTS["public_key"]),
            "--docker-config", str(PUBLISHED_HRH_INPUTS["docker_config"]),
            env={key: os.environ[key] for key in SAFE_COMPOSE_PROCESS_ENV if key in os.environ},
            timeout=1500,
        )
        try:
            PUBLISHED_HRH_VERIFICATION = json.loads(verify.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("published HRH verification returned malformed evidence") from exc
        SOURCE_FRAME.update(
            hrh_clinical_contract_revision=str(PUBLISHED_HRH_VERIFICATION["clinical_contract_revision"]),
            hrh_build_source_revision=str(PUBLISHED_HRH_VERIFICATION["build_source_revision"]),
        )
    SEED.mkdir()
    EVIDENCE.mkdir()
    for name in ("admin_password", "actor_password", "denied_password", "hrh_api_key"):
        (SEED / name).write_text("clinical_" + secrets.token_hex(24), encoding="ascii")
    make_certificates()
    env = {
        "CLINICAL_MM_DB_PASSWORD": secrets.token_hex(24), "CLINICAL_HRH_DB_PASSWORD": secrets.token_hex(24),
        "CLINICAL_HRH_SESSION_SECRET": secrets.token_hex(32), "CLINICAL_HRH_ENCRYPTION_KEY": secrets.token_hex(32),
        "CLINICAL_HARNESS": HARNESS.as_posix(), "CLINICAL_SEED": SEED.as_posix(),
        "CLINICAL_INGRESS_IMAGE": INGRESS_IMAGE, "CLINICAL_ADAPTER_IMAGE": ADAPTER_IMAGE,
        "CLINICAL_POLICY_PUBLIC_KEY": "placeholder",
    }
    if HRH_MODE == "source-build":
        assert HRH_ROOT is not None
        env.update(CLINICAL_HRH_ROOT=HRH_ROOT.as_posix(), CLINICAL_HRH_BUILD_SHA=HRH_SHA)
    else:
        assert PUBLISHED_HRH_VERIFICATION is not None
        subjects = PUBLISHED_HRH_VERIFICATION["subjects"]
        if not isinstance(subjects, dict):
            raise RuntimeError("published HRH verification subjects are malformed")
        env.update(CLINICAL_HRH_WEB_IMAGE=str(subjects["web"]), CLINICAL_HRH_MIGRATE_IMAGE=str(subjects["migrate"]))
    ENV_FILE.write_text("".join(f"{key}={value}\n" for key, value in env.items()), encoding="utf-8")


def set_env(name: str, value: str) -> None:
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    ENV_FILE.write_text("\n".join(f"{name}={value}" if line.startswith(name + "=") else line for line in lines) + "\n", encoding="utf-8")


def control(*args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = compose("exec", "--no-TTY", "controller", "python", "/harness/control.py", *args, check=False, timeout=timeout)
    if check and result.returncode:
        # This E2E is itself public CI evidence.  Its controller can read the
        # bootstrap seed, so raw child output must not be copied to the test
        # failure stream either.
        command = args[0] if args and args[0] in {
            "create-initial-admin", "bootstrap-mm", "seed-hrh", "policy",
            "outbox-init", "wait-mm", "wait-hrh", "send", "expect",
            "mutate", "grant-count", "outbox-summary",
        } else "controller"
        raise RuntimeError(f"controller command failed: {command} exit={result.returncode}")
    return result


def _compose_command(*args: str) -> list[str]:
    files: list[str] = []
    for path in selected_compose_files():
        files.extend(("--file", str(path)))
    return [
        "docker", "compose", "--env-file", str(ENV_FILE), "--project-name", PROJECT,
        *files, *args,
    ]


def _known_secret_canaries() -> dict[str, str]:
    # Generated only for this synthetic run.  Each value comes from a
    # different secret category and must be absent from every argv probe.
    return {
        "password": (SEED / "admin_password").read_text(encoding="ascii").strip(),
        "api_key": (SEED / "hrh_api_key").read_text(encoding="ascii").strip(),
        "key_material": (SEED / "mattermost.key").read_text(encoding="ascii").strip(),
        "actor_password": (SEED / "actor_password").read_text(encoding="ascii").strip(),
    }


def _same_uid_host_proc_cmdlines() -> list[str]:
    """Read only same-UID Linux-host argv surfaces for the delayed witness."""
    if not sys.platform.startswith("linux"):
        return []
    observed: list[str] = []
    observer_uid = os.getuid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if entry.stat(follow_symlinks=False).st_uid != observer_uid:
                continue
            observed.append((entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace"))
        except OSError:
            continue
    return observed


def _require_same_uid_linux_procfs_observer(procfs: list[str]) -> bool:
    """Require a separate same-UID Linux observer when the host supports it."""
    if not sys.platform.startswith("linux"):
        return False
    if not any("create-initial-admin" in command for command in procfs):
        raise RuntimeError("same-UID host procfs did not observe the real provisioning command")
    return True


def _assert_no_secret_canaries(surfaces: list[str], canaries: dict[str, str]) -> None:
    for category, canary in canaries.items():
        if any(canary in surface for surface in surfaces):
            raise RuntimeError(f"secret boundary witness found {category} canary")


def assert_initial_admin_secret_boundary() -> dict[str, object]:
    """Run actual first-admin provisioning while independently observing argv."""
    controller_id = compose("ps", "--quiet", "controller").stdout.strip()
    if not controller_id:
        raise RuntimeError("controller container unavailable for secret boundary witness")
    canaries = _known_secret_canaries()
    process = subprocess.Popen(
        _compose_command(
            "exec", "--no-TTY", "controller", "python", "/harness/control.py",
            "create-initial-admin", "--boundary-delay-seconds=3",
        ),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    docker_top: list[str] = []
    procfs: list[str] = []
    observed_controller = False
    try:
        deadline = time.monotonic() + 8
        while process.poll() is None and time.monotonic() < deadline:
            top = run("docker", "top", controller_id, "-eo", "pid,args", check=False, timeout=20)
            if top.returncode == 0:
                docker_top.append(top.stdout)
                observed_controller = observed_controller or "create-initial-admin" in top.stdout
            procfs.extend(_same_uid_host_proc_cmdlines())
            time.sleep(0.1)
        stdout, stderr = process.communicate(timeout=20)
    except BaseException:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)
        raise
    if process.returncode != 0:
        raise RuntimeError(f"initial administrator provisioning failed: exit={process.returncode}")
    procfs_observed = _require_same_uid_linux_procfs_observer(procfs)
    observed = [*docker_top, *procfs, stdout, stderr]
    _assert_no_secret_canaries(observed, canaries)
    if not observed_controller:
        raise RuntimeError("docker top did not observe the real provisioning command")
    return {
        "docker_top_observed": True,
        "procfs_observed": procfs_observed,
        "canary_categories": sorted(canaries),
    }


def wait_ingress(after: int = 0, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = compose("logs", "--no-color", "ingress", check=False).stdout
        if logs.count("mattermost_ingress_outcome=authenticated_ready") > after:
            return
        time.sleep(0.25)
    raise RuntimeError("ingress authenticated-ready deadline exceeded")


def wait_ingress_marker(marker: str, before: int, timeout: int = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = compose("logs", "--no-color", "ingress", check=False).stdout
        if logs.count(marker) > before:
            return
        time.sleep(0.25)
    raise RuntimeError(f"ingress marker deadline exceeded: {marker}")


def wait_grants(before: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if int(control("grant-count").stdout.strip()) > before:
            return
        time.sleep(0.1)
    raise RuntimeError("durable HRH grant was not observed")


def wait_delivery_delay() -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if int(control("delivery-delay-active").stdout.strip()) == 1:
            return
        time.sleep(0.1)
    raise RuntimeError("delivery reauthorization did not enter the harness-only delay")


def wait_delivery_reauthorized(label: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        evidence = json.loads(control("grant-evidence", label).stdout)
        if evidence["audits"].get("restricted_hermes_delivery_reauthorized", 0) >= 1:
            return
        time.sleep(0.1)
    raise RuntimeError("durable delivery reauthorization was not observed")


def wait_hrh_postgres() -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ready = compose(
            "exec", "--no-TTY", "hrh-postgres",
            "pg_isready", "-U", "hrh", "-d", "hrh",
            check=False,
        )
        if ready.returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError("HRH PostgreSQL readiness deadline exceeded")


def paused_outbox_snapshot(record_tag: str | None = None) -> list[dict[str, object]]:
    compose("pause", "ingress")
    try:
        arguments = ("snapshot-outbox-records", record_tag) if record_tag else ("snapshot-outbox-records",)
        result = json.loads(control(*arguments).stdout)
    finally:
        compose("unpause", "ingress", check=False)
    if not isinstance(result, list):
        raise RuntimeError("outbox snapshot result was not a list")
    return result


def image_evidence() -> dict[str, object]:
    result: dict[str, object] = {"host": {"os": platform.system(), "architecture": platform.machine()}, "images": {}}
    for name, reference in (("mattermost", MM_IMAGE), ("postgres", PG_IMAGE), ("tls", NGINX_IMAGE)):
        inspected = json.loads(run("docker", "image", "inspect", reference).stdout)[0]
        digest = reference.split("@", 1)[1]
        if not any(item.endswith("@" + digest) for item in inspected.get("RepoDigests", [])):
            raise RuntimeError("pinned image digest mismatch")
        result["images"][name] = {"reference": reference, "image_id": inspected["Id"], "os": inspected["Os"], "architecture": inspected["Architecture"]}
    return result


def built_image_evidence() -> dict[str, object]:
    result: dict[str, object] = {}
    for service in ("ingress", "clinical-adapter", "hrh"):
        container = compose("ps", "--quiet", service).stdout.strip()
        if not container:
            raise RuntimeError(f"built image container unavailable: {service}")
        inspected = json.loads(run("docker", "container", "inspect", container).stdout)[0]
        image_id = inspected["Image"]
        image = json.loads(run("docker", "image", "inspect", image_id).stdout)[0]
        result[service] = {
            "image_id": image_id,
            "repo_digests": sorted(image.get("RepoDigests") or []),
        }
    return result


def registry_docker_environment() -> dict[str, str]:
    """Expose only the Docker config path, never its credential contents."""
    environment = {key: os.environ[key] for key in SAFE_COMPOSE_PROCESS_ENV if key in os.environ}
    if HRH_MODE == "published":
        config = PUBLISHED_HRH_INPUTS.get("docker_config")
        if not config:
            raise RuntimeError("published HRH Docker config is unavailable")
        environment["DOCKER_CONFIG"] = str(Path(config).resolve())
    return environment


def pull_published_hrh_subjects() -> None:
    if not PUBLISHED_HRH_VERIFICATION:
        raise RuntimeError("published HRH subjects were not verified before pull")
    subjects = PUBLISHED_HRH_VERIFICATION.get("subjects")
    if not isinstance(subjects, dict) or set(subjects) != {"web", "migrate"}:
        raise RuntimeError("published HRH subject set is malformed")
    for role in ("web", "migrate"):
        run("docker", "pull", str(subjects[role]), env=registry_docker_environment(), timeout=600)


def published_hrh_container_evidence(service: str, role: str, *, completed: bool = False) -> dict[str, object]:
    if not PUBLISHED_HRH_VERIFICATION:
        raise RuntimeError("published HRH verification evidence is unavailable")
    subjects = PUBLISHED_HRH_VERIFICATION["subjects"]
    approved = str(subjects[role])
    ps_args = ("ps", "--all", "--quiet", service) if completed else ("ps", "--quiet", service)
    container = compose(*ps_args).stdout.strip()
    if not container:
        raise RuntimeError(f"published HRH {role} container is unavailable")
    inspected = json.loads(run("docker", "container", "inspect", container).stdout)[0]
    if inspected.get("Config", {}).get("Image") != approved:
        raise RuntimeError(f"published HRH {role} container did not use the approved subject")
    image = json.loads(run("docker", "image", "inspect", approved).stdout)[0]
    if inspected.get("Image") != image.get("Id"):
        raise RuntimeError(f"published HRH {role} container image ID differs from the approved subject")
    expected_digest = approved.split("@", 1)[1]
    if not any(value.endswith("@" + expected_digest) for value in image.get("RepoDigests") or []):
        raise RuntimeError(f"published HRH {role} local image lacks the approved digest")
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise RuntimeError(f"published HRH {role} image platform differs from the approved platform")
    return {"service": service, "role": role, "approved_subject": approved, "image_id": image["Id"], "completed": completed}


def restricted_container_control_evidence() -> dict[str, object]:
    module_path = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
    spec = importlib.util.spec_from_file_location("clinical_staging_controls", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("clinical staging control verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inspected: dict[str, object] = {}
    identities: dict[str, dict[str, object]] = {}
    expected = {
        "clinical-adapter": {"uid": 10008, "gid": 20007, "groups": [20006, 20007]},
        "ingress": {"uid": 10007, "gid": 20005, "groups": [20000, 20001, 20005, 20006]},
    }
    identity_probe = (
        "import json,os; "
        "print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':sorted(os.getgroups())}))"
    )
    for service, expected_identity in expected.items():
        container = compose("ps", "--quiet", service).stdout.strip()
        if not container:
            raise RuntimeError(f"restricted container unavailable: {service}")
        inspected[service] = json.loads(run("docker", "container", "inspect", container).stdout)[0]
        identity = json.loads(
            compose("exec", "--no-TTY", service, "python", "-c", identity_probe).stdout
        )
        if identity != expected_identity:
            raise RuntimeError(f"{service} effective runtime identity rejected")
        identities[service] = identity
    controls = module.verify_restricted_container_controls(inspected)
    return {"effective_identity": identities, "confinement": controls}


def network_and_surface_controls() -> dict[str, bool]:
    ingress_env = compose("exec", "--no-TTY", "ingress", "python", "-c", "import os,json; print(json.dumps(sorted(os.environ)))").stdout
    if "HRH" in ingress_env or "api-key" in ingress_env.lower():
        raise RuntimeError("edge environment contains an HRH credential/configuration name")
    no_hrh = compose("exec", "--no-TTY", "ingress", "python", "-c", "import socket; socket.getaddrinfo('hrh-tls',8443)", check=False).returncode != 0
    no_mm = compose("exec", "--no-TTY", "clinical-adapter", "python", "-c", "import socket; socket.getaddrinfo('mattermost',8065)", check=False).returncode != 0
    adapter_hrh = compose("exec", "--no-TTY", "clinical-adapter", "python", "-c", "import socket; socket.getaddrinfo('hrh-tls',8443)", check=False).returncode == 0
    no_conversation = compose("exec", "--no-TTY", "ingress", "python", "-c", "from pathlib import Path; raise SystemExit(Path('/run/restricted-inference/conversation.sock').exists())", check=False).returncode == 0
    no_agent_modules = compose("exec", "--no-TTY", "ingress", "python", "-c", "import importlib.util; raise SystemExit(any(importlib.util.find_spec(x) for x in ('run_agent','model_tools')))", check=False).returncode == 0
    if not all((no_hrh, no_mm, adapter_hrh, no_conversation, no_agent_modules)):
        raise RuntimeError("network or zero model/conversation/provider calls boundary failed")
    return {"edge_cannot_resolve_hrh": no_hrh, "adapter_cannot_resolve_mattermost": no_mm, "adapter_resolves_only_hrh_boundary": adapter_hrh, "zero model/conversation/provider calls": no_conversation and no_agent_modules}


def send_negative(label: str, mutation: str, *, actor: str = "actor", channel: str = "actor_dm") -> None:
    control("mutate", "reset")
    control("mutate", mutation)
    marker = "mattermost_clinical_outcome=authorization_denied"
    before = compose("logs", "--no-color", "ingress", check=False).stdout.count(marker)
    control("send", actor, channel, "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", label)
    wait_ingress_marker(marker, before)
    control("expect", label, "no-reply", timeout=45)


def scan_logs(canaries: dict[str, str]) -> str:
    logs = compose("logs", "--no-color", check=False).stdout
    forbidden = [
        "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb2",
        "appointment_synth_01", "Synthetic clinical bot", "actor@clinical.invalid", "syntheticstaff",
    ]
    leaked = [value for value in forbidden if value in logs]
    if leaked:
        raise RuntimeError("container logs contain synthetic clinical identifiers")
    _assert_no_secret_canaries([logs], canaries)
    return logs


def main() -> None:
    global CREATED
    phase("prepare")
    prepare()
    if PUBLISHED_SUBJECTS:
        phase("pull-published-no-rebuild")
        run("docker", "pull", INGRESS_IMAGE, timeout=600)
        run("docker", "pull", ADAPTER_IMAGE, timeout=600)
    else:
        phase("build")
        compose("build", "ingress", "clinical-adapter", timeout=600)
    if HRH_MODE == "published":
        phase("pull-verified-hrh-subjects")
        pull_published_hrh_subjects()
        compose("build", "controller", timeout=600)
    else:
        compose("build", "controller", "hrh-migrate", "hrh", timeout=1800)
    phase("initialize-volumes")
    compose("up", "--detach", "controller")
    CREATED = True
    control("seed-volumes")
    phase("databases-and-migrations")
    compose("up", "--detach", "mattermost-postgres", "hrh-postgres", timeout=600)
    wait_hrh_postgres()
    compose("up", "--detach", "hrh-migrate", timeout=600)
    migrated = compose("wait", "hrh-migrate", check=False, timeout=600)
    require_success(migrated, "hrh-migrate")
    published_migrate = published_hrh_container_evidence("hrh-migrate", "migrate", completed=True) if HRH_MODE == "published" else None
    phase("servers")
    compose("up", "--detach", "mattermost", timeout=300)
    control("wait-mm")
    phase("secret-boundary")
    secret_boundary = assert_initial_admin_secret_boundary()
    control("bootstrap-mm")
    control("seed-hrh")
    control("policy")
    control("outbox-init")
    public_key = control("public-key").stdout.strip()
    base64.b64decode(public_key, validate=True)
    set_env("CLINICAL_POLICY_PUBLIC_KEY", public_key)
    compose("up", "--detach", "hrh", "hrh-tls", "clinical-socket-init", "clinical-adapter", timeout=600)
    published_web = published_hrh_container_evidence("hrh", "web") if HRH_MODE == "published" else None
    control("wait-hrh", timeout=300)
    compose("up", "--detach", "ingress", timeout=180)
    wait_ingress()
    restricted_controls = restricted_container_control_evidence()
    control("hrh-route-control")
    control("uds-controls")
    phase("valid-clinical-command")
    control("send", "actor", "actor_dm", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "success")
    try:
        control("expect", "success", "reply", timeout=60)
    except RuntimeError:
        compose("stop", "ingress", check=False)
        emit_public_debug("valid-command")
        raise
    known_success = json.loads(control("grant-evidence", "success").stdout)
    if known_success["audits"].get("restricted_hermes_delivery_reauthorized", 0) != 1:
        raise RuntimeError("known delivery did not obtain exactly one authorization")
    boundaries = network_and_surface_controls()
    phase("identity-controls")
    control("send", "denied", "denied_dm", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "actor-cross")
    control("expect", "actor-cross", "no-reply", timeout=45)
    control("send", "actor", "group_channel", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "channel-cross")
    control("expect", "channel-cross", "no-reply", timeout=45)
    phase("authorization-controls")
    for label, mutation in (("unbound", "unbound"), ("disabled", "disabled"), ("missing-patients", "missing-patients"), ("missing-appointments", "missing-appointments")):
        send_negative(label, mutation)
    phase("revocation-before-delivery")
    control("mutate", "reset")
    control("mutate", "revoke-on-finalize")
    denial_marker = "mattermost_clinical_outcome=authorization_denied"
    denial_before = compose("logs", "--no-color", "ingress", check=False).stdout.count(denial_marker)
    control("send", "actor", "actor_dm", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "revoked")
    wait_ingress_marker(denial_marker, denial_before)
    control("expect", "revoked", "no-reply", timeout=45)
    control("mutate", "drop-revoke-trigger")
    phase("source-deletion-before-delivery")
    control("mutate", "reset")
    before = int(control("grant-count").stdout.strip())
    control("mutate", "crash-delay")
    control("send", "actor", "actor_dm", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "source-deleted")
    wait_grants(before)
    wait_delivery_delay()
    in_flight_records = [row for row in paused_outbox_snapshot() if row.get("state") == "IN_FLIGHT"]
    if len(in_flight_records) != 1:
        raise RuntimeError("source-deletion barrier did not isolate exactly one IN_FLIGHT outbox record")
    source_before = in_flight_records[0]
    if source_before.get("reason") != "" or source_before.get("nonce_erased") or source_before.get("ciphertext_erased"):
        raise RuntimeError("source-deletion IN_FLIGHT record did not retain its encrypted payload")
    source_record_tag = source_before.get("record_tag")
    if not isinstance(source_record_tag, str) or len(source_record_tag) != 64:
        raise RuntimeError("source-deletion READY record tag was invalid")
    source_deletion = json.loads(control("delete-source", "source-deleted").stdout)
    control("mutate", "drop-crash-delay", timeout=60)
    wait_delivery_reauthorized("source-deleted")
    control("expect", "source-deleted", "no-reply", timeout=45)
    terminal_records = paused_outbox_snapshot(source_record_tag)
    if len(terminal_records) != 1:
        raise RuntimeError("source-deletion terminal record was not found by exact tag")
    source_after = terminal_records[0]
    expected_after = {
        "record_tag": source_record_tag,
        "state": "AMBIGUOUS",
        "reason": "delivery_authorization_unknown",
        "generation": int(source_before["generation"]) + 1,
        "nonce_erased": True,
        "ciphertext_erased": True,
    }
    if source_after != expected_after:
        raise RuntimeError(
            "source deletion did not produce the observed terminal contract: "
            + json.dumps(source_after, sort_keys=True)
        )
    source_delivery = json.loads(control("grant-evidence", "source-deleted").stdout)
    if source_delivery["audits"].get("restricted_hermes_delivery_reauthorized", 0) != 1:
        raise RuntimeError("source-deletion unknown delivery did not obtain exactly one authorization")
    phase("crash-retry")
    control("mutate", "reset")
    before = int(control("grant-count").stdout.strip())
    control("mutate", "crash-delay")
    control("send", "actor", "actor_dm", "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1", "crash-retry")
    try:
        wait_grants(before)
    except RuntimeError:
        compose("stop", "ingress", check=False)
        emit_public_debug("crash-retry")
        raise
    wait_delivery_delay()
    before_crash = json.loads(control("grant-evidence", "crash-retry").stdout)
    if before_crash["audits"].get("restricted_hermes_next_appointment_read_authorized") != 1 or before_crash["audits"].get("restricted_hermes_next_appointment_read_completed") != 1:
        raise RuntimeError("crash window did not follow exactly one durable clinical read")
    crash_records = [row for row in paused_outbox_snapshot() if row.get("state") == "IN_FLIGHT"]
    if len(crash_records) != 1:
        raise RuntimeError("crash window did not isolate exactly one IN_FLIGHT outbox record")
    crash_before = crash_records[0]
    crash_record_tag = crash_before.get("record_tag")
    if not isinstance(crash_record_tag, str) or len(crash_record_tag) != 64:
        raise RuntimeError("crash IN_FLIGHT record tag was invalid")
    compose("kill", "ingress")
    control("mutate", "drop-crash-delay", timeout=60)
    compose("up", "--detach", "ingress")
    wait_ingress()
    wait_delivery_reauthorized("crash-retry")
    control("expect", "crash-retry", "no-reply", timeout=60)
    after_recovery = json.loads(control("grant-evidence", "crash-retry").stdout)
    crash_after_rows = paused_outbox_snapshot(crash_record_tag)
    if len(crash_after_rows) != 1:
        raise RuntimeError("crash terminal record was not found by exact tag")
    crash_after = crash_after_rows[0]
    expected_crash_after = {
        "record_tag": crash_record_tag,
        "state": "AMBIGUOUS",
        "reason": "restart_in_flight",
        "generation": int(crash_before["generation"]) + 1,
        "nonce_erased": True,
        "ciphertext_erased": True,
    }
    if crash_after != expected_crash_after:
        raise RuntimeError("crash recovery did not erase the unknown delivery: " + json.dumps(crash_after, sort_keys=True))
    crash_invariants = {
        "response_digest_equal": after_recovery["response_digest"] == before_crash["response_digest"],
        "read_authorized": after_recovery["audits"].get("restricted_hermes_next_appointment_read_authorized", 0),
        "read_completed": after_recovery["audits"].get("restricted_hermes_next_appointment_read_completed", 0),
        "delivery_reauthorized": after_recovery["audits"].get("restricted_hermes_delivery_reauthorized", 0),
    }
    print("clinical_composed_e2e crash_invariants=" + json.dumps(crash_invariants, sort_keys=True), flush=True)
    if crash_invariants != {
        "response_digest_equal": True,
        "read_authorized": 1,
        "read_completed": 1,
        # The server-side authorization can commit after the client crashes,
        # but the durable claim fences recovery from asking a second time.
        "delivery_reauthorized": 1,
    }:
        raise RuntimeError(
            "crash recovery invariant mismatch: " + json.dumps(crash_invariants, sort_keys=True)
        )
    phase("final-denial-sweep")
    control("mutate", "reset")
    time.sleep(3)
    denied_labels = [
        "actor-cross", "channel-cross", "unbound", "disabled",
        "missing-patients", "missing-appointments", "revoked",
    ]
    for label in denied_labels:
        control("expect", label, "no-reply", timeout=45)
    post_counts = {
        "valid": int(control("post-count", "success").stdout.strip()),
        "recovered": int(control("post-count", "crash-retry").stdout.strip()),
        "source_deleted": int(control("post-count", "source-deleted").stdout.strip()),
        **{label: int(control("post-count", label).stdout.strip()) for label in denied_labels},
    }
    if post_counts["valid"] != 1 or post_counts["recovered"] != 0 or post_counts["source_deleted"] != 0:
        raise RuntimeError("known/unknown delivery post-count contract failed: " + json.dumps(post_counts, sort_keys=True))
    phase("evidence")
    logs = scan_logs(_known_secret_canaries())
    policy_binding = json.loads(control("active-policy-binding").stdout)
    if (not isinstance(policy_binding, dict) or set(policy_binding) != {"epoch", "digest"}
            or not isinstance(policy_binding.get("epoch"), str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", policy_binding["epoch"])
            or not isinstance(policy_binding.get("digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", policy_binding["digest"])):
        raise RuntimeError("active policy binding is malformed")
    evidence = {
        **SOURCE_FRAME,
        "runtime_product_sha": RUNTIME_PRODUCT_SHA,
        "policy": policy_binding,
        "images": image_evidence()["images"], "boundaries": boundaries,
        "secret_boundary": secret_boundary,
        "built_images": built_image_evidence(),
        "published_hrh": {
            "verification": PUBLISHED_HRH_VERIFICATION,
            "web_container": published_web,
            "migrate_container": published_migrate,
            "hrh_source_dependency_configured": False,
            "runtime_controller_source_present": True,
        } if HRH_MODE == "published" else None,
        "restricted_container_controls": restricted_controls,
        "commands": [
            "python tests/deployment/test_clinical_composed_e2e.py",
            "pytest tests/static/test_clinical_composed_e2e_surface.py tests/unit/test_clinical_adapter.py tests/unit/test_mattermost_clinical.py",
        ],
        "crash_invariants": crash_invariants,
        "source_deletion": {
            **source_deletion,
            "delivery_count": post_counts["source_deleted"],
            "before": source_before,
            "after": source_after,
        },
        "known_success": known_success,
        "crash_unknown": {"before": crash_before, "after": crash_after},
        "post_counts": post_counts,
        "scenarios": {"valid": "one-authorization-one-post", "actor_cross": "deny", "channel_cross": "deny", "patient_cross": "deny", "unbound": "deny", "disabled": "deny", "missing_each_permission": "deny", "revoked_before_delivery": "zero-post", "source_deleted_before_delivery": "ambiguous-zero-post", "swapped_digest": "deny", "crash_retry": "ambiguous-zero-post", "logs": "no synthetic identifiers or secret canaries"},
        "retained_output_secret_canaries_absent": sorted(_known_secret_canaries()),
        "residual_limitations": [
            "Synthetic data and a test CA were used; this is technical conformance evidence, not a compliance certification.",
            "The run exercised Linux containers and the pinned Mattermost ESR image, not a production deployment or host-level operating-system controls.",
            (
                "HRH web and migrations were consumed from verified exact subjects without HRH source; runtime/controller source remained present. Signed publication claims were verified, but Git ancestry was not recomputed."
                if HRH_MODE == "published"
                else "The HRH service was built from the clean head/tree source frame; no published HRH registry digest, SBOM, provenance attestation, or no-rebuild verification is claimed."
            ),
        ],
    }
    _assert_no_secret_canaries([logs, json.dumps(evidence, sort_keys=True)], _known_secret_canaries())
    (EVIDENCE / "report.json").write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    phase("cleanup")
    compose("down", "--volumes", "--remove-orphans", timeout=300)
    run("docker", "image", "rm", "-f", INGRESS_IMAGE, ADAPTER_IMAGE, timeout=180)
    CREATED = False
    shutil.rmtree(STATE)
    atexit.unregister(cleanup)
    print("Clinical composed E2E: PASS", flush=True)


if __name__ == "__main__":
    main()
