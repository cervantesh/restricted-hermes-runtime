from __future__ import annotations

import atexit
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
CONTROL_PATH = ROOT / "tests" / "deployment" / "clinical-composed-e2e" / "control.py"


def load_staging():
    spec = importlib.util.spec_from_file_location("clinical_staging_secret_boundary", STAGING_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_control():
    source = str(ROOT / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    spec = importlib.util.spec_from_file_location("clinical_control_secret_boundary", CONTROL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_composed_e2e(monkeypatch: pytest.MonkeyPatch):
    """Load the executable harness without registering its process cleanup."""
    monkeypatch.setattr(atexit, "register", lambda *_args, **_kwargs: None)
    spec = importlib.util.spec_from_file_location(
        "clinical_composed_e2e_secret_boundary",
        ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shell_failure_public_message_never_copies_child_output(monkeypatch: pytest.MonkeyPatch):
    module = load_staging()
    canaries = {
        "password": "PASSWORD_SECRET_CANARY_9159",
        "api_key": "API_KEY_SECRET_CANARY_9159",
        "token": "TOKEN_SECRET_CANARY_9159",
        "key_material": "KEY_MATERIAL_SECRET_CANARY_9159",
        "stdout": "STDOUT_SECRET_CANARY_9159",
        "stderr": "STDERR_SECRET_CANARY_9159",
    }
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=17,
            stdout=" ".join((canaries["password"], canaries["api_key"], canaries["stdout"])),
            stderr=" ".join((canaries["token"], canaries["key_material"], canaries["stderr"])),
        ),
    )

    with pytest.raises(module.CommandError) as raised:
        module.Shell().run("synthetic-child", "nonsecret")

    public = str(raised.value)
    assert public == "command failed: child exit=17"
    assert all(canary not in public for canary in canaries.values())


def test_initial_admin_provisioner_never_passes_password_to_host_command_arguments(
    tmp_path: Path,
):
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    secret_canaries = (
        "PASSWORD_SECRET_CANARY_9159",
        "API_KEY_SECRET_CANARY_9159",
        "TOKEN_SECRET_CANARY_9159",
        "KEY_MATERIAL_SECRET_CANARY_9159",
    )

    def fake_control(*args: str, **kwargs: object) -> str:
        calls.append((args, kwargs))
        return ""

    staging.control = fake_control  # type: ignore[method-assign]
    staging._provision_initial_mattermost_admin()

    assert calls == [(("create-initial-admin",), {"timeout": 180})]
    observed = repr(calls)
    assert all(canary not in observed for canary in secret_canaries)


def test_controller_provisions_first_admin_with_secret_only_in_https_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_control()
    password = "PASSWORD_SECRET_CANARY_9159"
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "admin_password").write_text(password + "\n", encoding="ascii")
    monkeypatch.setattr(module, "SEED", seed)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_request(*args: object, **kwargs: object):
        calls.append((args, kwargs))
        return ({"id": "administrator", "roles": "system_user system_admin"}, {})

    monkeypatch.setattr(module, "request", fake_request)
    monkeypatch.setattr(module, "_mm_context", lambda: object())

    module.provision_initial_mattermost_admin()

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] == module.MM_BASE
    assert args[2] == "POST"
    assert args[3] == "/users"
    assert args[4] == {
        "username": "clinicaladmin",
        "email": "admin@clinical.invalid",
        "password": password,
        "email_verified": True,
    }
    assert kwargs == {}


def test_controller_initial_admin_conflict_is_idempotent_but_other_failures_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_control()
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "admin_password").write_text("PASSWORD_SECRET_CANARY_9159\n", encoding="ascii")
    monkeypatch.setattr(module, "SEED", seed)
    monkeypatch.setattr(module, "_mm_context", lambda: object())

    monkeypatch.setattr(
        module,
        "request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            module.ApiError(409, "store.sql_user.save_conflict.app_error", "User already exists")
        ),
    )
    module.provision_initial_mattermost_admin()

    monkeypatch.setattr(
        module,
        "request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            module.ApiError(503, "service_unavailable", "PASSWORD_SECRET_CANARY_9159")
        ),
    )
    with pytest.raises(RuntimeError) as raised:
        module.provision_initial_mattermost_admin()
    assert str(raised.value) == "Mattermost initial administrator bootstrap failed"
    assert "PASSWORD_SECRET_CANARY_9159" not in str(raised.value)


def test_controller_fails_closed_if_initial_api_response_is_not_an_administrator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_control()
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "admin_password").write_text("PASSWORD_SECRET_CANARY_9159\n", encoding="ascii")
    monkeypatch.setattr(module, "SEED", seed)
    monkeypatch.setattr(module, "_mm_context", lambda: object())
    monkeypatch.setattr(
        module,
        "request",
        lambda *_args, **_kwargs: ({"id": "nonadmin", "roles": "system_user"}, {}),
    )

    with pytest.raises(RuntimeError, match="initial administrator bootstrap failed"):
        module.provision_initial_mattermost_admin()


def test_cli_never_renders_command_error_text(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    module = load_staging()
    canary = "STDERR_SECRET_CANARY_9159"

    class FakeStaging:
        def __init__(self, *_args, **_kwargs):
            pass

        def status(self):
            raise module.CommandError(canary)

    monkeypatch.setattr(module, "ClinicalStaging", FakeStaging)
    assert module.main([
        "--hrh-root", "/synthetic/hrh",
        "--state-dir", "/synthetic/clinicalstagingsecret.synthetic-clinical-staging",
        "--project", "clinicalstagingsecret",
        "status",
    ]) == 2
    assert capsys.readouterr().err == "clinical_staging outcome=denied reason=command_failed\n"


@pytest.mark.skipif(os.name != "posix", reason="mode/ownership contract is Linux-only")
def test_finalization_recovers_before_and_after_secret_erase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The durable finalizing state must survive either cleanup interruption."""
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    password = state / "seed" / "admin_password"
    runtime.mkdir()
    hrh.mkdir()
    password.parent.mkdir(parents=True)
    password.write_text("PASSWORD_SECRET_CANARY_9159\n", encoding="ascii")
    password.chmod(0o600)
    monkeypatch.setattr(module, "fsync_directory", lambda _path: None)
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)
    marker = {"lifecycle": "finalizing"}
    writes: list[str] = []
    staging._write_marker = lambda value: writes.append(value["lifecycle"])  # type: ignore[method-assign]

    original_erase = staging._erase_initial_admin_password
    staging._erase_initial_admin_password = lambda: (_ for _ in ()).throw(KeyboardInterrupt())  # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt):
        staging._finalize_initialization(marker)
    assert marker["lifecycle"] == "finalizing"
    assert password.exists()
    assert writes == []

    staging._erase_initial_admin_password = original_erase  # type: ignore[method-assign]
    staging._finalize_initialization(marker)
    assert marker["lifecycle"] == "ready"
    assert not password.exists()
    assert writes == ["ready"]

    password.write_text("PASSWORD_SECRET_CANARY_9159\n", encoding="ascii")
    password.chmod(0o600)
    marker["lifecycle"] = "finalizing"
    writes.clear()
    staging._write_marker = lambda _value: (_ for _ in ()).throw(KeyboardInterrupt())  # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt):
        staging._finalize_initialization(marker)
    assert marker["lifecycle"] == "ready"
    assert not password.exists()

    marker["lifecycle"] = "finalizing"  # persisted marker after the interrupted atomic write
    staging._write_marker = lambda value: writes.append(value["lifecycle"])  # type: ignore[method-assign]
    staging._finalize_initialization(marker)
    assert marker["lifecycle"] == "ready"
    assert writes == ["ready"]


def test_next_init_invocation_resumes_finalizing_before_operational_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    (state / module.MARKER_NAME).write_text("synthetic", encoding="ascii")
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)
    marker = {"lifecycle": "finalizing"}
    resumed: list[str] = []
    original_stat = Path.stat
    operator_uid = 1000

    def fake_stat(path: Path, *args: object, **kwargs: object):
        if path == state:
            return SimpleNamespace(st_uid=operator_uid, st_mode=stat.S_IFDIR | 0o700)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(module.os, "getuid", lambda: operator_uid, raising=False)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_args: {})
    monkeypatch.setattr(module, "read_marker", lambda *_args: marker)
    monkeypatch.setattr(module, "verify_effective_env", lambda *_args: None)
    monkeypatch.setattr(
        staging,
        "_finalize_initialization",
        lambda value: (resumed.append(value["lifecycle"]), value.update(lifecycle="ready")),
    )
    monkeypatch.setattr(staging, "up", lambda: {"lifecycle": "ready"})
    monkeypatch.setattr(staging, "compose", lambda *_args, **_kwargs: pytest.fail("finalizing resume must not reprovision"))

    assert staging.init() == {"lifecycle": "ready"}
    assert resumed == ["finalizing"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only wrapper recovery contract")
def test_atomic_marker_write_recovers_a_killed_legacy_temp_and_rejects_symlink(
    tmp_path: Path,
):
    """A resumed finalizer recovers only a private regular SIGKILL-era temp."""
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir(mode=0o700)
    marker = state / module.MARKER_NAME
    stale = marker.with_name(marker.name + ".tmp")
    stale.write_text('{"incomplete": true}\n', encoding="utf-8")
    stale.chmod(0o600)
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)
    lifecycle = {"lifecycle": "finalizing"}

    staging._finalize_initialization(lifecycle)
    assert not stale.exists()
    assert lifecycle["lifecycle"] == "ready"

    sentinel = tmp_path / "unrelated-sentinel"
    sentinel.write_text("must remain", encoding="ascii")
    stale.symlink_to(sentinel)
    with pytest.raises(module.SafetyError, match="regular file"):
        staging._finalize_initialization({"lifecycle": "finalizing"})
    assert sentinel.read_text(encoding="ascii") == "must remain"
    assert stale.is_symlink()
    stale.unlink()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only wrapper recovery contract")
def test_next_initializer_erases_hard_killed_owned_seed_without_reusing_it(tmp_path: Path):
    """A real child os._exit after _seed_material cannot strand a reusable seed."""
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    frame = {
        "runtime_head": "a" * 40,
        "runtime_tree": "b" * 40,
        "hrh_head": "c" * 40,
        "hrh_tree": "d" * 40,
    }
    crash_script = """
import importlib.util
import os
import sys
from pathlib import Path

script_path = Path(sys.argv[1])
root = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('clinical_staging_child', script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
runtime = root / 'runtime'
hrh = root / 'hrh'
state = root / 'clinicalstagingsecret.synthetic-clinical-staging'
staging = module.ClinicalStaging(runtime, hrh, state, 'clinicalstagingsecret', 18443)
original = staging._seed_material
def seed_then_die(destination):
    original(destination)
    os._exit(71)
staging._seed_material = seed_then_die
staging._prepare_new_state({
    'runtime_head': 'a' * 40,
    'runtime_tree': 'b' * 40,
    'hrh_head': 'c' * 40,
    'hrh_tree': 'd' * 40,
})
"""
    crashed = subprocess.run(
        [sys.executable, "-c", crash_script, str(STAGING_PATH), str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert crashed.returncode == 71
    remnants = list(tmp_path.glob(f".{state.name}.init-*"))
    assert len(remnants) == 1
    old_password = remnants[0] / "seed" / "admin_password"
    old_secret = old_password.read_bytes()

    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)
    marker = staging._prepare_new_state(frame)

    assert marker["state_dir"] == str(state)
    assert not list(tmp_path.glob(f".{state.name}.init-*"))
    assert (state / "seed" / "admin_password").read_bytes() != old_secret


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only wrapper recovery contract")
def test_orphan_reconciliation_refuses_symlinked_or_unowned_tree(tmp_path: Path):
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    orphan = tmp_path / f".{state.name}.init-0123456789abcdef"
    orphan.mkdir(mode=0o700)
    sentinel = tmp_path / "unrelated-sentinel"
    sentinel.write_text("must remain", encoding="ascii")
    (orphan / "trap").symlink_to(sentinel)
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)

    with pytest.raises(module.SafetyError, match="symlink"):
        staging._reconcile_owned_initialization_orphans()
    assert sentinel.read_text(encoding="ascii") == "must remain"
    assert orphan.exists()


def test_composed_e2e_public_failure_paths_discard_child_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
):
    module = load_composed_e2e(monkeypatch)
    canaries = "PASSWORD_SECRET_CANARY_9159 API_KEY_SECRET_CANARY_9159 TOKEN_SECRET_CANARY_9159"
    failed = SimpleNamespace(returncode=29, stdout=canaries, stderr=canaries)

    with pytest.raises(RuntimeError) as migration:
        module.require_success(failed, "hrh-migrate")
    assert str(migration.value) == "clinical composed E2E failed: hrh-migrate exit=29"
    assert canaries not in str(migration.value)

    module.emit_public_debug("crash-retry", failed, failed)
    public_stderr = capsys.readouterr().err
    assert public_stderr == "clinical_composed_e2e debug=crash-retry details=omitted\n"
    assert canaries not in public_stderr


def test_composed_e2e_retained_logs_reject_every_secret_canary(monkeypatch: pytest.MonkeyPatch):
    module = load_composed_e2e(monkeypatch)
    canaries = {
        "password": "PASSWORD_SECRET_CANARY_9159",
        "api_key": "API_KEY_SECRET_CANARY_9159",
        "key_material": "KEY_MATERIAL_SECRET_CANARY_9159",
    }
    monkeypatch.setattr(
        module,
        "compose",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=" ".join(canaries.values()), stderr=""),
    )
    with pytest.raises(RuntimeError, match="secret boundary witness found password canary"):
        module.scan_logs(canaries)


def test_linux_procfs_witness_requires_the_same_uid_provisioner_and_rejects_canaries(
    monkeypatch: pytest.MonkeyPatch,
):
    module = load_composed_e2e(monkeypatch)
    monkeypatch.setattr(module.sys, "platform", "linux")

    with pytest.raises(RuntimeError, match="same-UID host procfs"):
        module._require_same_uid_linux_procfs_observer(["python unrelated.py"])
    assert module._require_same_uid_linux_procfs_observer(
        ["docker compose exec controller python /harness/control.py create-initial-admin"]
    ) is True
    with pytest.raises(RuntimeError, match="password canary"):
        module._assert_no_secret_canaries(
            ["docker compose PASSWORD_SECRET_CANARY_9159"],
            {"password": "PASSWORD_SECRET_CANARY_9159"},
        )

    monkeypatch.setattr(module.sys, "platform", "win32")
    assert module._require_same_uid_linux_procfs_observer([]) is False


@pytest.mark.skipif(os.name != "posix", reason="mode/ownership contract is Linux-only")
def test_initial_admin_password_cleanup_is_strict_and_interruption_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_staging()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingsecret.synthetic-clinical-staging"
    seed = state / "seed"
    runtime.mkdir()
    hrh.mkdir()
    seed.mkdir(parents=True)
    password = seed / "admin_password"
    password.write_text("PASSWORD_SECRET_CANARY_9159\n", encoding="ascii")
    password.chmod(0o600)
    monkeypatch.setattr(module, "fsync_directory", lambda _path: None)
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingsecret", 18443)

    staging._erase_initial_admin_password()
    assert not password.exists()

    password.write_text("PASSWORD_SECRET_CANARY_9159\n", encoding="ascii")
    password.chmod(0o644)
    with pytest.raises(module.SafetyError, match="mode-0600"):
        staging._erase_initial_admin_password()
    assert password.exists()
