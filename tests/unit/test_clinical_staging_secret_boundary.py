from __future__ import annotations

import importlib.util
import os
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


def test_shell_failure_public_message_never_copies_child_output(monkeypatch: pytest.MonkeyPatch):
    module = load_staging()
    stdout_canary = "STDOUT_SECRET_CANARY_9159"
    stderr_canary = "STDERR_SECRET_CANARY_9159"
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=17, stdout=stdout_canary, stderr=stderr_canary,
        ),
    )

    with pytest.raises(module.CommandError) as raised:
        module.Shell().run("synthetic-child", "nonsecret")

    public = str(raised.value)
    assert public == "command failed: child exit=17"
    assert stdout_canary not in public
    assert stderr_canary not in public


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
