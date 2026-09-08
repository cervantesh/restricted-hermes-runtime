from __future__ import annotations

import atexit
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py"
E30_HRH_SHA = "e30a4f968de6727519f49c08369f561fdf269ec5"
E30_HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"


def load_runner():
    spec = importlib.util.spec_from_file_location("clinical_composed_e2e_environment", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_compose_ignores_inherited_clinical_variables_and_uses_generated_e30_frame(
    tmp_path, monkeypatch,
):
    """A caller cannot override `--env-file` through Compose shell precedence."""
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    runner.ENV_FILE = tmp_path / "compose.env"
    runner.ENV_FILE.write_text(
        "CLINICAL_HRH_ROOT=/synthetic/hrh-e30\n"
        f"CLINICAL_HRH_BUILD_SHA={E30_HRH_SHA}\n"
        "CLINICAL_MM_DB_PASSWORD=generated\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CLINICAL_HRH_ROOT", "/attacker/mixed-frame")
    monkeypatch.setenv("CLINICAL_HRH_BUILD_SHA", "f" * 40)
    monkeypatch.setenv("CLINICAL_UNDECLARED_OVERRIDE", "unexpected")
    captured: dict[str, object] = {}

    def fake_run(*args: str, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "run", fake_run)
    runner.compose("config", "--quiet")

    environment = captured["env"]
    assert environment["CLINICAL_HRH_ROOT"] == "/synthetic/hrh-e30"
    assert environment["CLINICAL_HRH_BUILD_SHA"] == E30_HRH_SHA
    assert "CLINICAL_UNDECLARED_OVERRIDE" not in environment
    assert "/attacker/mixed-frame" not in environment.values()
    args = captured["args"]
    assert args[:3] == ("docker", "compose", "--env-file")
    assert args[-2:] == ("config", "--quiet")
    assert runner.HRH_SHA == E30_HRH_SHA
    assert runner.HRH_TREE == E30_HRH_TREE
    compose = runner.SOURCE_BUILD_COMPOSE_FILE.read_text(encoding="utf-8")
    assert "Dockerfile.web.clinical-candidate" in compose
    assert "Dockerfile.migrate.clinical-candidate" in compose


def test_published_mode_uses_two_files_and_injects_pull_never(tmp_path, monkeypatch):
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    runner.HRH_MODE = "published"
    runner.ENV_FILE = tmp_path / "compose.env"
    runner.ENV_FILE.write_text("CLINICAL_HRH_WEB_IMAGE=registry/web@sha256:" + "1" * 64 + "\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(*args: str, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "run", fake_run)
    runner.compose("up", "--detach", "hrh")

    args = captured["args"]
    assert str(runner.COMPOSE_FILE) in args
    assert str(runner.PUBLISHED_HRH_COMPOSE_FILE) in args
    assert str(runner.SOURCE_BUILD_COMPOSE_FILE) not in args
    assert args[-5:] == ("up", "--pull", "never", "--detach", "hrh")
    assert "DOCKER_CONFIG" not in captured["env"]


def test_published_mode_rejects_even_an_empty_hrh_root_variable(monkeypatch):
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    runner.HRH_MODE = "published"
    monkeypatch.setenv("CLINICAL_E2E_HRH_ROOT", "")

    with pytest.raises(RuntimeError, match="forbids CLINICAL_E2E_HRH_ROOT"):
        runner.prepare()


def test_published_pull_uses_exact_subjects_and_private_config_only(monkeypatch, tmp_path):
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    runner.HRH_MODE = "published"
    runner.PUBLISHED_HRH_INPUTS["docker_config"] = str(tmp_path / "caller-docker")
    runner.ACTIVE_HRH_DOCKER_CONFIG = tmp_path / "private-docker-snapshot"
    runner.PUBLISHED_HRH_VERIFICATION = {
        "subjects": {
            "web": "registry.example/web@sha256:" + "1" * 64,
            "migrate": "registry.example/migrate@sha256:" + "2" * 64,
            "evidence": "registry.example/evidence@sha256:" + "3" * 64,
        }
    }
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "run", fake_run)
    runner.pull_published_hrh_subjects()

    assert [call[0][2] for call in calls] == [
        runner.PUBLISHED_HRH_VERIFICATION["subjects"]["web"],
        runner.PUBLISHED_HRH_VERIFICATION["subjects"]["migrate"],
    ]
    assert all(call[0][:2] == ("docker", "pull") for call in calls)
    assert all(call[1]["env"]["DOCKER_CONFIG"] == str(tmp_path / "private-docker-snapshot") for call in calls)
    assert all("never-publish" not in " ".join(call[0]) for call in calls)


def test_failed_published_migration_stops_before_web_or_clinical_startup(monkeypatch):
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    runner.HRH_MODE = "published"
    calls = []

    def fake_compose(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 17 if args[0] == "wait" else 0, "", "")

    monkeypatch.setattr(runner, "compose", fake_compose)
    monkeypatch.setattr(
        runner,
        "published_hrh_container_evidence",
        lambda *args, **kwargs: pytest.fail("image evidence cannot run after migration failure"),
    )

    with pytest.raises(RuntimeError, match="hrh-migrate"):
        runner.run_hrh_migration()

    assert calls == [("up", "--detach", "hrh-migrate"), ("wait", "hrh-migrate")]


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink retarget regression")
def test_host_pull_keeps_run_owned_docker_config_after_caller_path_retargets(
    tmp_path,
):
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    runner.HRH_MODE = "published"
    original = tmp_path / "original"
    attacker = tmp_path / "attacker"
    snapshot = tmp_path / "run-owned-snapshot"
    original.mkdir()
    attacker.mkdir()
    snapshot.mkdir()
    caller = tmp_path / "caller"
    caller.symlink_to(original, target_is_directory=True)
    runner.PUBLISHED_HRH_INPUTS["docker_config"] = str(caller)
    runner.ACTIVE_HRH_DOCKER_CONFIG = snapshot

    caller.unlink()
    caller.symlink_to(attacker, target_is_directory=True)

    assert runner.registry_docker_environment()["DOCKER_CONFIG"] == str(snapshot)


def test_image_evidence_preserves_source_schema_and_uses_neutral_published_field(
    monkeypatch,
):
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    monkeypatch.setattr(runner, "effective_image_evidence", lambda: {"hrh": {"image_id": "sha256:test"}})

    source_receipt = {}
    runner.HRH_MODE = "source-build"
    runner.attach_hrh_image_evidence(source_receipt)
    assert source_receipt == {"built_images": {"hrh": {"image_id": "sha256:test"}}}

    published_receipt = {}
    runner.HRH_MODE = "published"
    runner.attach_hrh_image_evidence(published_receipt)
    assert published_receipt == {"effective_images": {"hrh": {"image_id": "sha256:test"}}}
