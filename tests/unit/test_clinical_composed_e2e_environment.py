from __future__ import annotations

import atexit
import importlib.util
import subprocess
from pathlib import Path


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
    assert environment["DOCKER_CONFIG"] == str(runner.DOCKER_CONFIG_DIR)
    assert "CLINICAL_UNDECLARED_OVERRIDE" not in environment
    assert "/attacker/mixed-frame" not in environment.values()
    args = captured["args"]
    assert args[:3] == ("docker", "compose", "--env-file")
    assert args[-2:] == ("config", "--quiet")
    assert runner.HRH_SHA == E30_HRH_SHA
    assert runner.HRH_TREE == E30_HRH_TREE
    compose = runner.COMPOSE_FILE.read_text(encoding="utf-8")
    assert "Dockerfile.web.clinical-candidate" in compose
    assert "Dockerfile.migrate.clinical-candidate" in compose


def test_windows_compose_discovery_allows_only_installation_roots():
    runner = load_runner()
    atexit.unregister(runner.cleanup)
    environment = runner.compose_process_environment(
        {
            "PATH": "C:/safe/bin",
            "ProgramFiles": "C:/Program Files",
            "CLINICAL_HRH_ROOT": "C:/attacker/override",
        },
        platform_name="nt",
    )

    assert environment == {
        "PATH": "C:/safe/bin",
        "ProgramFiles": "C:/Program Files",
    }


def test_windows_compose_discovery_rejects_a_host_without_installation_root():
    runner = load_runner()
    atexit.unregister(runner.cleanup)

    try:
        runner.compose_process_environment({"PATH": "C:/safe/bin"}, platform_name="nt")
    except RuntimeError as exc:
        assert str(exc) == "clinical composed E2E Docker Compose discovery is unavailable"
    else:
        raise AssertionError("missing Windows Docker Compose discovery was accepted")
