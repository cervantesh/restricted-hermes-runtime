from __future__ import annotations

import importlib.util
import os
import platform
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p2_host_platform_admission.py"
HARNESS = ROOT / "tests" / "deployment" / "test_representative_clinical_egress.sh"


def load_module():
    spec = importlib.util.spec_from_file_location("p2_host_platform_admission", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_accepts_only_the_declared_representative_host_class():
    module = load_module()

    assert module.admit(
        "Linux", "x86_64", 'ID=ubuntu\nVERSION_ID="24.04"\n', "6.8.0-generic",
        container_detected=False,
    ) == module.HOST_CLASS


def test_rejects_a_container_even_when_its_os_release_matches_the_host_class():
    module = load_module()

    with pytest.raises(module.HostAdmissionError, match="unsupported-host"):
        module.admit(
            "Linux", "x86_64", 'ID=ubuntu\nVERSION_ID="24.04"\n', "6.8.0-generic",
            container_detected=True,
        )


@pytest.mark.parametrize(
    "system,machine,os_release,kernel_release",
    [
        ("Windows", "AMD64", "", ""),
        ("Linux", "aarch64", 'ID=ubuntu\nVERSION_ID="24.04"\n', "6.8.0-generic"),
        ("Linux", "x86_64", 'ID=debian\nVERSION_ID="12"\n', "6.8.0-generic"),
        ("Linux", "x86_64", 'ID=ubuntu\nVERSION_ID="22.04"\n', "6.8.0-generic"),
        ("Linux", "x86_64", "not=parseable", "6.8.0-generic"),
        ("Linux", "x86_64", 'ID=ubuntu\nVERSION_ID="24.04"\n', "6.6.87-microsoft-standard-WSL2"),
    ],
)
def test_rejects_every_other_platform_without_echoing_host_details(system, machine, os_release, kernel_release):
    module = load_module()

    with pytest.raises(module.HostAdmissionError, match="unsupported-host"):
        module.admit(system, machine, os_release, kernel_release, container_detected=False)


def test_cli_reduces_a_real_platform_rejection_to_a_content_safe_error(monkeypatch, capsys):
    module = load_module()
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(module, "_container_detected", lambda: False)

    assert module.main() == 2
    assert capsys.readouterr().err == "p2-host-admission: DENIED class=unsupported-host\n"


def test_cli_rejects_detected_container_before_reporting_admission(monkeypatch, capsys):
    module = load_module()
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(module, "_read_os_release", lambda: 'ID=ubuntu\nVERSION_ID="24.04"\n')
    monkeypatch.setattr(module.platform, "release", lambda: "6.8.0-generic")
    monkeypatch.setattr(module, "_container_detected", lambda: True)

    assert module.main() == 2
    assert capsys.readouterr().err == "p2-host-admission: DENIED class=unsupported-host\n"


def test_container_detector_accepts_only_systemd_non_container_result(monkeypatch):
    module = load_module()
    commands: list[list[str]] = []

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "strict"
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(module.subprocess, "run", run)
    assert module._container_detected() is False
    assert commands == [["systemd-detect-virt", "--container", "--quiet"]]


def test_container_detector_fails_closed_for_detected_or_unavailable_runtime(monkeypatch):
    module = load_module()
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    assert module._container_detected() is True

    def unavailable(*_args, **_kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr(module.subprocess, "run", unavailable)
    with pytest.raises(module.HostAdmissionError, match="unsupported-host"):
        module._container_detected()


@pytest.mark.parametrize(
    "failure",
    [
        lambda module: SimpleNamespace(returncode=2),
        lambda module: (_ for _ in ()).throw(subprocess.TimeoutExpired("systemd-detect-virt", 5)),
    ],
)
def test_container_detector_fails_closed_for_ambiguous_result(monkeypatch, failure):
    module = load_module()
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: failure(module))

    with pytest.raises(module.HostAdmissionError, match="unsupported-host"):
        module._container_detected()


def test_harness_runs_host_admission_before_any_docker_discovery():
    source = HARNESS.read_text(encoding="utf-8")

    admission = source.index('"$python_bin" "$runtime/tools/p2_host_platform_admission.py"')
    assert admission < source.index("docker context inspect default")
    assert admission < source.index("docker info")


@pytest.mark.skipif(platform.system() != "Linux", reason="live representative-platform admission is Linux-only")
def test_live_linux_runner_must_satisfy_the_explicit_platform_gate(capsys):
    module = load_module()

    assert module.main() == 0
    assert capsys.readouterr().out == "p2-host-admission: PASS class=ubuntu-24.04-lts-x86_64\n"


@pytest.mark.skipif(platform.system() != "Linux", reason="representative harness is Linux-only")
def test_real_harness_rejects_overridden_docker_endpoint_before_collection(tmp_path: Path):
    """A remote Docker endpoint cannot produce a representative-host receipt."""
    module = load_module()
    try:
        module.admit(
            platform.system(), platform.machine().lower(), Path("/etc/os-release").read_text(encoding="utf-8"), platform.release(),
            container_detected=False,
        )
    except (module.HostAdmissionError, OSError):
        pytest.skip("runner is not the admitted representative host class")
    hrh = tmp_path / "hrh"
    (hrh / ".git").mkdir(parents=True)
    receipt = tmp_path / "receipt.json"
    environment = {**os.environ, "DOCKER_HOST": "tcp://example.invalid:2376"}

    completed = subprocess.run(
        ["bash", str(HARNESS), str(hrh), str(receipt)],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stderr == "representative-clinical-egress: DENIED class=unsupported-docker-endpoint\n"
    assert not receipt.exists()
    assert not (tmp_path / "receipt.json.evidence").exists()
    assert not (tmp_path / "receipt.json.diagnostic").exists()
