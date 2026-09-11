from __future__ import annotations

import importlib.util
import os
import platform
import subprocess
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
        "Linux", "x86_64", 'ID=ubuntu\nVERSION_ID="24.04"\n', "6.8.0-generic"
    ) == module.HOST_CLASS


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
        module.admit(system, machine, os_release, kernel_release)


def test_cli_reduces_a_real_platform_rejection_to_a_content_safe_error(monkeypatch, capsys):
    module = load_module()
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")

    assert module.main() == 2
    assert capsys.readouterr().err == "p2-host-admission: DENIED class=unsupported-host\n"


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
            platform.system(), platform.machine().lower(), Path("/etc/os-release").read_text(encoding="utf-8"), platform.release()
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
