from __future__ import annotations

import importlib.util
import platform
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p2_host_platform_admission.py"


def load_module():
    spec = importlib.util.spec_from_file_location("p2_host_platform_admission", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_accepts_only_the_declared_representative_host_class():
    module = load_module()

    assert module.admit("Linux", "x86_64", "ID=ubuntu\nVERSION_ID=\"24.04\"\n") == module.HOST_CLASS


@pytest.mark.parametrize(
    "system,machine,os_release",
    [
        ("Windows", "AMD64", ""),
        ("Linux", "aarch64", "ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
        ("Linux", "x86_64", "ID=debian\nVERSION_ID=\"12\"\n"),
        ("Linux", "x86_64", "ID=ubuntu\nVERSION_ID=\"22.04\"\n"),
        ("Linux", "x86_64", "not=parseable"),
    ],
)
def test_rejects_every_other_platform_without_echoing_host_details(system, machine, os_release):
    module = load_module()

    with pytest.raises(module.HostAdmissionError, match="unsupported-host"):
        module.admit(system, machine, os_release)


def test_cli_reduces_a_real_platform_rejection_to_a_content_safe_error(monkeypatch, capsys):
    module = load_module()
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")

    assert module.main() == 2
    assert capsys.readouterr().err == "p2-host-admission: DENIED class=unsupported-host\n"


@pytest.mark.skipif(platform.system() != "Linux", reason="live representative-platform admission is Linux-only")
def test_live_linux_runner_must_satisfy_the_explicit_platform_gate(capsys):
    """Exercise the real os-release path; this is platform parsing, not P2 proof."""
    module = load_module()

    assert module.main() == 0
    assert capsys.readouterr().out == "p2-host-admission: PASS class=ubuntu-24.04-lts-x86_64\n"
