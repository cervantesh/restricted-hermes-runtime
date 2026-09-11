#!/usr/bin/env python3
"""Fail closed unless execution is on the representative P2 host class.

This writes no receipt and makes no host-control claim.  It is the first gate
for a future representative egress collection, before Docker, staging state,
network creation, secrets, or receipt paths are touched.
"""
from __future__ import annotations

import platform
import subprocess
import sys


HOST_CLASS = "ubuntu-24.04-lts-x86_64"


class HostAdmissionError(RuntimeError):
    """A content-safe host-class admission failure."""


def _os_release_fields(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"ID", "VERSION_ID"}:
            continue
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value
    return fields


def admit(
    system: str,
    machine: str,
    os_release: str,
    kernel_release: str,
    *,
    container_detected: bool,
) -> str:
    """Return the sole admitted class or fail without echoing host inputs."""
    fields = _os_release_fields(os_release)
    kernel = kernel_release.lower() if isinstance(kernel_release, str) else ""
    if (
        system != "Linux"
        or machine not in {"x86_64", "amd64"}
        or fields.get("ID") != "ubuntu"
        or fields.get("VERSION_ID") != "24.04"
        or "microsoft" in kernel
        or "wsl" in kernel
        or container_detected is not False
    ):
        raise HostAdmissionError("unsupported-host")
    return HOST_CLASS


def _read_os_release() -> str:
    try:
        return open("/etc/os-release", encoding="utf-8").read()
    except OSError:
        return ""


def _container_detected() -> bool:
    """Return the explicit systemd container result or deny the unknown case."""
    try:
        result = subprocess.run(
            ["systemd-detect-virt", "--container", "--quiet"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=5,
            check=False,
        )
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired):
        raise HostAdmissionError("unsupported-host") from None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise HostAdmissionError("unsupported-host")


def main() -> int:
    try:
        admitted = admit(
            platform.system(),
            platform.machine().lower(),
            _read_os_release(),
            platform.release(),
            container_detected=_container_detected(),
        )
    except HostAdmissionError:
        print("p2-host-admission: DENIED class=unsupported-host", file=sys.stderr)
        return 2
    print(f"p2-host-admission: PASS class={admitted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
