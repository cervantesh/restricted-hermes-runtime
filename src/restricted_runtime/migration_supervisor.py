"""The sole process-spawning boundary for the one-shot migration image."""
from __future__ import annotations

import os
import signal
import subprocess
import time
from http.client import HTTPConnection
from pathlib import Path
from typing import Callable


def proxy_command(connection_name: str, socket_dir: Path) -> list[str]:
    return [
        "/cloud-sql-proxy",
        "--private-ip",
        f"--unix-socket={socket_dir.as_posix()}",
        "--health-check",
        "--http-address=127.0.0.1",
        "--http-port=9091",
        "--exit-zero-on-sigterm",
        connection_name,
    ]


def prepare_socket_directory(socket_dir: Path) -> None:
    socket_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    socket_dir.chmod(0o700)


def proxy_readiness() -> None:
    connection = HTTPConnection("127.0.0.1", 9091, timeout=1)
    try:
        connection.request("GET", "/readiness")
        if connection.getresponse().status != 200:
            raise RuntimeError("Cloud SQL proxy is not ready")
    finally:
        connection.close()


def proxy_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    child_environment = dict(os.environ if environment is None else environment)
    child_environment.pop("MIGRATION_ADMIN_DSN", None)
    return child_environment


def start_proxy(command: list[str], *, env: dict[str, str]) -> object:
    """Start the child with inherited stdout/stderr and no secret DSN."""
    return subprocess.Popen(command, env=env, shell=False)


def wait_for_proxy_ready(process: object, readiness_probe: Callable[[], None], *, timeout_seconds: float = 10, monotonic: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
    deadline = monotonic() + timeout_seconds
    last_error: Exception | None = None
    while True:
        if process.poll() is not None:
            raise RuntimeError("Cloud SQL proxy exited before readiness")
        try:
            readiness_probe()
            return
        except Exception as error:
            last_error = error
        if monotonic() >= deadline:
            raise RuntimeError("Cloud SQL proxy readiness timed out") from last_error
        sleep(0.1)


def cleanup_proxy(process: object, *, timeout_seconds: float = 5) -> None:
    if process.poll() is not None:
        raise RuntimeError("Cloud SQL proxy exited before supervised shutdown")
    process.terminate()
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        exit_code = process.wait(timeout=timeout_seconds)
    if exit_code != 0:
        raise RuntimeError(f"Cloud SQL proxy cleanup exited {exit_code}")


def install_shutdown_handlers() -> Callable[[], None]:
    """Make PID 1 enter the supervised cleanup path for TERM and INT."""
    def interrupt(signum: int, frame: object) -> None:
        raise RuntimeError(f"migration supervisor interrupted by signal {signum}")

    previous = [(signal_number, signal.signal(signal_number, interrupt)) for signal_number in (signal.SIGTERM, signal.SIGINT)]

    def restore() -> None:
        for signal_number, handler in previous:
            signal.signal(signal_number, handler)

    return restore


def run_with_proxy(*, connection_name: str, socket_dir: Path, run_migration: Callable[[object], None], connect: object, popen: Callable[..., object] | None = None, readiness_probe: Callable[[], None] = proxy_readiness, prepare_socket: Callable[[Path], None] = prepare_socket_directory, cleanup: Callable[[object], None] = cleanup_proxy, install_signals: Callable[[], Callable[[], None]] = install_shutdown_handlers) -> None:
    """Run exactly one proxy child and preserve the migration/postflight result."""
    process: object | None = None
    primary_error: BaseException | None = None
    restore_signals = install_signals()
    cleanup_error: BaseException | None = None
    try:
        prepare_socket(socket_dir)
        process = (start_proxy if popen is None else popen)(proxy_command(connection_name, socket_dir), env=proxy_environment())
        wait_for_proxy_ready(process, readiness_probe)
        run_migration(connect)
    except BaseException as error:
        primary_error = error
    finally:
        try:
            if process is not None:
                try:
                    cleanup(process)
                except BaseException as error:
                    cleanup_error = error
        finally:
            restore_signals()

    if primary_error is not None:
        raise primary_error
    if cleanup_error is not None:
        raise RuntimeError("Cloud SQL proxy cleanup failed") from cleanup_error
