"""A real process proof for the migration supervisor's PID 1 signal path."""
import os
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX signals; execute this proof under WSL")
def test_sigterm_supervisor_reaps_real_proxy_child(tmp_path: Path):
    import signal
    import subprocess
    import sys
    import time

    child_pid = tmp_path / "child.pid"
    script = f"""
import os, subprocess, sys, time
from pathlib import Path
from restricted_runtime import migration_supervisor
pid_file = Path({str(child_pid)!r})
migration_supervisor.proxy_command = lambda connection_name, socket_dir: [sys.executable, '-c', 'import time; time.sleep(60)']
def start(command, **kwargs):
    child = subprocess.Popen(command, **kwargs)
    pid_file.write_text(str(child.pid), encoding='ascii')
    return child
migration_supervisor.run_with_proxy(
    connection_name='project:region:instance', socket_dir=Path('/tmp/restricted-supervisor-socket'),
    run_migration=lambda connection: time.sleep(60), connect=None, popen=start,
    readiness_probe=lambda: None,
)
"""
    environment = dict(os.environ, PYTHONPATH=str(Path("src").resolve()))
    supervisor = subprocess.Popen([sys.executable, "-c", script], env=environment)
    deadline = time.monotonic() + 10
    while not child_pid.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert child_pid.exists(), "supervisor never started its child"
    pid = int(child_pid.read_text(encoding="ascii"))
    supervisor.send_signal(signal.SIGTERM)
    assert supervisor.wait(timeout=10) != 0
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
