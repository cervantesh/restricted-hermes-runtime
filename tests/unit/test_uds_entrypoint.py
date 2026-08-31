"""The local launcher owns restrictive UDS creation before Uvicorn starts."""
import os
import socket
import stat
from pathlib import Path

import pytest
import uvicorn

from restricted_runtime import uds_entrypoint

pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires POSIX AF_UNIX permissions")


def test_launcher_prebinds_restrictive_socket_and_uvicorn_fd_path_preserves_mode(monkeypatch):
    path = Path("/run/restricted-inference/conversation.sock")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    observed: dict[str, int] = {}

    def fake_run(app, *, fd, **kwargs):
        assert kwargs == {"server_header": False, "date_header": False}
        observed["mode"] = stat.S_IMODE(path.stat().st_mode)
        # This is Uvicorn's real existing-fd code path. Its bind_socket()
        # branch must not chmod the already-bound socket.
        bound = uvicorn.Config(app, fd=fd, lifespan="off").bind_socket()
        try:
            assert stat.S_IMODE(path.stat().st_mode) == 0o660
        finally:
            bound.close()

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("RESTRICTED_UDS_APP", "tests.test_uds_entrypoint:app")
    monkeypatch.setenv("RESTRICTED_UDS_PATH", str(path))
    uds_entrypoint.main()

    assert observed["mode"] == 0o660
    assert not path.exists()
