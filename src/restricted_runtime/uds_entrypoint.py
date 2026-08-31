"""Fixed local UDS launcher; no TCP bind surface."""
import os
import socket
import stat
from pathlib import Path

import uvicorn

_ALLOWED_PATHS = {"/run/restricted-inference/gateway.sock", "/run/restricted-inference/conversation.sock"}
_SOCKET_MODE = 0o660


def _bind_socket(path: str) -> socket.socket:
    if path not in _ALLOWED_PATHS:
        raise RuntimeError("closed UDS path required")
    target = Path(path)
    try:
        before = target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RuntimeError("local UDS path cannot be inspected") from exc
    else:
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
            raise RuntimeError("local UDS stale path rejected")
        try:
            current = target.lstat()
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise RuntimeError("local UDS stale path changed")
            target.unlink()
        except RuntimeError:
            raise
        except OSError as exc:
            raise RuntimeError("local UDS stale socket cannot be removed") from exc
    try:
        sock: socket.socket | None = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        os.chmod(path, _SOCKET_MODE)
        os.fchmod(sock.fileno(), _SOCKET_MODE)
        sock.set_inheritable(True)
        return sock
    except OSError as exc:
        if sock is not None:
            sock.close()
        raise RuntimeError("local UDS socket cannot be bound") from exc


def _close_socket(sock: socket.socket, path: str, identity: tuple[int, int] | None = None) -> None:
    try:
        current = Path(path).lstat()
        if stat.S_ISSOCK(current.st_mode) and current.st_uid == os.geteuid() and (identity is None or (current.st_dev, current.st_ino) == identity):
            Path(path).unlink()
    except OSError:
        pass
    finally:
        sock.close()


def main() -> None:
    app=os.environ["RESTRICTED_UDS_APP"]; path=os.environ["RESTRICTED_UDS_PATH"]
    sock = _bind_socket(path)
    identity = (Path(path).lstat().st_dev, Path(path).lstat().st_ino)
    try:
        uvicorn.run(app, fd=sock.fileno())
    finally:
        _close_socket(sock, path, identity)
if __name__=="__main__": main()
